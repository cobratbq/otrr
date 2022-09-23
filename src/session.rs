use std::{collections, rc::Rc};

use authentication::AKEContext;
use fragment::Assembler;

use crate::{
    authentication::{self, CryptographicMaterial},
    encoding::{
        encode_message, encode_otr_message, parse, EncodedMessage, MessageFlags, MessageType,
        OTREncoder, OTRMessageType, SSID,
    },
    fragment::{self, FragmentError},
    instancetag::{self, InstanceTag, INSTANCE_ZERO},
    protocol,
    smp::{self, SMPStatus},
    Host, OTRError, Policy, ProtocolStatus, UserMessage, Version,
};

pub struct Account {
    host: Rc<dyn Host>,
    details: Rc<AccountDetails>,
    /// instances contains all individual instances (clients) that have been
    /// encountered. Instance 0 is used for clients that have not yet announced
    /// their instance tag. Typically, before or during initial stages of OTR.
    instances: collections::HashMap<InstanceTag, Instance>,
}

// TODO not taking into account fragmentation yet. Any of the OTR-encoded messages can (and sometimes needs) to be fragmented.
// TODO how to manipulate policy bitflags?
impl Account {
    pub fn new(host: Rc<dyn Host>, policy: Policy) -> Self {
        Self {
            host,
            details: Rc::new(AccountDetails {
                policy,
                tag: instancetag::random_tag(),
            }),
            instances: collections::HashMap::new(),
        }
    }

    /// `sessions` returns a list of known instance tags (i.e. sessions). The session may be in any
    /// state of the protocol, i.e. `MSGSTATE_PLAINTEXT`, `MSGSTATE_ENCRYPTED`, `MSGSTATE_FINISHED`.
    /// However, the fact that a session (known by instance tag) exists, means that this instance
    /// tag was once revealed.
    pub fn sessions(&self) -> Vec<InstanceTag> {
        let mut sessions = Vec::<InstanceTag>::new();
        for k in self.instances.keys() {
            if *k == INSTANCE_ZERO {
                continue;
            }
            sessions.push(*k);
        }
        sessions
    }

    /// Query status (protocol status) for a particular instance. Returns status if the instance is
    /// known.
    pub fn status(&self, instance: InstanceTag) -> Option<ProtocolStatus> {
        self.instances.get(&instance).map(Instance::status)
    }

    /// `receive` processes a raw-bytes payload for possible OTR content. Receive should be called
    /// for any received messages such that the protocol may transparently handle any OTR protocol
    /// message, as well as warn the client about plaintext message received at unexpected times.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` on any deviating circumstances of the protocol, such as failed AKE
    /// negotiations, failed SMP negotiations, incorrectly formatted messages, protocol violations,
    /// etc. Most errors will contain an instance tag when an established OTR session is involved.
    ///
    /// # Panics
    ///
    /// Will panic on incorrect internal state or uses. It should not panic on any user input, as
    /// these are typically the chat network messages therefore out of the clients control.
    // TODO fuzzing target
    pub fn receive(&mut self, payload: &[u8]) -> Result<UserMessage, OTRError> {
        if !self.details.policy.contains(Policy::ALLOW_V3) {
            // OTR: if no version is allowed according to policy, do not do any handling at all.
            return Ok(UserMessage::Plaintext(Vec::from(payload)));
        }
        if fragment::match_fragment(payload) {
            let fragment = match fragment::parse(payload) {
                Some(fragment) => fragment,
                None => return Ok(UserMessage::None),
            };
            fragment::verify(&fragment).or(Err(OTRError::ProtocolViolation("Invalid fragment")))?;
            if fragment.receiver != self.details.tag {
                // NOTE: ignore instance tag ZERO as this is only relevant for OTRv2 and we do not
                // support this.
                return Err(OTRError::MessageForOtherInstance);
            }
            let details = Rc::clone(&self.details);
            let instance = self
                .instances
                .entry(fragment.sender)
                .or_insert_with(|| Instance::new(details, fragment.sender, Rc::clone(&self.host)));
            return match instance.assembler.assemble(&fragment) {
                // TODO theoretically, we could be recursing on a (nested) fragment, which is disallowed by the spec.
                Ok(assembled) => self.receive(assembled.as_slice()),
                // We've received a message fragment, but not enough to reassemble a message, so
                // return early with no actual result and tell the client to wait for more fragments
                // to arrive.
                Err(FragmentError::IncompleteResult | FragmentError::UnexpectedFragment) => {
                    Ok(UserMessage::None)
                }
                Err(FragmentError::InvalidData) => {
                    // TODO consider responding with OTR Error message to inform client, assuming we do have a valid sender instance tag.
                    Err(OTRError::ProtocolViolation("Fragment with invalid data."))
                }
            };
        }
        // TODO we should reset assembler here, but not sure how to do this, given that we many `n` instances with fragment assembler.
        // TODO consider returning empty vector or error code when message is only intended for OTR internally.
        match parse(payload)? {
            MessageType::Error(error) => {
                if self.details.policy.contains(Policy::ERROR_START_AKE) {
                    self.query(&[Version::V3])?;
                }
                Ok(UserMessage::Error(error))
            }
            MessageType::Plaintext(content) => {
                if self.has_sessions() || self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::Tagged(versions, content) => {
                if self.details.policy.contains(Policy::WHITESPACE_START_AKE) {
                    if let Some(selected) = self.select_version(&versions) {
                        self.initiate(&selected, None);
                    }
                }
                if self.has_sessions() || self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::Query(versions) => {
                if let Some(selected) = self.select_version(&versions) {
                    self.initiate(&selected, None);
                }
                Ok(UserMessage::None)
            }
            MessageType::Encoded(
                msg @ EncodedMessage {
                    version: _,
                    sender: _,
                    receiver: INSTANCE_ZERO,
                    message: OTRMessageType::DHKey(_),
                },
            ) => {
                // When a DH-Commit message was sent with receiver tag ZERO, then we may receive
                // any number of DH-Key messages in response. That is, a DH-Key message for each
                // client of the account that receives the DH-Commit message. (Potentially even
                // after the fact if client OTR plug-in incorrectly responds to history (replay)
                // of chat.
                self.verify_encoded_message_header(&msg)?;
                if msg.version == Version::V3 && !self.details.policy.contains(Policy::ALLOW_V3) {
                    return Ok(UserMessage::None);
                }
                // TODO allowing replies from multiple instances (different instances, repeats/replays) on single DH-Commit message: reuse of CTR value for same symmetric key r, opens up avenue to single (malicious) client responding multiple times (either with same instance tag, or with different instance tags). This means that they can respond, knowing the `r` value and therefore the DH public key. Opens up possibility for brute-forcing by spamming DH-Key messages from single malicious instance? Probably need to reinitiate with targeted message to DH-Key sender instance tag(?) to prevent multiple responses.
                // TODO DH-Key may be received multiple times. (reuse of `r`, dh-key)
                let result_context = self
                    .instances
                    .get(&INSTANCE_ZERO)
                    .unwrap()
                    .transfer_akecontext();
                // TODO do we transfer in all cases?
                let instance = self.instances.entry(msg.sender).or_insert_with(|| {
                    Instance::new(Rc::clone(&self.details), msg.sender, Rc::clone(&self.host))
                });
                if let Ok(context) = result_context {
                    // TODO how to respond if AKE is already initiated (i.e. in-progress)?
                    // TODO how to respond if instance already is confidential session (or finished)?
                    instance.adopt_akecontext(context);
                }
                instance.handle(msg)
            }
            MessageType::Encoded(msg) => {
                self.verify_encoded_message_header(&msg)?;
                if msg.version == Version::V3 && !self.details.policy.contains(Policy::ALLOW_V3) {
                    return Ok(UserMessage::None);
                }
                self.get_instance(msg.sender)?.handle(msg)
            }
        }
    }

    fn select_version(&self, versions: &[Version]) -> Option<Version> {
        if versions.contains(&Version::V3) && self.details.policy.contains(Policy::ALLOW_V3) {
            Some(Version::V3)
        } else {
            None
        }
    }

    fn filter_versions(&self, versions: &[Version]) -> Vec<Version> {
        if versions.contains(&Version::V3) && self.details.policy.contains(Policy::ALLOW_V3) {
            vec![Version::V3]
        } else {
            Vec::new()
        }
    }

    fn verify_encoded_message_header(&self, msg: &EncodedMessage) -> Result<(), OTRError> {
        match msg.version {
            Version::None => {
                return Err(OTRError::ProtocolViolation(
                    "Encoded message must always have a protocol version.",
                ))
            }
            Version::Unsupported(version) => return Err(OTRError::UnsupportedVersion(version)),
            Version::V3 => { /* This is acceptable. */ }
        }
        instancetag::verify_instance_tag(msg.sender).or(Err(OTRError::ProtocolViolation(
            "Sender instance tag is illegal value",
        )))?;
        if msg.sender == INSTANCE_ZERO {
            return Err(OTRError::ProtocolViolation("Sender instance tag is zero"));
        }
        instancetag::verify_instance_tag(msg.receiver).or(Err(OTRError::ProtocolViolation(
            "Receiver instance tag is illegal value",
        )))?;
        if let OTRMessageType::DHCommit(_) = msg.message {
            // allow receiver tag zero for DH-Commit message
        } else if msg.receiver == INSTANCE_ZERO {
            return Err(OTRError::ProtocolViolation(
                "Receiver instance tag is zero.",
            ));
        }
        if msg.receiver > INSTANCE_ZERO && msg.receiver != self.details.tag {
            return Err(OTRError::MessageForOtherInstance);
        }
        Ok(())
    }

    /// `send` processes plaintext message content (user input) through the current state of OTR to
    /// ready them for sending. This involves possibly encrypting the plaintext message, possibly
    /// triggering other protocol interactions, and so forth. Additionally, depending on set
    /// policies, `send` may issue warnings or refuse to operate to ensure that the client operates
    /// according to set policies.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` on any kind of special-case situations involving the OTR protocol,
    /// such as protocol violations, inproper state, incorrect internal state (data), etc.
    ///
    /// # Panics
    ///
    /// Will panic on inappropriate user-input. Panics are most likely traced back to incorrect use.
    pub fn send(
        &mut self,
        instance: Option<InstanceTag>,
        content: &[u8],
    ) -> Result<Vec<u8>, OTRError> {
        if !self.details.policy.contains(Policy::ALLOW_V3) {
            // OTR: if no version is allowed according to policy, do not do any handling at all.
            return Ok(Vec::from(content));
        }
        let receiver = instance.unwrap_or(INSTANCE_ZERO);
        let instance = self
            .instances
            .get_mut(&receiver)
            .ok_or(OTRError::UnknownInstance(receiver))?;
        // "If msgstate is MSGSTATE_PLAINTEXT:"
        if instance.status() == ProtocolStatus::Plaintext {
            if self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                // "   If REQUIRE_ENCRYPTION is set:"
                // "     Store the plaintext message for possible retransmission, and send a Query
                //       Message."
                self.query(&[Version::V3])?;
                // TODO OTR: store message for possible retransmission after OTR session is established.
                return Err(OTRError::PolicyRestriction(
                    "Encryption is required by policy, but no confidential session is established yet. Query-message is sent to initiate OTR session.",
                ));
            } else if self.details.policy.contains(Policy::SEND_WHITESPACE_TAG) {
                // FIXME send whitespace tag as first try if policy allows, after receiving a plaintext message, take as sign that OTR is not supported/recipient is not interested in engaging in OTR session.
                // TODO add logic for sending whitespace-tagged message to probe for OTR capabilities. (Send until receiving a follow-up plaintext message, then assume Alice is either not capable or not interested.)
            }
        }
        // "If msgstate is MSGSTATE_ENCRYPTED:
        //    Encrypt the message, and send it as a Data Message. Store the plaintext message for
        //    possible retransmission.
        //  If msgstate is MSGSTATE_FINISHED:
        //    Inform the user that the message cannot be sent at this time. Store the plaintext
        //    message for possible retransmission."
        instance.send(content)
    }

    /// `initiate` initiates the OTR protocol for designated receiver.
    pub fn initiate(&mut self, version: &Version, receiver: Option<InstanceTag>) -> UserMessage {
        let receiver = receiver.unwrap_or(INSTANCE_ZERO);
        self.instances
            .entry(receiver)
            .or_insert_with(|| {
                Instance::new(Rc::clone(&self.details), receiver, Rc::clone(&self.host))
            })
            .initiate(version)
    }

    /// `end` ends the specified OTR session and resets the state back to plaintext. This means that
    /// confidential communication has ended and any subsequent message will be sent as plain text,
    /// i.e. unencrypted. This function should only be called as a result of _direct user
    /// interaction_.
    ///
    /// # Errors
    ///
    /// Will return an error in case the specified instance does not exist.
    #[inline(always)]
    pub fn end(&mut self, instance: InstanceTag) -> Result<UserMessage, OTRError> {
        self.reset(instance)
    }

    /// `query` sends a OTR query-message over the host's communication network in order to probe
    /// for other parties that are willing to initiate an OTR session.
    ///
    /// # Errors
    ///
    /// Will return an error in case of no compatible errors.
    pub fn query(&mut self, versions: &[Version]) -> Result<(), OTRError> {
        let accepted_versions = self.filter_versions(versions);
        if accepted_versions.is_empty() {
            return Err(OTRError::UserError("No supported versions available."));
        }
        // TODO Embed query tag into plaintext message or construct plaintext message with clarifying information.
        let msg = MessageType::Query(accepted_versions);
        self.host.inject(&encode_message(&msg));
        Ok(())
    }

    /// `reset` resets the OTR session, as specified by the instance, to plaintext state. This means
    /// that any message sent afterwards will be in plaintext unless other actions are taken to
    /// (re)initialize an OTR session (initiate AKE).
    ///
    /// # Errors
    ///
    /// Will return `OTRError` in case the instance does not exist.
    pub fn reset(&mut self, instance: InstanceTag) -> Result<UserMessage, OTRError> {
        Ok(self.get_instance(instance)?.reset())
    }

    /// `start_smp` initiates the Socialist Millionaires' Protocol for the specified instance. The
    /// initiator immediately supplies a question (`question`, which is optional so may be
    /// zero-length) and a `secret` which is the secret value that tested for in the SMP execution.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` in case the instance does not exist, or the protocol is in an
    /// incorrect state. An established encrypted OTR session is necessary to start SMP.
    pub fn start_smp(
        &mut self,
        instance: InstanceTag,
        secret: &[u8],
        question: &[u8],
    ) -> Result<(), OTRError> {
        let message = self.get_instance(instance)?.start_smp(secret, question)?;
        self.host.inject(&message);
        Ok(())
    }

    /// `abort_smp` aborts an (in-progress) SMP session.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` in case the specified instance is not a confidential session, i.e.
    /// encrypted OTR session, and on any violations of the OTR protocol.
    pub fn abort_smp(&mut self, instance: InstanceTag) -> Result<(), OTRError> {
        let message = self.get_instance(instance)?.abort_smp()?;
        self.host.inject(&message);
        Ok(())
    }

    /// `smp_ssid` returns the SSID used for verification in case of an established (encrypted) OTR
    /// session.
    /// 
    /// # Errors
    /// 
    /// Will give an `OTRError::UnknownInstance` error in case of non-existing instance.
    pub fn smp_ssid(&self, instance: InstanceTag) -> Result<SSID, OTRError> {
        self.instances.get(&instance).ok_or(OTRError::UnknownInstance(instance))?.smp_ssid()
    }

    // TODO this function has nasty detail that borrow checker sees these calls as a persistent mutable borrow. This unnecessarily limits flexibility. Can we do something with lifetimes to avoid this?
    fn get_instance(&mut self, instance: InstanceTag) -> Result<&mut Instance, OTRError> {
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance(instance))
    }

    /// `has_encrypted_sessions` checks if any instances are established or finished OTR
    /// sessions.
    fn has_sessions(&self) -> bool {
        self.instances.iter().any(|i| {
            i.1.status() == ProtocolStatus::Encrypted || i.1.status() == ProtocolStatus::Finished
        })
    }
}

/// Instance serves a single communication session, ensuring that messages always travel between the same two clients.
struct Instance {
    // TODO can we share the details in an immutable way?
    details: Rc<AccountDetails>,
    receiver: InstanceTag,
    host: Rc<dyn Host>,
    assembler: Assembler,
    state: Box<dyn protocol::ProtocolState>,
    ake: AKEContext,
}

/// `Instance` represents a single instance, a communication session with a single client of an
/// account. The protocol assumes that multiple clients can be active at the same time for a single
/// chat account.
/// `Instance` expects to receive (as much as possible) preselected values to be used: selection,
/// validation to be performed in `Session` if possible.
impl Instance {
    fn new(details: Rc<AccountDetails>, receiver: InstanceTag, host: Rc<dyn Host>) -> Self {
        Self {
            details,
            receiver,
            assembler: Assembler::new(),
            state: protocol::new_state(),
            ake: AKEContext::new(Rc::clone(&host)),
            host,
        }
    }

    fn status(&self) -> ProtocolStatus {
        self.state.status()
    }

    fn initiate(&mut self, version: &Version) -> UserMessage {
        assert_eq!(*version, Version::V3);
        let msg = self.ake.initiate();
        self.host.inject(&encode_otr_message(
            self.ake.version(),
            self.details.tag,
            self.receiver,
            msg,
        ));
        UserMessage::None
    }

    fn transfer_akecontext(&self) -> Result<AKEContext, OTRError> {
        self.ake.transfer().map_err(OTRError::AuthenticationError)
    }

    fn adopt_akecontext(&mut self, context: AKEContext) {
        self.ake = context;
    }

    fn handle(&mut self, encoded_message: EncodedMessage) -> Result<UserMessage, OTRError> {
        assert_eq!(encoded_message.version, Version::V3);
        // TODO need to inspect error handling to appropriately respond with OTR message to indicate that an error has occurred. This has not yet been considered.
        assert_eq!(self.receiver, encoded_message.sender);
        assert_eq!(self.details.tag, encoded_message.receiver);
        // FIXME how to handle AKE errors in each case?
        match encoded_message.message {
            OTRMessageType::DHCommit(msg) => {
                let response = self
                    .ake
                    .handle_dhcommit(msg).map_err(OTRError::AuthenticationError)?;
                self.host.inject(&encode_otr_message(
                    Version::V3,
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::None)
            }
            OTRMessageType::DHKey(msg) => {
                let response = self
                    .ake
                    .handle_dhkey(msg).map_err(OTRError::AuthenticationError)?;
                self.host.inject(&encode_otr_message(
                    Version::V3,
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::None)
            }
            OTRMessageType::RevealSignature(msg) => {
                let (CryptographicMaterial{version, ssid, our_dh, their_dh, their_dsa}, response) = self
                    .ake
                    .handle_reveal_signature(msg).map_err(OTRError::AuthenticationError)?;
                self.state = self.state.secure(Rc::clone(&self.host), version, self.details.tag,
                    encoded_message.sender, ssid, our_dh, their_dh, their_dsa);
                self.host.inject(&encode_otr_message(
                    Version::V3,
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            OTRMessageType::Signature(msg) => {
                let CryptographicMaterial{version, ssid, our_dh, their_dh, their_dsa} = self
                    .ake
                    .handle_signature(msg).map_err(OTRError::AuthenticationError)?;
                self.state = self.state.secure(Rc::clone(&self.host), version, self.details.tag,
                    encoded_message.sender, ssid, our_dh, their_dh, their_dsa);
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
                // TODO If there is a recent stored message, encrypt it and send it as a Data Message.
            }
            OTRMessageType::Data(msg) => {
                // TODO verify and validate message before passing on to state.
                // NOTE that TLV 0 (Padding) and 1 (Disconnect) are handled as part of the protocol.
                // Other TLVs that are their own protocol or function, must be handled subsequently.
                let (message, transition) = self.state.handle(&msg);
                if transition.is_some() {
                    self.state = transition.unwrap();
                }
                match message {
                    Ok(UserMessage::Confidential(_, _, tlvs)) if smp::any_smp_tlv(&tlvs) => {
                        // REMARK we completely ignore the content for messages with SMP TLVs.
                        // REMARK we could inspect and log if messages with SMP TLVs do not have the IGNORE_UNREADABLE flag set.
                        let tlv = tlvs.iter().find(|t| smp::is_smp_tlv(t)).unwrap();
                        // Socialist Millionaire Protocol (SMP) handling.
                        if let Some(reply_tlv) = self.state.smp_mut().unwrap().handle(tlv) {
                            let otr_message = self.state.prepare(
                                MessageFlags::IGNORE_UNREADABLE,
                                &OTREncoder::new()
                                    .write_byte(0)
                                    .write_tlv(reply_tlv)
                                    .to_vec())?;
                            self.host.inject(&encode_otr_message(self.state.version(),
                                self.details.tag, self.receiver, otr_message));
                        }
                        match self.state.smp().unwrap().status() {
                            SMPStatus::InProgress => Ok(UserMessage::None),
                            SMPStatus::Success => Ok(UserMessage::SMPSucceeded(self.receiver)),
                            SMPStatus::Aborted(_) => Ok(UserMessage::SMPFailed(self.receiver)),
                            SMPStatus::Initial => panic!("BUG: we should be able to reach after having processed an SMP message TLV."),
                        }
                    }
                    // TODO following three patterns are there only to replace 0 instance tag value with actual receiver value.
                    Ok(UserMessage::ConfidentialSessionStarted(INSTANCE_ZERO)) => Ok(UserMessage::ConfidentialSessionStarted(self.receiver)),
                    Ok(UserMessage::Confidential(INSTANCE_ZERO, content, tlvs)) => Ok(UserMessage::Confidential(self.receiver, content, tlvs)),
                    Ok(UserMessage::ConfidentialSessionFinished(INSTANCE_ZERO)) => Ok(UserMessage::ConfidentialSessionFinished(self.receiver)),
                    msg @ Ok(_) => msg,
                    Err(OTRError::UnreadableMessage(_)) if msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) => {
                        // For an unreadable message, even if the IGNORE_UNREADABLE flag is set, we
                        // need to send an OTR Error response, to indicate to the other user that
                        // we no longer have a correctly established OTR session.
                        self.host.inject(&encode_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Ok(UserMessage::None)
                    }
                    Err(OTRError::UnreadableMessage(_)) => {
                        self.host.inject(&encode_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Err(OTRError::UnreadableMessage(self.receiver))
                    }
                    err @ Err(_) => {
                        // TODO do all these errors require Error Message response to other party?
                        err
                    }
                }
            }
            OTRMessageType::Undefined(_) => panic!("BUG: this message-type is used as a placeholder. It can never be an incoming message-type to be handled."),
        }
    }

    fn reset(&mut self) -> UserMessage {
        let previous = self.state.status();
        let version = self.state.version();
        // TODO what happens with verification status when we force-reset? Should be preserved? (prefer always reset for safety)
        let (abortmsg, newstate) = self.state.finish();
        self.state = newstate;
        if previous == self.state.status() {
            assert!(abortmsg.is_none());
            return UserMessage::None;
        }
        if let Some(msg) = abortmsg {
            self.host.inject(&encode_otr_message(
                version,
                self.details.tag,
                self.receiver,
                msg,
            ));
        }
        UserMessage::Reset(self.receiver)
    }

    // TODO double-check if I use this function correctly, don't encode_otr_message twice!
    fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OTRError> {
        let plaintext = utils::std::bytes::drop_by_value(plaintext, 0);
        // TODO OTR: store plaintext message for possible retransmission (various states, see spec)
        match self.state.prepare(MessageFlags::empty(), &plaintext)? {
            OTRMessageType::Undefined(message) => {
                assert!(
                    self.state.status() != ProtocolStatus::Plaintext,
                    "BUG: received undefined message type in state {:?}",
                    self.state.status()
                );
                Ok(encode_message(&MessageType::Plaintext(message)))
            }
            message @ (OTRMessageType::DHCommit(_)
            | OTRMessageType::DHKey(_)
            | OTRMessageType::RevealSignature(_)
            | OTRMessageType::Signature(_)
            | OTRMessageType::Data(_)) => Ok(encode_otr_message(
                self.state.version(),
                self.details.tag,
                self.receiver,
                message,
            )),
        }
    }

    // TODO delegate to here from Account instance.
    fn start_smp(&mut self, secret: &[u8], question: &[u8]) -> Result<Vec<u8>, OTRError> {
        // logic currently assumes that if the call to smp succeeds, that we are in an appropriate
        // state to send a message with appended TLV.
        // TODO consider what to do if SMP in progress: immediately reset and initiate, or do nothing, or ...?
        let tlv = self.state.smp_mut()?.initiate(secret, question)?;
        let message = self.state.prepare(
            MessageFlags::IGNORE_UNREADABLE,
            &OTREncoder::new().write_byte(0).write_tlv(tlv).to_vec(),
        )?;
        Ok(encode_otr_message(
            self.state.version(),
            self.details.tag,
            self.receiver,
            message,
        ))
    }

    fn smp_ssid(&self) -> Result<SSID, OTRError> {
        Ok(self.state.smp()?.ssid())
    }

    // TODO delegate to here from Account instance.
    fn abort_smp(&mut self) -> Result<Vec<u8>, OTRError> {
        let smp = self.state.smp_mut();
        if smp.is_err() {
            return Err(OTRError::IncorrectState(
                "SMP is unavailable in the current state",
            ));
        }
        let tlv = smp.unwrap().abort();
        let message = encode_otr_message(
            self.state.version(),
            self.details.tag,
            self.receiver,
            self.state
                .prepare(
                    MessageFlags::IGNORE_UNREADABLE,
                    &OTREncoder::new().write_byte(0).write_tlv(tlv).to_vec(),
                )
                .unwrap(),
        );
        Ok(message)
    }
}

/// `AccountDetails` contains our own, static account details.
// TODO either extend AccountDetails as needed, or remove unnecessary wrapper for only single value?
struct AccountDetails {
    policy: Policy,
    tag: InstanceTag,
}

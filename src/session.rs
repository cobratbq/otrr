use std::{collections, rc::Rc};

use authentication::AKEContext;
use fragment::Assembler;

use crate::{
    authentication::{self, CryptographicMaterial},
    encoding::{
        self, encode_message, serialize_message, EncodedMessage, EncodedMessageType, MessageFlags,
        MessageType, OTREncoder, SSID,
    },
    fragment::{self, fragment, FragmentError},
    instancetag::{self, InstanceTag, INSTANCE_ZERO},
    protocol::{self, Message},
    smp::{self, SMPStatus},
    Host, OTRError, Policy, ProtocolStatus, UserMessage, Version, SUPPORTED_VERSIONS,
};

pub struct Account {
    host: Rc<dyn Host>,
    details: Rc<AccountDetails>,
    /// instances contains all individual instances (clients) that have been
    /// encountered. Instance 0 is used for clients that have not yet announced
    /// their instance tag. Typically, before or during initial stages of OTR.
    instances: collections::HashMap<InstanceTag, Instance>,
    /// `whitespace_tagged` indicates whether or not a whitespace-tagged plaintext message was sent
    /// already. This field is shared with the method call that constructs the actual
    /// whitespace-tagged message whenever the opportunity is there. This field is shared such that
    /// sending a whitespace-tagged message (which is not specific to an instance) is common
    /// knowledge among all instances.
    // TODO `whitespace_tagged` is never reset to false. (After reentering MSGSTATE_PLAINTEXT)
    whitespace_tagged: bool,
}

impl Account {
    pub fn new(host: Rc<dyn Host>, policy: Policy) -> Self {
        Self {
            host,
            details: Rc::new(AccountDetails {
                policy,
                tag: instancetag::random_tag(),
            }),
            instances: collections::HashMap::new(),
            whitespace_tagged: false,
        }
    }

    #[must_use]
    pub fn get_instance_tag(&self) -> InstanceTag {
        self.details.tag
    }

    #[must_use]
    pub fn get_policy(&self) -> Policy {
        self.details.policy
    }

    /// `sessions` returns a list of known instance tags (i.e. sessions). The session may be in any
    /// state of the protocol, i.e. `MSGSTATE_PLAINTEXT`, `MSGSTATE_ENCRYPTED`, `MSGSTATE_FINISHED`.
    /// However, the fact that a session (known by instance tag) exists, means that this instance
    /// tag was once revealed.
    #[must_use]
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
    // REMARK fuzzing target
    // TODO check impact of receiving error: cannot disconnect all established sessions (multiple instances)
    // TODO check impact of receiving query: should not re-establish all active sessions (multiple instances)
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
                Ok(assembled) => {
                    if fragment::match_fragment(&assembled) {
                        return Err(OTRError::ProtocolViolation("Assembled fragments lead to a fragment. This is disallowed by the specification."));
                    }
                    self.receive(assembled.as_slice())
                }
                Err(FragmentError::IncompleteResult | FragmentError::UnexpectedFragment) => {
                    // We've received a message fragment, but not enough to reassemble a message, so
                    // return early with no actual result and tell the client to wait for more
                    // fragments to arrive. (Or we have received an unexpected fragment, therefore
                    // reset everything and forget what we had up to now.)
                    Ok(UserMessage::None)
                }
                Err(FragmentError::InvalidData) => {
                    // Given that this is (merely) a fragment, just discard it and do not send an
                    // error message, as the error message would wreak havoc on the (still
                    // functional) encrypted session.
                    Err(OTRError::ProtocolViolation(
                        "Fragment contains invalid data.",
                    ))
                }
            };
        }
        // TODO can we handle possible errors produced here to reset whitespace_tagged, respond with OTR Error, etc?
        match encoding::parse(payload)? {
            MessageType::Error(error) => {
                if self.details.policy.contains(Policy::ERROR_START_AKE) {
                    self.query()?;
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
                    if let Some(selected) = select_version(&self.details.policy, &versions) {
                        self.initiate(&selected, INSTANCE_ZERO);
                    }
                }
                if self.has_sessions() || self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::Query(versions) => {
                if let Some(selected) = select_version(&self.details.policy, &versions) {
                    self.initiate(&selected, INSTANCE_ZERO);
                }
                Ok(UserMessage::None)
            }
            MessageType::Encoded(
                msg @ EncodedMessage {
                    version: _,
                    sender: _,
                    receiver: _,
                    message: EncodedMessageType::DHKey(_),
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
                // TODO DH-Key (responses) may be received multiple times (multiple instances, multiple repeats). Do we need to take these cases into account when handling? (temporary dh keypair and `r` value are same/reused for all cases, same CTR value used for all cases)
                let result_context = self
                    .instances
                    .get(&INSTANCE_ZERO)
                    .unwrap()
                    .transfer_akecontext();
                let instance = self.instances.entry(msg.sender).or_insert_with(|| {
                    Instance::new(Rc::clone(&self.details), msg.sender, Rc::clone(&self.host))
                });
                if let Ok(context) = result_context {
                    // Transfer is only supported in `AKEState::AwaitingDHKey`. Therefore, result
                    // indicates whether transfer is possible.
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
        if let EncodedMessageType::DHCommit(_) = msg.message {
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
    /// NOTE: for correctness of the OTR protocol, `0` (`NULL`) values in the user message will be
    /// dropped. If the policy does not allow OTR to operate (all protocol versions disabled) then
    /// user content will not be touched at all.
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
        instance: InstanceTag,
        content: &[u8],
    ) -> Result<Vec<Vec<u8>>, OTRError> {
        if !self.details.policy.contains(Policy::ALLOW_V3) {
            // OTR: if no version is allowed according to policy, do not do any handling at all.
            return Ok(vec![Vec::from(content)]);
        }
        let instance = self
            .instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance(instance))?;
        // "If msgstate is MSGSTATE_PLAINTEXT:"
        if self.details.policy.contains(Policy::REQUIRE_ENCRYPTION)
            && instance.status() == ProtocolStatus::Plaintext
        {
            // "   If REQUIRE_ENCRYPTION is set:
            //       Store the plaintext message for possible retransmission, and send a Query
            //       Message."
            self.query()?;
            return Err(OTRError::PolicyRestriction(
                "Encryption is required by policy, but no confidential session is established yet. Query-message is sent to initiate OTR session.",
            ));
        }
        // "If msgstate is MSGSTATE_ENCRYPTED:
        //    Encrypt the message, and send it as a Data Message. Store the plaintext message for
        //    possible retransmission.
        //  If msgstate is MSGSTATE_FINISHED:
        //    Inform the user that the message cannot be sent at this time. Store the plaintext
        //    message for possible retransmission."
        instance.send(&mut self.whitespace_tagged, content)
    }

    /// `initiate` initiates the OTR protocol for designated receiver.
    pub fn initiate(&mut self, version: &Version, receiver: InstanceTag) -> UserMessage {
        self.instances
            .entry(receiver)
            .or_insert_with(|| {
                Instance::new(Rc::clone(&self.details), receiver, Rc::clone(&self.host))
            })
            .initiate(version)
    }

    /// `end` ends the specified OTR session and resets the state back to plaintext. This means that
    /// confidential communication ends and any subsequent message will be sent as plain text, i.e.
    /// unencrypted. This function should only be called as a result of _direct user interaction_.
    ///
    /// In the case the other party ended/aborted the session, the session would transition to
    /// `MSGSTATE_FINISHED`. In that case, too, `end` resets the session back to
    /// `MSGSTATE_PLAINTEXT`
    ///
    /// # Errors
    ///
    /// Will return an error in case the specified instance does not exist.
    pub fn end(&mut self, instance: InstanceTag) -> Result<UserMessage, OTRError> {
        Ok(self.get_instance(instance)?.reset())
    }

    /// `query` sends a OTR query-message over the host's communication network in order to probe
    /// for other parties that are willing to initiate an OTR session.
    ///
    /// # Errors
    ///
    /// Will return an error in case of no compatible errors.
    pub fn query(&mut self) -> Result<(), OTRError> {
        let accepted_versions = filter_versions(&self.details.policy, &SUPPORTED_VERSIONS);
        if accepted_versions.is_empty() {
            return Err(OTRError::UserError("No supported versions available."));
        }
        self.host
            .inject(&serialize_message(&MessageType::Query(accepted_versions)));
        Ok(())
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
        self.instances
            .get(&instance)
            .ok_or(OTRError::UnknownInstance(instance))?
            .smp_ssid()
    }

    fn get_instance(&mut self, instance: InstanceTag) -> Result<&mut Instance, OTRError> {
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance(instance))
    }

    /// `has_encrypted_sessions` checks if any instances are established or finished OTR sessions.
    fn has_sessions(&self) -> bool {
        self.instances.iter().any(|i| {
            assert_eq!(*i.0, i.1.receiver);
            assert!(
                *i.0 != INSTANCE_ZERO || i.1.status() == ProtocolStatus::Plaintext,
                "BUG: Given that we do not support OTR version 1 and 2, we expect instance 0 is Plaintext"
            );
            i.1.status() == ProtocolStatus::Encrypted || i.1.status() == ProtocolStatus::Finished
        })
    }
}

/// Instance serves a single communication session, ensuring that messages always travel between the same two clients.
struct Instance {
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
        self.host.inject(&encode_message(
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
        assert_eq!(self.receiver, encoded_message.sender);
        assert_eq!(self.details.tag, encoded_message.receiver);
        // Given that we are processing an actual (OTR-)encoded message intended for this instance,
        // we should reset the assembler now.
        self.assembler.reset();
        match encoded_message.message {
            EncodedMessageType::DHCommit(msg) => {
                let response = self
                    .ake
                    .handle_dhcommit(msg).map_err(OTRError::AuthenticationError)?;
                self.host.inject(&encode_message(
                    self.ake.version(),
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::None)
            }
            EncodedMessageType::DHKey(msg) => {
                let response = self
                    .ake
                    .handle_dhkey(msg).map_err(OTRError::AuthenticationError)?;
                self.host.inject(&encode_message(
                    self.ake.version(),
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::None)
            }
            EncodedMessageType::RevealSignature(msg) => {
                let (CryptographicMaterial{version, ssid, our_dh, their_dh, their_dsa}, response) = self
                    .ake
                    .handle_reveal_signature(msg).map_err(OTRError::AuthenticationError)?;
                self.state = self.state.secure(Rc::clone(&self.host), version, self.details.tag,
                    encoded_message.sender, ssid, our_dh, their_dh, their_dsa);
                self.host.inject(&encode_message(
                    self.ake.version(),
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            EncodedMessageType::Signature(msg) => {
                let CryptographicMaterial{version, ssid, our_dh, their_dh, their_dsa} = self
                    .ake
                    .handle_signature(msg).map_err(OTRError::AuthenticationError)?;
                self.state = self.state.secure(Rc::clone(&self.host), version, self.details.tag,
                    encoded_message.sender, ssid, our_dh, their_dh, their_dsa);
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            EncodedMessageType::Data(msg) => {
                // TODO verify and validate message (necessary?) before passing on to state.
                // NOTE that TLV 0 (Padding) and 1 (Disconnect) are already handled as part of the
                // protocol. Other TLVs that are their own protocol or function, therefore must be
                // handled separately.
                let (message, transition) = self.state.handle(&msg);
                if transition.is_some() {
                    self.state = transition.unwrap();
                }
                match message {
                    Ok(Message::Confidential(_, tlvs)) if smp::any_smp_tlv(&tlvs) => {
                        // REMARK we completely ignore the content for messages with SMP TLVs.
                        // REMARK we could inspect and log if messages with SMP TLVs do not have the IGNORE_UNREADABLE flag set.
                        let tlv = tlvs.into_iter().find(smp::is_smp_tlv).unwrap();
                        // Socialist Millionaire Protocol (SMP) handling.
                        if let Some(reply_tlv) = self.state.smp_mut().unwrap().handle(&tlv) {
                            let otr_message = self.state.prepare(
                                MessageFlags::IGNORE_UNREADABLE,
                                &OTREncoder::new()
                                    .write_byte(0)
                                    .write_tlv(reply_tlv)
                                    .to_vec())?;
                            self.host.inject(&encode_message(self.state.version(),
                                self.details.tag, self.receiver, otr_message));
                        }
                        match self.state.smp().unwrap().status() {
                            SMPStatus::InProgress => Ok(UserMessage::None),
                            SMPStatus::Success => Ok(UserMessage::SMPSucceeded(self.receiver)),
                            SMPStatus::Aborted(_) => Ok(UserMessage::SMPFailed(self.receiver)),
                            SMPStatus::Initial => panic!("BUG: we should be able to reach after having processed an SMP message TLV."),
                        }
                    }
                    Ok(Message::Confidential(content, tlvs)) => Ok(UserMessage::Confidential(self.receiver, content, tlvs)),
                    Ok(Message::ConfidentialFinished) => Ok(UserMessage::ConfidentialSessionFinished(self.receiver)),
                    Err(OTRError::UnreadableMessage(_)) if msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) => {
                        // For an unreadable message, even if the IGNORE_UNREADABLE flag is set, we
                        // need to send an OTR Error response, to indicate to the other user that
                        // we no longer have a correctly established OTR session.
                        self.host.inject(&serialize_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Ok(UserMessage::None)
                    }
                    Err(OTRError::UnreadableMessage(_)) => {
                        self.host.inject(&serialize_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Err(OTRError::UnreadableMessage(self.receiver))
                    }
                    Err(error) => {
                        // TODO do all these errors require Error Message response to other party?
                        Err(error)
                    }
                }
            }
            EncodedMessageType::Unencoded(_) => panic!("BUG: this message-type is used as a placeholder. It can never be an incoming message-type to be handled."),
        }
    }

    fn reset(&mut self) -> UserMessage {
        let previous = self.state.status();
        let version = self.state.version();
        let (abortmsg, newstate) = self.state.finish();
        self.state = newstate;
        if previous == self.state.status() {
            assert!(abortmsg.is_none());
            return UserMessage::None;
        }
        if let Some(msg) = abortmsg {
            self.host.inject(&encode_message(
                version,
                self.details.tag,
                self.receiver,
                msg,
            ));
        }
        UserMessage::Reset(self.receiver)
    }

    fn send(
        &mut self,
        whitespace_tagged: &mut bool,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>, OTRError> {
        let plaintext = utils::std::bytes::drop_by_value(plaintext, 0);
        match self.state.prepare(MessageFlags::empty(), &plaintext)? {
            EncodedMessageType::Unencoded(msg) => {
                assert!(
                    self.state.status() != ProtocolStatus::Plaintext,
                    "BUG: received undefined message type in state {:?}",
                    self.state.status()
                );
                let versions = filter_versions(&self.details.policy, &SUPPORTED_VERSIONS);
                let message = if self.details.policy.contains(Policy::SEND_WHITESPACE_TAG)
                    && !*whitespace_tagged
                    && !versions.is_empty()
                {
                    *whitespace_tagged = true;
                    MessageType::Tagged(versions, msg)
                } else {
                    MessageType::Plaintext(msg)
                };
                Ok(vec![serialize_message(&message)])
            }
            message @ (EncodedMessageType::DHCommit(_)
            | EncodedMessageType::DHKey(_)
            | EncodedMessageType::RevealSignature(_)
            | EncodedMessageType::Signature(_)) => {
                let content =
                    encode_message(self.ake.version(), self.details.tag, self.receiver, message);
                Ok(self.prepare_payloads(content))
            }
            message @ EncodedMessageType::Data(_) => {
                let content = encode_message(
                    self.state.version(),
                    self.details.tag,
                    self.receiver,
                    message,
                );
                Ok(self.prepare_payloads(content))
            }
        }
    }

    fn prepare_payloads(&self, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let max_size = self.host.message_size();
        if payload.len() <= max_size {
            // send message-bytes as-is: fragmentation is not needed.
            vec![payload]
        } else {
            // fragmentation is needed: send multiple fragments instead.
            fragment(max_size, self.details.tag, self.receiver, &payload)
                .iter()
                .map(|f| OTREncoder::new().write_encodable(f).to_vec())
                .collect()
        }
    }

    fn start_smp(&mut self, secret: &[u8], question: &[u8]) -> Result<Vec<u8>, OTRError> {
        // logic currently assumes that if the call to smp succeeds, that we are in an appropriate
        // state to send a message with appended TLV.
        let tlv = self.state.smp_mut()?.initiate(secret, question)?;
        let message = self.state.prepare(
            MessageFlags::IGNORE_UNREADABLE,
            &OTREncoder::new().write_byte(0).write_tlv(tlv).to_vec(),
        )?;
        Ok(encode_message(
            self.state.version(),
            self.details.tag,
            self.receiver,
            message,
        ))
    }

    fn smp_ssid(&self) -> Result<SSID, OTRError> {
        Ok(self.state.smp()?.ssid())
    }

    fn abort_smp(&mut self) -> Result<Vec<u8>, OTRError> {
        let smp = self.state.smp_mut();
        if smp.is_err() {
            return Err(OTRError::IncorrectState(
                "SMP is unavailable in the current state",
            ));
        }
        let tlv = smp.unwrap().abort();
        let message = encode_message(
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

/// `AccountDetails` contains our own, static details for an account shared among instances.
struct AccountDetails {
    policy: Policy,
    tag: InstanceTag,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn select_version(policy: &Policy, versions: &[Version]) -> Option<Version> {
    if versions.contains(&Version::V3) && policy.contains(Policy::ALLOW_V3) {
        Some(Version::V3)
    } else {
        None
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn filter_versions(policy: &Policy, versions: &[Version]) -> Vec<Version> {
    if versions.contains(&Version::V3) && policy.contains(Policy::ALLOW_V3) {
        vec![Version::V3]
    } else {
        Vec::new()
    }
}

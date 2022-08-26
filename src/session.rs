use std::{collections, rc::Rc};

use authentication::AKEContext;
use fragment::Assembler;

use crate::{
    authentication::{self, CryptographicMaterial},
    encoding::{
        encode, encode_otr_message, parse, EncodedMessage, MessageFlags, MessageType, OTREncoder,
        OTRMessageType, CTR_LEN,
    },
    fragment::{self, FragmentError},
    instancetag::{self, InstanceTag, INSTANCE_ZERO},
    protocol, smp, Host, OTRError, Policy, ProtocolStatus, UserMessage, Version,
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

    /// Query status (protocol status) for a particular instance. Returns status if the instance is known.
    pub fn status(&self, instance: InstanceTag) -> Option<ProtocolStatus> {
        self.instances
            .get(&instance)
            .map(|instance| instance.status())
    }

    // TODO fuzzing target
    pub fn receive(&mut self, payload: &[u8]) -> Result<UserMessage, OTRError> {
        if fragment::match_fragment(payload) {
            // FIXME handle OTRv2 fragments not being supported(?)
            let fragment = fragment::parse(payload).or(Err(OTRError::ProtocolViolation(
                "Illegal or unsupported fragment.",
            )))?;
            fragment::verify(&fragment).or(Err(OTRError::ProtocolViolation("Invalid fragment")))?;
            if fragment.receiver != self.details.tag && fragment.receiver != INSTANCE_ZERO {
                return Err(OTRError::MessageForOtherInstance);
            }
            let details = Rc::clone(&self.details);
            let instance = self
                .instances
                .entry(fragment.sender)
                .or_insert_with(|| Instance::new(details, fragment.sender, Rc::clone(&self.host)));
            return match instance.assembler.assemble(fragment) {
                // FIXME check whether fragment sender tag corresponds to message sender tag?
                // FIXME do something after parsing? Immediately delegate to particular instance? Immediately assume EncodedMessage content?
                Ok(assembled) => self.receive(assembled.as_slice()),
                // We've received a message fragment, but not enough to reassemble a message, so return early with no actual result and tell the client to wait for more fragments to arrive.
                Err(FragmentError::IncompleteResult) => Ok(UserMessage::None),
                Err(FragmentError::UnexpectedFragment) => Ok(UserMessage::None),
                Err(FragmentError::InvalidFormat) => {
                    Err(OTRError::ProtocolViolation("Fragment with invalid format."))
                }
                Err(FragmentError::InvalidData) => {
                    Err(OTRError::ProtocolViolation("Fragment with invalid data."))
                }
            };
        }
        // TODO we should reset assembler here, but not sure how to do this, given that we many `n` instances with fragment assembler.
        // TODO consider returning empty vector or error code when message is only intended for OTR internally.
        // FIXME we need to route non-OTR-encoded message through the session too, so that the session instance can act on plaintext message such as warning user for unencrypted messages in encrypted sessions.
        match parse(&payload)? {
            MessageType::ErrorMessage(error) => {
                if self.details.policy.contains(Policy::ERROR_START_AKE) {
                    // TODO if ERROR_START_AKE reply with Query message.
                    self.query(vec![Version::V3]);
                }
                Ok(UserMessage::Error(error))
            }
            MessageType::PlaintextMessage(content) => {
                if self.has_encrypted_sessions() {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else if self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::TaggedMessage(versions, content) => {
                if self.details.policy.contains(Policy::WHITESPACE_START_AKE) {
                    // Given policy, automatically initiate
                    // TODO currently assumes a version can be found, otherwise errors out too early, losing message.
                    self.initiate(
                        self.select_version(&versions)
                            .ok_or(OTRError::NoAcceptableVersion)?,
                        None,
                    )?;
                }
                if self.has_encrypted_sessions() {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else if self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::QueryMessage(versions) => {
                // TODO take policies and instances into account before initiating.
                self.initiate(
                    self.select_version(&versions)
                        .ok_or(OTRError::NoAcceptableVersion)?,
                    None,
                )?;
                Ok(UserMessage::None)
            }
            MessageType::EncodedMessage(msg) => {
                if msg.receiver != INSTANCE_ZERO && msg.receiver != self.details.tag {
                    return Err(OTRError::MessageForOtherInstance);
                }
                // FIXME at some point, need to clone the AKE state to the sender instance-tag once we have the actual tag (i.s.o. zero-tag) to continue establishing instance-personalized session.
                // FIXME in case of unreadable message, also send OTR Error message to other party
                self.instances
                    .get_mut(&msg.sender)
                    .ok_or(OTRError::UnknownInstance)?
                    .handle(msg)
            }
        }
    }

    fn select_version(&self, versions: &Vec<Version>) -> Option<Version> {
        // TODO take policies into account before initiating.
        if versions.contains(&Version::V3) {
            Some(Version::V3)
        } else {
            None
        }
    }

    pub fn send(&mut self, instance: InstanceTag, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        // FIXME figure out recipient, figure out messaging state, optionally encrypt, optionally tag, prepare byte-stream ready for sending.
        // FIXME send whitespace tag as first try if policy allows, after receiving a plaintext message, take as sign that OTR is not supported/recipient is not interested in engaging in OTR session.
        // FIXME figure out what the "default" instance is, if session is established, then send query message if in plaintext or whatever is otherwise necessary.
        // "If msgstate is MSGSTATE_PLAINTEXT:
        //    If REQUIRE_ENCRYPTION is set:
        //      Store the plaintext message for possible retransmission, and send a Query Message.
        //    Otherwise:
        //      If SEND_WHITESPACE_TAG is set, and you have not received a plaintext message from this correspondent since last entering MSGSTATE_PLAINTEXT, attach the whitespace tag to the message. Send the (possibly modified) message as plaintext.
        //  If msgstate is MSGSTATE_ENCRYPTED:
        //    Encrypt the message, and send it as a Data Message. Store the plaintext message for possible retransmission.
        //  If msgstate is MSGSTATE_FINISHED:
        //    Inform the user that the message cannot be sent at this time. Store the plaintext message for possible retransmission."
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance)?
            .send(content)
    }

    /// `initiate` initiates the OTR protocol for designated receiver.
    // FIXME this is an issue: we always start with instance receiver 0, so how can we distinguish instances?
    pub fn initiate(
        &mut self,
        version: Version,
        receiver: Option<InstanceTag>,
    ) -> Result<UserMessage, OTRError> {
        let receiver = receiver.unwrap_or(INSTANCE_ZERO);
        self.instances
            .entry(receiver)
            .or_insert_with(|| {
                Instance::new(Rc::clone(&self.details), receiver, Rc::clone(&self.host))
            })
            .initiate(version)
    }

    pub fn end(&mut self, receiver: InstanceTag) -> Result<UserMessage, OTRError> {
        self.instances
            .get_mut(&receiver)
            .ok_or(OTRError::UnknownInstance)?
            .reset()
    }

    pub fn query(&mut self, possible_versions: Vec<Version>) {
        // TODO verify possible versions against supported (non-blocked) versions.
        let msg = MessageType::QueryMessage(possible_versions);
        self.host.inject(&encode(&msg));
    }

    pub fn reset(&mut self, instance: InstanceTag) -> Result<UserMessage, OTRError> {
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance)?
            .reset()
    }

    /// has_encrypted_sessions checks if any instances have established or finished an OTR session.
    fn has_encrypted_sessions(&self) -> bool {
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
// TODO check rest of code for design-goal to have choices made in `Session` as much as possible.
impl Instance {
    fn new(details: Rc<AccountDetails>, receiver: InstanceTag, host: Rc<dyn Host>) -> Self {
        // FIXME include both our and their tags for repeated use?
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

    fn initiate(&mut self, version: Version) -> Result<UserMessage, OTRError> {
        assert_eq!(version, Version::V3);
        let msg = self
            .ake
            .initiate()
            .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
        self.host.inject(&encode_otr_message(
            self.ake.version(),
            self.details.tag,
            self.receiver,
            msg,
        ));
        Ok(UserMessage::None)
    }

    // FIXME should we also receive error message, plaintext message, tagged message etc. to warn about receiving unencrypted message during confidential session?
    fn handle(&mut self, encoded_message: EncodedMessage) -> Result<UserMessage, OTRError> {
        // TODO need to inspect error handling to appropriately respond with OTR message to indicate that an error has occurred. This has not yet been considered.
        assert_eq!(self.receiver, encoded_message.sender);
        // FIXME how to handle AKE errors in each case?
        match encoded_message.message {
            OTRMessageType::DHCommit(msg) => {
                let response = self
                    .ake
                    .handle_dhcommit(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
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
                    .handle_dhkey(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
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
                    .handle_reveal_signature(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                // FIXME handle errors and inject response.
                // FIXME ensure proper, verified transition to confidential session.
                let ctr = [0u8; CTR_LEN];
                self.state = self.state.secure(Rc::clone(&self.host), version, ssid, ctr, our_dh, their_dh, their_dsa);
                self.host.inject(&encode_otr_message(
                    Version::V3,
                    self.details.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::ConfidentialSessionStarted)
                // TODO If there is a recent stored message, encrypt it and send it as a Data Message.
            }
            OTRMessageType::Signature(msg) => {
                let CryptographicMaterial{version, ssid, our_dh, their_dh, their_dsa} = self
                    .ake
                    .handle_signature(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                // FIXME ensure proper, verified transition to confidential session.
                let ctr = [0u8; CTR_LEN];
                self.state = self.state.secure(Rc::clone(&self.host), version, ssid, ctr, our_dh, their_dh, their_dsa);
                Ok(UserMessage::ConfidentialSessionStarted)
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
                    Ok(UserMessage::Confidential(content, tlvs)) => {
                        if let Some(tlv) = tlvs.iter().find(|t| smp::is_smp_tlv(&t)) {
                            // REMARK we could inspect and log if messages with SMP TLVs do not have the IGNORE_UNREADABLE flag set.
                            // Socialist Millionaire Protocol (SMP)
                            let reply_tlv = self.state.smp()?.handle(tlv)?;
                            let otr_message = self.state.prepare(
                                MessageFlags::IGNORE_UNREADABLE,
                                &OTREncoder::new()
                                    .write_byte(0)
                                    .write_tlv(reply_tlv)
                                    .to_vec())?;
                            self.host.inject(&encode_otr_message(self.state.version(),
                                self.details.tag, self.receiver, otr_message));
                            // FIXME continue here: determine whether SMP has finished and what the outcome is.
                            // TODO SMP messages always have empty body?
                            Ok(UserMessage::None)
                        } else {
                            Ok(UserMessage::Confidential(content, tlvs))
                        }
                    },
                    msg @ Ok(_) => msg,
                    err @ Err(OTRError::UnreadableMessage) => {
                        self.host.inject(&encode(&MessageType::ErrorMessage(
                            Vec::from("unreadable message")
                        )));
                        if msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) {
                            Ok(UserMessage::None)
                        } else {
                            err
                        }
                    }
                    err @ Err(_) => err,
                }
            }
            OTRMessageType::Undefined(_) => panic!("BUG: this message-type is used as a placeholder. It can never be an incoming message-type to be handled."),
        }
    }

    fn reset(&mut self) -> Result<UserMessage, OTRError> {
        let previous = self.state.status();
        let version = self.state.version();
        // TODO what happens with verification status when we force-reset? Should be preserved? (prefer always reset for safety)
        let (abortmsg, newstate) = self.state.finish();
        self.state = newstate;
        if previous == self.state.status() {
            assert!(abortmsg.is_none());
            return Ok(UserMessage::None);
        }
        if let Some(msg) = abortmsg {
            self.host.inject(&encode_otr_message(
                version,
                self.details.tag,
                // FIXME replace with receiver tag of other party once accessible/available.
                self.receiver,
                msg,
            ));
        }
        Ok(UserMessage::Reset)
    }

    // TODO double-check if I use this function correctly, don't encode_otr_message twice!
    fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OTRError> {
        // TODO need to check for NULL chars, as this is also the separator for subsequent TLVs
        Ok(
            match self.state.prepare(MessageFlags::empty(), plaintext)? {
                OTRMessageType::Undefined(message) => {
                    if self.state.status() == ProtocolStatus::Plaintext {
                        panic!(
                            "BUG: received undefined message type in state {:?}",
                            self.state.status()
                        )
                    }
                    encode(&MessageType::PlaintextMessage(message))
                }
                message @ OTRMessageType::DHCommit(_)
                | message @ OTRMessageType::DHKey(_)
                | message @ OTRMessageType::RevealSignature(_)
                | message @ OTRMessageType::Signature(_)
                | message @ OTRMessageType::Data(_) => encode_otr_message(
                    self.state.version(),
                    self.details.tag,
                    self.receiver,
                    message,
                ),
            },
        )
    }

    fn start_smp(&mut self, secret: &[u8], question: &[u8]) -> Result<Vec<u8>, OTRError> {
        // logic currently assumes that if the call to smp succeeds, that we are in an appropriate
        // state to send a message with appended TLV.
        let tlv = self.state.smp()?.initiate(secret, question)?;
        // TODO double-check/reason on flag ignore-unreadable.
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
}

/// `AccountDetails` contains our own, static account details.
// TODO either extend AccountDetails as needed, or remove unnecessary wrapper for only single value?
struct AccountDetails {
    policy: Policy,
    tag: InstanceTag,
}

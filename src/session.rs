use std::{collections, rc::Rc};

use authentication::AKEContext;
use fragment::Assembler;

use crate::{
    authentication,
    encoding::{encode, encode_otr_message, parse, EncodedMessage, MessageType, OTRMessageType, CTR_LEN},
    fragment::{self, FragmentError},
    host::Host,
    instancetag::{InstanceTag, INSTANCE_ZERO},
    protocol, OTRError, UserMessage, Version, ProtocolStatus,
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
#[allow(dead_code)]
impl Account {
    pub fn new() -> Self {
        // FIXME implement new account creation
        todo!("to be implemented")
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
        return match parse(&payload)? {
            MessageType::ErrorMessage(error) => Ok(UserMessage::Error(error)),
            MessageType::PlaintextMessage(content) => Ok(UserMessage::Plaintext(content)),
            MessageType::TaggedMessage(versions, content) => {
                // TODO take policies into account before initiating.
                self.initiate(
                    self.select_version(&versions)
                        .ok_or(OTRError::NoAcceptableVersion)?,
                )?;
                Ok(UserMessage::Plaintext(content))
            }
            MessageType::QueryMessage(versions) => {
                // TODO take policies into account before initiating.
                self.initiate(
                    self.select_version(&versions)
                        .ok_or(OTRError::NoAcceptableVersion)?,
                )?;
                Ok(UserMessage::None)
            }
            MessageType::EncodedMessage(msg) => {
                if msg.receiver != INSTANCE_ZERO && msg.receiver != self.details.tag {
                    return Err(OTRError::MessageForOtherInstance);
                }
                // FIXME at some point, need to clone the AKE state to the sender instance-tag once we have the actual tag (i.s.o. zero-tag) to continue establishing instance-personalized session.
                self.instances
                    .get_mut(&msg.sender)
                    .ok_or(OTRError::UnknownInstance)?
                    .handle(msg)
            }
        };
    }

    // TODO should rely on some pool of accepted versions instead of hard-coding.
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
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance)?
            .send(content)
    }

    pub fn initiate(&mut self, version: Version) -> Result<UserMessage, OTRError> {
        let receiver = INSTANCE_ZERO;
        self.instances
            .entry(receiver)
            .or_insert_with(|| {
                Instance::new(Rc::clone(&self.details), receiver, Rc::clone(&self.host))
            })
            .initiate(version)
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
}

/// Instance serves a single communication session, ensuring that messages always travel between the same two clients.
struct Instance {
    // TODO can we share the details in an immutable way?
    account: Rc<AccountDetails>,
    receiver: InstanceTag,
    host: Rc<dyn Host>,
    assembler: Assembler,
    state: Box<dyn protocol::ProtocolState>,
    ake: AKEContext,
}

impl Instance {
    fn new(account: Rc<AccountDetails>, receiver: InstanceTag, host: Rc<dyn Host>) -> Self {
        // FIXME include both our and their tags for repeated use?
        Self {
            account,
            receiver,
            assembler: Assembler::new(),
            state: protocol::new_state(),
            ake: AKEContext::new(Rc::clone(&host)),
            host,
        }
    }

    fn status(&self) -> ProtocolStatus {
        return self.state.status();
    }

    fn initiate(&mut self, version: Version) -> Result<UserMessage, OTRError> {
        let msg = self
            .ake
            .initiate()
            .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
        self.host.inject(&encode_otr_message(
            version,
            self.account.tag,
            self.receiver,
            msg,
        ));
        // FIXME do we need to store the chosen protocol version here? probably yes
        Ok(UserMessage::None)
    }

    // FIXME should we also receive error message, plaintext message, tagged message etc. to warn about receiving unencrypted message during confidential session?
    fn handle(&mut self, encoded_message: EncodedMessage) -> Result<UserMessage, OTRError> {
        assert_eq!(self.receiver, encoded_message.sender);
        // FIXME how to handle AKE errors in each case?
        return match encoded_message.message {
            OTRMessageType::DHCommit(msg) => {
                let response = self
                    .ake
                    .handle_dhcommit(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                self.host.inject(&encode_otr_message(
                    Version::V3,
                    self.account.tag,
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
                    self.account.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::None)
            }
            OTRMessageType::RevealSignature(msg) => {
                let (material, response) = self
                    .ake
                    .handle_reveal_signature(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                // FIXME handle errors and inject response.
                // FIXME ensure proper, verified transition to confidential session.
                let ctr = [0u8; CTR_LEN];
                self.state = self.state.secure(material.version, material.ssid, ctr, Rc::clone(&material.our_dh), material.their_dh);
                self.host.inject(&encode_otr_message(
                    Version::V3,
                    self.account.tag,
                    encoded_message.sender,
                    response,
                ));
                Ok(UserMessage::ConfidentialSessionStarted)
                // TODO If there is a recent stored message, encrypt it and send it as a Data Message.
            }
            OTRMessageType::Signature(msg) => {
                let material = self
                    .ake
                    .handle_signature(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                // FIXME ensure proper, verified transition to confidential session.
                let ctr = [0u8; CTR_LEN];
                self.state = self.state.secure(material.version, material.ssid, ctr, Rc::clone(&material.our_dh), material.their_dh);
                Ok(UserMessage::ConfidentialSessionStarted)
                // TODO If there is a recent stored message, encrypt it and send it as a Data Message.
            }
            OTRMessageType::Data(msg) => {
                // FIXME verify and validate message before passing on to state.
                let (message, transition) = self.state.handle(&msg);
                if transition.is_some() {
                    self.state = transition.unwrap();
                }
                // FIXME in case of error, check for ignore-unreadable flag.
                return message;
            }
            OTRMessageType::Undefined(_) => panic!("BUG: this message-type is used as a placeholder. It can never be an incoming message-type to be handled."),
        };
    }

    fn reset(&mut self) -> Result<UserMessage, OTRError> {
        let previous = self.state.status();
        // TODO what happens with verification status when we force-reset? Should be preserved? (prefer always reset for safety)
        let (abortmsg, newstate) = self.state.finish();
        self.state = newstate;
        if previous == self.state.status() {
            return Ok(UserMessage::None);
        }
        if let Some(msg) = abortmsg {
            self.host.inject(&encode_otr_message(
                Version::V3,
                self.account.tag,
                // FIXME replace with receiver tag of other party once accessible/available.
                self.receiver,
                msg,
            ));
        }
        Ok(UserMessage::Reset)
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        // FIXME hard-coded instance tag INSTANCE_ZERO
        Ok(match self.state.send(content)? {
            OTRMessageType::Undefined(message) => {
                if self.state.status() == ProtocolStatus::Plaintext {
                    panic!("BUG: received undefined message type in state {:?}", self.state.status())
                }
                encode(&MessageType::PlaintextMessage(message))
            },
            message @ OTRMessageType::DHCommit(_)
            | message @ OTRMessageType::DHKey(_)
            | message @ OTRMessageType::RevealSignature(_)
            | message @ OTRMessageType::Signature(_)
            | message @ OTRMessageType::Data(_) => {
                encode_otr_message(self.state.version(), self.account.tag, self.receiver, message)
            }
        })
    }
}

// TODO either extend AccountDetails as needed, or remove unnecessary wrapper for only single value?
struct AccountDetails {
    tag: InstanceTag,
}

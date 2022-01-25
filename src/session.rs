use std::{collections, rc::Rc};

use authentication::AKEContext;
use fragment::{Assembler, AssemblingError};

use crate::{
    authentication,
    encoding::{parse, EncodedMessage, MessageType, OTRMessage},
    fragment,
    host::Host,
    protocol, InstanceTag, OTRError, UserMessage, Version,
};

pub struct Account {
    host: Rc<dyn Host>,
    tag: InstanceTag,
    instances: collections::HashMap<InstanceTag, Instance>,
}

#[allow(dead_code)]
impl Account {
    pub fn status(&self, instance: InstanceTag) -> Option<protocol::ProtocolStatus> {
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
            if fragment.receiver != self.tag && fragment.receiver != 0u32 {
                return Err(OTRError::MessageForOtherInstance);
            }
            if !self.instances.contains_key(&fragment.sender) {
                self.instances.insert(
                    fragment.sender,
                    Instance {
                        assembler: Assembler::new(),
                        state: protocol::new(),
                        ake: AKEContext::new(Rc::clone(&self.host)),
                    },
                );
            }
            let instance = self.instances.get_mut(&fragment.sender).unwrap();
            return match instance.assembler.assemble(fragment) {
                // FIXME check whether fragment sender tag corresponds to message sender tag?
                // FIXME do something after parsing? Immediately delegate to particular instance? Immediately assume EncodedMessage content?
                Ok(assembled) => self.receive(assembled.as_slice()),
                // We've received a message fragment, but not enough to reassemble a message, so return early with no actual result and tell the client to wait for more fragments to arrive.
                Err(AssemblingError::IncompleteResult) => Ok(UserMessage::None),
                Err(AssemblingError::IllegalFragment) => {
                    Err(OTRError::ProtocolViolation("Illegal fragment received."))
                }
                Err(AssemblingError::UnexpectedFragment) => {
                    // TODO debug info, keep?
                    println!("Unexpected fragment received. Assembler reset.");
                    Ok(UserMessage::None)
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
                // TODO: take policies into account before initiating.
                self.initiate(versions);
                Ok(UserMessage::Plaintext(content))
            }
            MessageType::QueryMessage(versions) => {
                // TODO: take policies into account before initiating.
                self.initiate(versions);
                Ok(UserMessage::Initiated)
            }
            MessageType::EncodedMessage(msg) => {
                // FIXME add more precise instane tag (sender/receiver) validation.
                if msg.receiver != 0u32 && msg.receiver != self.tag {
                    return Err(OTRError::MessageForOtherInstance);
                }
                self.instances
                    .get_mut(&msg.sender)
                    .ok_or(OTRError::UnknownInstance)?
                    .handle(self.host.as_ref(), msg)
            }
        };
    }

    pub fn send(&mut self, instance: InstanceTag, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        // return self.instances.get_mut(&instance).unwrap().send(content);
        // FIXME figure out recipient, figure out messaging state, optionally encrypt, optionally tag, prepare byte-stream ready for sending.
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance)?
            .send(content)
    }

    fn initiate(&mut self, _accepted_versions: Vec<Version>) {
        todo!("Implement sending/injecting DH-Commit message.")
    }

    fn query(&mut self, _possible_versions: Vec<Version>) {
        todo!("Query by sending query message.")
    }
}

/// Instance serves a single communication session, ensuring that messages always go to the same single client.
struct Instance {
    assembler: Assembler,
    state: Box<dyn protocol::ProtocolState>,
    ake: AKEContext,
}

impl Instance {
    fn status(&self) -> protocol::ProtocolStatus {
        return self.state.status();
    }

    fn initiate(&mut self) -> Result<(), OTRError> {
        let msg = self.ake.initiate().unwrap();
        todo!()
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        encodedmessage: EncodedMessage,
    ) -> Result<UserMessage, OTRError> {
        // FIXME how to handle AKE errors in each case?
        return match encodedmessage.message {
            OTRMessage::DHCommit(msg) => {
                let response = self
                    .ake
                    .handle_commit(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;

                // FIXME handle errors and inject response.
                Ok(UserMessage::None)
            }
            OTRMessage::DHKey(msg) => {
                let response = self
                    .ake
                    .handle_key(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                // FIXME handle errors and inject response.
                Ok(UserMessage::None)
            }
            OTRMessage::RevealSignature(msg) => {
                let response = self
                    .ake
                    .handle_reveal_signature(msg)
                    .or_else(|err| Err(OTRError::AuthenticationError(err)))?;
                // FIXME handle errors and inject response.
                // FIXME ensure proper, verified transition to confidential session.
                self.state = self.state.secure();
                Ok(UserMessage::ConfidentialSessionStarted)
            }
            OTRMessage::Signature(msg) => {
                let result = self.ake.handle_signature(msg);
                // FIXME handle errors and inject response.
                // FIXME ensure proper, verified transition to confidential session.
                self.state = self.state.secure();
                Ok(UserMessage::ConfidentialSessionStarted)
            }
            OTRMessage::Data(msg) => {
                // FIXME verify and validate message before passing on to state.
                let (message, transition) = self.state.handle(&msg);
                if transition.is_some() {
                    self.state = transition.unwrap();
                }
                // FIXME in case of error, check for ignore-unreadable flag.
                return message;
            }
        };
    }

    // TODO: probably an API function => pub
    fn finish(&mut self) -> Result<UserMessage, OTRError> {
        // FIXME verify and validate message before passing on to state.
        self.state = self.state.finish();
        // FIXME how to determine if we aborted an existing confidential session? (Do we really care?)
        return Ok(UserMessage::Reset);
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return self.state.send(content);
    }
}

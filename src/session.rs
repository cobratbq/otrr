use std::collections;

use crate::{InstanceTag, Message, OTRError, Version, decoder::{self, MessageType, OTRMessage}, fragment, protocol};

pub struct Account {
    instances: collections::HashMap<InstanceTag, Instance>,
}

impl Account {
    // TODO fuzzing target
    pub fn receive(&mut self, payload: &[u8]) -> Result<Message, OTRError> {
        if fragment::is_fragment(payload) {
            // FIXME handle OTRv2 fragments not being supported(?)
            let fragment = fragment::parse(payload);
            if !self.instances.contains_key(&fragment.sender) {
                self.instances.insert(
                    fragment.sender,
                    Instance {
                        assembler: fragment::new_assembler(),
                        state: protocol::ProtocolState::Plaintext,
                    },
                );
            }
            let instance = self.instances.get_mut(&fragment.sender).unwrap();
            match instance.assembler.assemble(fragment) {
                // FIXME check whether fragment sender tag corresponds to message sender tag?
                // FIXME do something after parsing? Immediately delegate to particular instance? Immediately assume EncodedMessage content?
                Ok(assembled) => return self.receive(assembled.as_slice()),
                // We've received a message fragment, but not enough to reassemble a message, so return early with no actual result and tell the client to wait for more fragments to arrive.
                Err(fragment::AssemblingError::IncompleteResult) => return Ok(Message::None),
                Err(fragment::AssemblingError::IllegalFragment) => return Err(OTRError::ProtocolViolation("Illegal fragment received.")),
                Err(fragment::AssemblingError::UnexpectedFragment) => {
                    todo!("handle unexpected fragments")
                }
            }
        }
        // TODO we should reset assembler here, but not sure how to do this, given that we many `n` instances with fragment assembler.
        // TODO consider returning empty vector or error code when message is only intended for OTR internally.
        return match decoder::parse(&payload)? {
            MessageType::ErrorMessage(error) => Ok(Message::Error(error)),
            MessageType::PlaintextMessage(content) => Ok(Message::Plain(content)),
            MessageType::TaggedMessage(versions, content) => {
                // FIXME act on versions in tagged message.
                Ok(Message::Plain(content))
            }
            MessageType::QueryMessage(versions) => {
                // FIXME act on versions in query message.
                Ok(Message::None)
            }
            MessageType::EncodedMessage {
                version,
                sender,
                receiver,
                message,
            } => {
                // FIXME look-up or create instance, delegate handling to instance
                self.instances.get_mut(&sender).unwrap().handle(version, sender, receiver, message);
                todo!("Implement!")
            }
        };
    }
}

pub struct Instance {
    assembler: fragment::Assembler,
    state: protocol::ProtocolState,
}

impl Instance {
    fn handle(&mut self, version: Version, sender: InstanceTag, receiver: InstanceTag, message: OTRMessage) {
        // FIXME implement message handling
    }
}

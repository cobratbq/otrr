use std::collections;

use crate::{InstanceTag, OTRError, Version, decoder, fragment, protocol};

// pub trait Session {
//     fn receive(payload: &[u8]);
//     //pub fn send();
// }

pub struct Account {
    instances: collections::HashMap<InstanceTag, Instance>,
}

impl Account {
    // TODO fuzzing target
    pub fn receive(&mut self, payload: &[u8]) -> Result<Vec<u8>, OTRError> {
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
                Err(fragment::AssemblingError::IncompleteResult) => return Ok(Vec::new()),
                Err(fragment::AssemblingError::IllegalFragment) => return Err(OTRError::ProtocolViolation("Illegal fragment received.")),
                Err(fragment::AssemblingError::UnexpectedFragment) => {
                    todo!("handle unexpected fragments")
                }
            }
        }
        // TODO we should reset assembler here, but not sure how to do this, given that we many `n` instances with fragment assembler.
        // TODO consider returning empty vector or error code when message is only intended for OTR internally.
        return match decoder::parse(&payload)? {
            decoder::MessageType::ErrorMessage(error) => Err(OTRError::ErrorMessage(error)),
            decoder::MessageType::PlaintextMessage(content) => Ok(content),
            decoder::MessageType::TaggedMessage(versions, content) => {
                // FIXME act on versions in tagged message.
                Ok(content)
            }
            decoder::MessageType::QueryMessage(versions) => {
                // FIXME act on versions in query message.
                Ok(Vec::new())
            },
            decoder::MessageType::EncodedMessage {
                version,
                messagetype,
                sender,
                receiver,
                content,
            } => {
                // FIXME look-up or create instance, delegate handling to instance
                self.instances.get_mut(&sender).unwrap().handle(version, messagetype, sender, receiver, content);
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
    fn handle(&mut self, version: Version, messagetype: decoder::EncodedMessageType, sender: InstanceTag, receiver: InstanceTag, content: Vec<u8>) {
        // FIXME implement message handling
    }
}

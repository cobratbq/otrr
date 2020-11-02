use std::collections;

use crate::{decoder, fragment, protocol, InstanceTag, OTRError};

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
            // FIXME handle OTRv2 fragments not being supported.
            let fragment = fragment::parse_fragment(payload);
            if !self.instances.contains_key(&fragment.sender) {
                self.instances.insert(
                    fragment.sender,
                    Instance {
                        assembler: fragment::NewAssembler(),
                        state: protocol::ProtocolState::Plaintext,
                    },
                );
            }
            let instance = self.instances.get_mut(&fragment.sender).unwrap();
            match instance.assembler.assemble(fragment) {
                Ok(assembled) => {
                    // Given that we know fragment's sender instance tag, immediately redirect to expected/mandatory instance.
                    // This also prevents malicious data where the fragment sender instance tag is different from the payload's sender instance tag.

                    // FIXME do something after parsing? Immediately delegate to particular instance? Immediately assume EncodedMessage content?
                    return self.receive(assembled.as_slice());
                }
                Err(fragment::AssemblingError::IncompleteResult) => {
                    todo!("handle incomplete result")
                }
                Err(fragment::AssemblingError::IllegalFragment) => {
                    todo!("handle illegal fragments")
                }
                Err(fragment::AssemblingError::UnexpectedFragment) => {
                    todo!("handle unexpected fragments")
                }
            }
        }
        // FIXME we should reset assembler here, but not sure how to do this, given that we many `n` instances with fragment assembler.
        return match decoder::parse(&payload)? {
            decoder::MessageType::ErrorMessage(error) => Err(OTRError::ErrorMessage(error)),
            decoder::MessageType::PlaintextMessage(content) => todo!("To be implemented"),
            decoder::MessageType::TaggedMessage(versions, content) => todo!("To be implemented"),
            decoder::MessageType::QueryMessage(versions) => todo!("To be implemented"),
            decoder::MessageType::EncodedMessage {
                version,
                messagetype,
                sender,
                receiver,
                content,
            } => todo!("Implement!"),
        };
    }
}

pub struct Instance {
    assembler: fragment::Assembler,
    state: protocol::ProtocolState,
}

impl Instance {
    fn handle(&mut self) {}
}

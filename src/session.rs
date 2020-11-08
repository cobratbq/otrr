use std::collections;

use crate::{
    decoder::{self, MessageType, OTRMessage},
    fragment, protocol, Host, InstanceTag, Message, OTRError, Version,
};

pub struct Account {
    host: Box<dyn Host>,
    instances: collections::HashMap<InstanceTag, Instance>,
}

// TODO add conditional initiation of OTR protocol AKE.
// TODO introduce fragmenter.

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
                        state: Box::new(protocol::PlaintextState {}),
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
                Err(fragment::AssemblingError::IllegalFragment) => {
                    return Err(OTRError::ProtocolViolation("Illegal fragment received."))
                }
                Err(fragment::AssemblingError::UnexpectedFragment) => {
                    todo!("handle unexpected fragments")
                }
            }
        }
        // TODO we should reset assembler here, but not sure how to do this, given that we many `n` instances with fragment assembler.
        // TODO consider returning empty vector or error code when message is only intended for OTR internally.
        // FIXME we need to route non-OTR-encoded message through the session too, so that the session instancce can act on plaintext message such as warning user for unencrypted messages in encrypted sessions.
        return match decoder::parse(&payload)? {
            MessageType::ErrorMessage(error) => Ok(Message::Error(error)),
            MessageType::PlaintextMessage(content) => Ok(Message::Plain(content)),
            MessageType::TaggedMessage(versions, content) => {
                self.initiate(versions);
                Ok(Message::Plain(content))
            }
            MessageType::QueryMessage(versions) => {
                self.initiate(versions);
                Ok(Message::None)
            }
            MessageType::EncodedMessage {
                version,
                sender,
                receiver,
                message,
            } => {
                // FIXME look-up or create instance, delegate handling to instance
                self.instances.get_mut(&sender).unwrap().handle(
                    self.host.as_ref(),
                    version,
                    sender,
                    receiver,
                    message,
                )
            }
        };
    }

    fn initiate(&mut self, versions: Vec<Version>) {
        todo!("Implement sending/injecting DH-Commit message.")
    }
}

pub struct Instance {
    assembler: fragment::Assembler,
    state: Box<dyn protocol::ProtocolState>,
}

impl Instance {
    fn handle(
        &mut self,
        host: &dyn Host,
        version: Version,
        sender: InstanceTag,
        receiver: InstanceTag,
        message: OTRMessage,
    ) -> Result<Message, OTRError> {
        let (message, new_state) = self.state.handle(host, message);
        self.update(new_state);
        return message;
    }

    fn finish(&mut self) -> Result<Message, OTRError> {
        let (message, new_state) = self.state.finish();
        self.update(new_state);
        return message;
    }

    // TODO replace with macro?
    fn update(&mut self, new_state: Option<Box<dyn protocol::ProtocolState>>) {
        if new_state.is_none() {
            return
        }
        self.state = new_state.unwrap();
    }
}

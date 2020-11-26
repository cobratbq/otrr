use std::collections;

use crate::{
    authentication,
    encoding::{self, MessageType, OTRMessage},
    fragment, protocol, Host, InstanceTag, Message, OTRError, Version,
};

pub struct Account {
    host: Box<dyn Host>,
    tag: InstanceTag,
    instances: collections::HashMap<InstanceTag, Instance>,
}

impl Account {
    // TODO fuzzing target
    pub fn receive(&mut self, payload: &[u8]) -> Result<Message, OTRError> {
        if fragment::is_fragment(payload) {
            // FIXME handle OTRv2 fragments not being supported(?)
            let fragment = fragment::parse(payload).or(Err(OTRError::ProtocolViolation(
                "Illegal or unsupported fragment.",
            )))?;
            if fragment.receiver != self.tag && fragment.receiver != 0u32 {
                return Err(OTRError::MessageForOtherInstance);
            }
            if !self.instances.contains_key(&fragment.sender) {
                self.instances.insert(
                    fragment.sender,
                    Instance {
                        assembler: fragment::new_assembler(),
                        state: protocol::new_protocol_state(),
                        ake: authentication::new_context(),
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
        return match encoding::parse(&payload)? {
            MessageType::ErrorMessage(error) => Ok(Message::Error(error)),
            MessageType::PlaintextMessage(content) => Ok(Message::Plaintext(content)),
            MessageType::TaggedMessage(versions, content) => {
                self.initiate(versions);
                Ok(Message::Plaintext(content))
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
                // FIXME add more precise instane tag (sender/receiver) validation.
                if receiver != 0u32 && receiver != self.tag {
                    return Err(OTRError::MessageForOtherInstance);
                }
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

    pub fn send(&mut self, instance: InstanceTag, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return self.instances.get_mut(&instance).unwrap().send(content);
        // FIXME figure out recipient, figure out messaging state, optionally encrypt, optionally tag, prepare byte-stream ready for sending.
        todo!()
    }

    fn initiate(&mut self, accepted_versions: Vec<Version>) {
        todo!("Implement sending/injecting DH-Commit message.")
    }

    fn query(&mut self, possible_versions: Vec<Version>) {
        todo!("Query by sending query message.")
    }
}

struct Instance {
    assembler: fragment::Assembler,
    state: Box<dyn protocol::ProtocolState>,
    ake: authentication::AKEContext,
}

impl Instance {
    fn status(&self) -> protocol::ProtocolStatus {
        return self.state.status();
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        version: Version,
        sender: InstanceTag,
        receiver: InstanceTag,
        message: OTRMessage,
    ) -> Result<Message, OTRError> {
        return match message {
            OTRMessage::DHCommit {
                gx_encrypted,
                gx_hashed,
            } => {
                let response = self.ake.handle_commit(gx_encrypted, gx_hashed);
                // FIXME handle errors and inject response.
                Ok(Message::None)
            }
            OTRMessage::DHKey { gy } => {
                let response = self.ake.handle_key(&gy);
                // FIXME handle errors and inject response.
                Ok(Message::None)
            }
            OTRMessage::RevealSignature {
                key,
                signature_encrypted,
                signature_mac,
            } => {
                let response = self.ake.handle_reveal_signature(key, signature_encrypted, signature_mac);
                // FIXME handle errors and inject response.
                // FIXME ensure proper, verified transition to confidential session.
                Ok(Message::ConfidentialSessionStarted)
            }
            OTRMessage::Signature {
                signature_encrypted,
                signature_mac,
            } => {
                let result = self.ake.handle_signature(signature_encrypted, signature_mac);
                // FIXME handle errors and inject response.
                // FIXME ensure proper, verified transition to confidential session.
                self.state = Box::new(self.state.secure()?);
                Ok(Message::ConfidentialSessionStarted)
            }
            OTRMessage::Data {
                flags,
                sender_keyid,
                receiver_keyid,
                dh_y,
                ctr,
                encrypted,
                authenticator,
                revealed,
            } => {
                // FIXME verify and validate message before passing on to state.
                let (message, new_state) = self.state.handle(host, dh_y, ctr, encrypted, authenticator);
                self._update(new_state);
                // FIXME in case of error, check for ignore-unreadable flag.
                return message;
            }
        };
    }

    fn finish(&mut self) -> Result<Message, OTRError> {
        // FIXME verify and validate message before passing on to state.
        let (message, new_state) = self.state.finish();
        self._update(new_state);
        return message;
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return self.state.send(content);
    }

    // TODO replace with macro?
    fn _update(&mut self, new_state: Option<Box<dyn protocol::ProtocolState>>) {
        if new_state.is_none() {
            return;
        }
        self.state = new_state.unwrap();
    }
}

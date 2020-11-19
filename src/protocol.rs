use crate::{authentication, decoder::OTRMessage, Host, Message, OTRError};

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn handle(
        &mut self,
        host: &dyn Host,
        message: OTRMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError>;
}

pub enum ProtocolStatus {
    Plaintext,
    Encrypted,
    Finished,
}

pub fn new_protocol_state() -> Box<dyn ProtocolState> {
    return Box::new(PlaintextState {
        ake: authentication::AKEState::None,
    });
}

struct PlaintextState {
    ake: authentication::AKEState,
}

impl ProtocolState for PlaintextState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Plaintext;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        message: OTRMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return match message {
            OTRMessage::DHCommit {
                gx_encrypted: _,
                gx_hashed: _,
            } => todo!(),
            OTRMessage::DHKey { gy: _ } => todo!(),
            OTRMessage::RevealSignature {
                key: _,
                signature_encrypted: _,
                signature_mac: _,
            } => todo!(),
            OTRMessage::Signature {
                signature_encrypted: _,
                signature_mac: _,
            } => todo!(),
            OTRMessage::Data {
                flags: _,
                sender_keyid: _,
                receiver_keyid: _,
                dh_y: _,
                ctr: _,
                encrypted: _,
                authenticator: _,
                revealed: _,
            } => (Err(OTRError::UnreadableMessage), None),
        };
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Ok(Message::None), None);
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Ok(Vec::from(content));
    }
}

struct EncryptedState {}

impl ProtocolState for EncryptedState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Encrypted;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        message: OTRMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        return match message {
            OTRMessage::DHCommit {
                gx_encrypted: _,
                gx_hashed: _,
            } => todo!(),
            OTRMessage::DHKey { gy: _ } => todo!(),
            OTRMessage::RevealSignature {
                key: _,
                signature_encrypted: _,
                signature_mac: _,
            } => todo!(),
            OTRMessage::Signature {
                signature_encrypted: _,
                signature_mac: _,
            } => todo!(),
            OTRMessage::Data {
                flags: _,
                sender_keyid: _,
                receiver_keyid: _,
                dh_y: _,
                ctr: _,
                encrypted: _,
                authenticator: _,
                revealed: _,
            } => todo!(),
        };
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        return (
            Ok(Message::Reset),
            Some(Box::new(PlaintextState {
                ake: authentication::AKEState::None,
            })),
        );
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        todo!()
    }
}

struct FinishedState {}

impl ProtocolState for FinishedState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Finished;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        message: OTRMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return match message {
            OTRMessage::DHCommit {
                gx_encrypted: _,
                gx_hashed: _,
            } => todo!(),
            OTRMessage::DHKey { gy: _ } => todo!(),
            OTRMessage::RevealSignature {
                key: _,
                signature_encrypted: _,
                signature_mac: _,
            } => todo!(),
            OTRMessage::Signature {
                signature_encrypted: _,
                signature_mac: _,
            } => todo!(),
            OTRMessage::Data {
                flags: _,
                sender_keyid: _,
                receiver_keyid: _,
                dh_y: _,
                ctr: _,
                encrypted: _,
                authenticator: _,
                revealed: _,
            } => (Err(OTRError::UnreadableMessage), None),
        };
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (
            Ok(Message::Reset),
            Some(Box::new(PlaintextState {
                ake: authentication::AKEState::None,
            })),
        );
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Err(OTRError::ProtocolInFinishedState);
    }
}

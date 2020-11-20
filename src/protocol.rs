use crate::{CTR, Host, Message, OTRError};

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn handle(
        &mut self,
        host: &dyn Host,
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
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
    return Box::new(PlaintextState {});
}

struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Plaintext;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME assumes that this only needs to handle encrypted (OTR Data messages).
        return (Err(OTRError::UnreadableMessage), None)
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
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        todo!("To be implemented")
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        return (
            Ok(Message::Reset),
            Some(Box::new(PlaintextState {})),
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
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Err(OTRError::UnreadableMessage), None)
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (
            Ok(Message::Reset),
            Some(Box::new(PlaintextState {})),
        );
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Err(OTRError::ProtocolInFinishedState);
    }
}

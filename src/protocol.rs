use crate::{CTR, host::Host, Message, OTRError};

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
    fn secure(&self) -> Box<EncryptedState>;
    // FIXME consider simplifying return value below.
    fn finish(&self) -> Box<PlaintextState>;
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

pub struct PlaintextState {}

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

    fn secure(&self) -> Box<EncryptedState> {
        todo!()
    }

    fn finish(&self) -> Box<PlaintextState> {
        // FIXME is it desireable/harmful to have to construct a new instance?
        return Box::new(PlaintextState {});
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Ok(Vec::from(content));
    }
}

pub struct EncryptedState {}

impl Drop for EncryptedState {
    fn drop(&mut self) {
        todo!()
    }
}

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

    fn secure(&self) -> Box<EncryptedState> {
        todo!()
    }

    fn finish(&self) -> Box<PlaintextState> {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        return Box::new(PlaintextState {});
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        todo!()
    }
}

pub struct FinishedState {}

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

    fn secure(&self) -> Box<EncryptedState> {
        todo!()
    }

    fn finish(&self) -> Box<PlaintextState> {
        return Box::new(PlaintextState {});
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Err(OTRError::ProtocolInFinishedState);
    }
}

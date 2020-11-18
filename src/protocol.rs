use crate::{Host, Message, OTRError, decoder::OTRMessage};

pub trait ProtocolState {
    fn is_confidential(&self) -> bool;
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError>;
}

pub struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn is_confidential(&self) -> bool {
        return false;
    }

    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Ok(Message::None), None);
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Ok(Vec::from(content))
    }
}

struct EncryptedState {}

impl ProtocolState for EncryptedState {
    fn is_confidential(&self) -> bool {
        return true;
    }

    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        return (Ok(Message::Reset), Some(Box::new(PlaintextState {})));
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        todo!()
    }
}

struct FinishedState {}

impl ProtocolState for FinishedState {
    fn is_confidential(&self) -> bool {
        return false;
    }

    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Ok(Message::Reset), Some(Box::new(PlaintextState {})));
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Err(OTRError::ProtocolInFinishedState);
    }
}

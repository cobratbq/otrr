use crate::{Host, Message, OTRError, decoder::OTRMessage};

pub trait ProtocolState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
}

pub struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Ok(Message::None), None);
    }
}

struct EncryptedState {}

impl ProtocolState for EncryptedState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        return (Ok(Message::Reset), Some(Box::new(PlaintextState {})));
    }
}

struct FinishedState {}

impl ProtocolState for FinishedState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Ok(Message::Reset), Some(Box::new(PlaintextState {})));
    }
}

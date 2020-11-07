use crate::{authentication::AKEState, Host, decoder::OTRMessage};

pub trait ProtocolState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> Option<Box<dyn ProtocolState>>;
    fn finish(&mut self) -> Option<Box<dyn ProtocolState>>;
}

pub struct PlaintextState {

}

impl ProtocolState for PlaintextState {

    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> Option<Box<dyn ProtocolState>> {
        return None
    }

    fn finish(&mut self) -> Option<Box<dyn ProtocolState>> {
        return None
    }
}

struct EncryptedState {
    ake: AKEState,
}

impl ProtocolState for EncryptedState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> Option<Box<dyn ProtocolState>> {
        todo!()
    }

    fn finish(&mut self) -> Option<Box<dyn ProtocolState>> {
        return Some(Box::new(PlaintextState{}))
    }
}

struct FinishedState {
}

impl ProtocolState for FinishedState {
    fn handle(&mut self, host: &dyn Host, message: OTRMessage) -> Option<Box<dyn ProtocolState>> {
        todo!()
    }

    fn finish(&mut self) -> Option<Box<dyn ProtocolState>> {
        return Some(Box::new(PlaintextState{}))
    }
}
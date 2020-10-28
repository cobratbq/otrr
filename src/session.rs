use std::collections;

use crate::{decoder::Decoder, InstanceTag, protocol::ProtocolState};

// pub trait Session {
//     fn receive(payload: &[u8]);
//     //pub fn send();
// }

pub struct Account {
    instances: collections::HashMap<InstanceTag, Instance>,
}

impl Account {

    pub fn receive(payload: &[u8]) {
        
    }
}

pub struct Instance {
    decoder: Decoder,
    state: ProtocolState,
}

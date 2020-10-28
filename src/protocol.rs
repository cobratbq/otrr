use crate::authentication::AKEState;

pub enum ProtocolState {
    Plaintext,
    Encrypted{
        ake: AKEState,
    },
    Finished,
}

use crate::crypto::DSA;

// TODO warn in case of unreadable message unless unreadable-flag is set
/// Host represents the Host implementation for calling back into the messaging client.
pub trait Host {
    /// Inject a message into the messaging's transport stream. (I.e. protocol-related so not relevant to return to the client.)
    fn inject(&self, message: &Vec<u8>);

    // TODO need to distinguish between public keys for various accounts? (avoids linking identity over different chat networks)
    /// Acquire the long-term DSA keypair from the host application.
    fn keypair(&self) -> DSA::Keypair;
}

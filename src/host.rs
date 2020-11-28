use crate::crypto::DSA;

// TODO warn in case of unreadable message unless unreadable-flag is set
/// Host represents the Host implementation for calling back into the messaging client.
pub trait Host {
    /// Inject a message into the messaging's transport stream.
    fn inject(&self, message: &[u8]);

    // FIXME give this function a decent name!
    fn public_key(&self) -> DSA::PublicKey;
}

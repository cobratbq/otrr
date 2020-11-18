extern crate base64;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate hex;
extern crate num_bigint;

mod authentication;
mod decoder;
mod fragment;
mod protocol;
mod session;

/// Host represents the Host implementation for calling back into the messaging client.
pub trait Host {
    /// Inject a message into the messaging's transport stream.
    fn inject(&self, message: &[u8]);
}

/// Message represents the resulting Message intended for the messaging client, possibly containing content relevant to display to the user.
pub enum Message {
    /// Nothing received that is relevant to report/transfer back to the messaging client.
    None,
    /// Message for user received over open, plaintext transport.
    Plaintext(Vec<u8>),
    /// OTR error message received.
    Error(Vec<u8>),
    /// Message state reset to "plaintext". (by user action)
    Reset,
    /// Confidential session started, transitioned to "encrypted" state.
    ConfidentialSessionStarted,
    /// Message for user received over confidential OTR transport.
    Confidential(Vec<u8>),
    /// Confidential session ended, transitioned to "finished" state. (Session ended by other party.)
    ConfidentialSessionFinished,
}

/// OTRError is the enum containing the various errors that can occur.
#[derive(std::fmt::Debug)]
pub enum OTRError {
    /// Message contained invalid data according to the OTR protocol.
    ProtocolViolation(&'static str),
    /// Message payload is incomplete. The message cannot be reconstructed from the received bytes.
    IncompleteMessage,
    /// An OTR message was received that is intended for a different instance (client).
    MessageForOtherInstance,
    /// Messaging is blocked in OTR protocol "Finished" state to ensure no accidental disclosure occurs.
    ProtocolInFinishedState,
}

/// Version contains the various supported OTR protocol versions.
#[derive(PartialEq)]
pub enum Version {
    Unsupported(u16),
    // V1, // will not be supported.
    // V2, // will not be supported.
    V3,
}

/// InstanceTag represents a client instance tag. The instance tag is used to distinguish between multiple clients using the same account.
pub type InstanceTag = u32;

// TODO early implementation assumptions:
// 1. injections of messages into the transport never fails.
// 2. OTR is always enabled.
// 3. add message fragmentation.
// 4. ...

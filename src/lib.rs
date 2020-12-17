use authentication::AKEError;

extern crate aes_ctr;
extern crate base64;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate hex;
extern crate num_bigint;
extern crate ring;

mod authentication;
mod crypto;
mod encoding;
mod fragment;
mod protocol;

pub mod host;
pub mod session;

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
    /// Encrypted message is unreadable due to loss of keys and/or wrong protocol state.
    UnreadableMessage,
    /// An OTR message was received that is intended for a different instance (client).
    MessageForOtherInstance,
    /// Messaging is blocked in OTR protocol "Finished" state to ensure no accidental disclosure occurs.
    ProtocolInFinishedState,
    /// Violation of cryptographic or mathematical requirement for correct/secure operation.
    CryptographicViolation(&'static str),
    /// AuthenticationError indicates that there was an error during AKE.
    AuthenticationError(AKEError),
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

/// CTR type represents the first half of the counter value used for encryption, which is transmitted between communicating parties.
type CTR = [u8; 8];

/// MAC type represents the 20-byte MAC value.
type MAC = [u8; 20];

type Signature = [u8; 40];

// TODO early implementation assumptions:
// 1. injections of messages into the transport never fails.
// 2. OTR is always enabled.
// 3. add message fragmentation.
// 4. ...

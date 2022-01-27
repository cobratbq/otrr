use authentication::AKEError;
use bitflags::bitflags;
use crypto::CryptoError;

extern crate aes_ctr;
extern crate base64;
extern crate bitflags;
extern crate hex;
extern crate num;
extern crate num_bigint;
// TODO std::lazy::Lazy is in rust nightly, consider using that once available.
extern crate once_cell;
extern crate regex;
extern crate ring;

mod authentication;
mod crypto;
mod encoding;
mod fragment;
mod protocol;

pub mod host;
pub mod session;

// TODO early implementation assumptions:
// 1. injections of messages into the transport never fails.
// 2. OTR is always enabled. (clarify nuances of this/meaning of this)
// 3. add message fragmentation.
// 4. ...

// TODO initialization-time checking:
//   1. CPU capabilities: usize 32-bit or 64-bit, given checking for appropriate boundaries throughout code. (e.g. encoding.rs serialization)

/// UserMessage represents the resulting Message intended for the messaging client, possibly containing content relevant to display to the user.
pub enum UserMessage {
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
    /// Message to be sent to an unknown instance. (FIXME need to check with spec on details)
    UnknownInstance,
    // FIXME: not sure if this is the way to go...
    /// No acceptable version available in proposed protocol versions.
    NoAcceptableVersion,
    /// Messaging is blocked in OTR protocol "Finished" state to ensure no accidental disclosure occurs.
    ProtocolInFinishedState,
    /// Violation of cryptographic or mathematical requirement for correct/secure operation.
    CryptographicViolation(CryptoError),
    /// (AKE) AuthenticationError indicates that there was an error during AKE.
    AuthenticationError(AKEError),
    /// (SMP) SMPInProgress indicates that an SMP exchange is in progress, so to initiate a new SMP,
    /// the previous one needs to be aborted first.
    SMPInProgress,
    SMPAborted(TLV),
    SMPProtocolViolation,
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
const INSTANCE_ZERO: InstanceTag = 0u32;
pub type InstanceTag = u32;

// TODO: how can I initialize arrays using their type aliases, such that I don't have to repeat the size?
/// CTR type represents the first half of the counter value used for encryption, which is transmitted between communicating parties.
const CTR_LEN: usize = 8;
type CTR = [u8; CTR_LEN];

/// MAC type represents the 20-byte MAC value.
const MAC_LEN: usize = 20;
type MAC = [u8; MAC_LEN];

/// Signature type represents a DSA signature in IEEE-P1363 representation.
const SIGNATURE_LEN: usize = 40;
type Signature = [u8; SIGNATURE_LEN];

#[derive(Debug)]
pub struct TLV(pub u16, pub Vec<u8>);

// TODO implement use of policy flags!
bitflags! {
    /// Policy bit-flags can be set to indicate how OTR should respond to certain events related to messaging and the OTR protocol.
    struct Policy: u32 {
    // ALLOW_V1
    //     Allow version 1 of the OTR protocol to be used (in general this document will not address OTR protocol version 1; see previous protocol documents for these details).
    //const ALLOW_V1 = 0b00000001;
    // ALLOW_V2
    //     Allow version 2 of the OTR protocol to be used.
    //const ALLOW_V2 = 0b00000010;
    // ALLOW_V3
    //     Allow version 3 of the OTR protocol to be used.
    const ALLOW_V3 = 0b00000100;
    // REQUIRE_ENCRYPTION
    //     Refuse to send unencrypted messages.
    const REQUIRE_ENCRYPTION = 0b00001000;
    // SEND_WHITESPACE_TAG
    //     Advertise your support of OTR using the whitespace tag.
    const WHITESPACE_TAG = 0b00010000;
    // WHITESPACE_START_AKE
    //     Start the OTR AKE when you receive a whitespace tag.
    const WHITESPACE_START_AKE = 0b00100000;
    // ERROR_START_AKE
    //     Start the OTR AKE when you receive an OTR Error Message.
    const ERROR_START_AKE = 0b01000000;
    }
}

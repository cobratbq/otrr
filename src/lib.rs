use authentication::AKEError;
use bitflags::bitflags;
use crypto::{CryptoError, DSA};
use encoding::TLV;

extern crate aes_ctr;
extern crate base64;
extern crate bitflags;
extern crate hex;
extern crate num_integer;
extern crate num_bigint;
// TODO std::lazy::Lazy is in rust nightly, consider using that once available.
extern crate once_cell;
extern crate regex;
extern crate ring;

mod authentication;
mod crypto;
mod encoding;
mod fragment;
mod instancetag;
mod keymanager;
mod protocol;
mod smp;
mod utils;

pub mod session;

// TODO early implementation assumptions:
// 1. injections of messages into the transport never fails.
// 2. OTR is always enabled. (clarify nuances of this/meaning of this)
// 3. add message fragmentation.
// 4. ...

// TODO initialization-time checking:
//   1. CPU capabilities: usize 32-bit or 64-bit, given checking for appropriate boundaries throughout code. (e.g. encoding.rs serialization)
//      - usize >= u32 for array-indexing in OTR-encoding.
//      - usize >= u32 for array-indexing using KeyID. (protocol.rs)

// TODO add periodic heartbeat message
// TODO support messages in backlog for sending when confidential session established?
// TODO replace once_cell::Lazy with std::lazy::Lazy once the api is in stable.

/// UserMessage represents the resulting Message intended for the messaging client, possibly containing content relevant to display to the user.
#[derive(Debug)]
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
    Confidential(Vec<u8>, Vec<TLV>),
    /// Confidential session ended, transitioned to "finished" state. (Session ended by other party.)
    ConfidentialSessionFinished,
}

/// OTRError is the enum containing the various errors that can occur.
#[derive(Debug)]
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
    // FIXME not sure if this is the way to go...
    /// No acceptable version available in proposed protocol versions.
    NoAcceptableVersion,
    /// Messaging is blocked in OTR protocol "Finished" state to ensure no accidental disclosure occurs.
    ProtocolInFinishedState,
    /// Violation of cryptographic or mathematical requirement for correct/secure operation.
    CryptographicViolation(CryptoError),
    /// (AKE) AuthenticationError indicates that there was an error during AKE.
    AuthenticationError(AKEError),
    /// SMPQuerySecret indicates that an TLV SMP 1 or 1Q is received and the secret needs to be
    /// entered by the user to continue the SMP process.
    // FIXME not sure I'm happy with this, should go somehwere else, maybe UserMessage?
    SMPQuerySecret(&'static str),
    /// SMPIncorrectState identifies that SMP operations are called at a inappropriate time: the
    /// session is not in an encrypted state. SMP has no relevance.
    SMPIncorrectState,
    /// (SMP) SMPInProgress indicates that an SMP exchange is in progress, so to initiate a new SMP,
    /// the previous one needs to be aborted first.
    SMPInProgress,
    // SMP process aborted, most likely by user request. Provided TLV can be sent to other party to signal SMP abort.
    SMPAborted(TLV),
    // SMP process received invalid input for given state of the SMP.
    SMPProtocolViolation,
}

#[derive(PartialEq, Debug)]
pub enum ProtocolStatus {
    Plaintext,
    Encrypted,
    Finished,
}

/// Version contains the various supported OTR protocol versions.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub enum Version {
    None,
    // V1, // will not be supported.
    // V2, // will not be supported.
    V3,
    Unsupported(u16),
}

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

/// TLV_TYPE_0_PADDING is the TLV that can be used to introduce arbitrary-length padding to an
/// encrypted message.
pub const TLV_TYPE_0_PADDING: TLVType = 0;

/// TLV_TYPE_1_DISCONNECT is the TLV that signals a disconnect.
pub const TLV_TYPE_1_DISCONNECT: TLVType = 1;

/// TLV_TYPE is an alias for an u16 value. The values are not restricted. Therefore define the type.
pub type TLVType = u16;

/// Host represents the Host implementation for calling back into the messaging client.
pub trait Host {
    /// Inject a message into the messaging's transport stream. (I.e. protocol-related so not relevant to return to the client.)
    fn inject(&self, message: &[u8]);

    /// Acquire the long-term DSA keypair from the host application.
    fn keypair(&self) -> DSA::Keypair;
}

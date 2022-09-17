use authentication::AKEError;
use bitflags::bitflags;
use crypto::{CryptoError, DSA};
use encoding::TLV;
use instancetag::InstanceTag;

extern crate aes_ctr;
extern crate base64;
extern crate bitflags;
extern crate hex;
extern crate num_bigint;
extern crate num_integer;
extern crate utils;
// TODO std::lazy::Lazy is in rust nightly, consider using that once available.
extern crate once_cell;
extern crate regex;
extern crate ring;

mod authentication;
mod crypto;
mod encoding;
mod fragment;
mod keymanager;
mod protocol;
mod smp;

pub mod instancetag;
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
// TODO check API guidelines (https://rust-lang.github.io/api-guidelines/checklist.html)

/// UserMessage represents the resulting Message intended for the messaging client, possibly
/// containing content relevant to display to the user.
#[derive(Debug)]
pub enum UserMessage {
    /// Nothing received that is relevant to report/transfer back to the messaging client.
    None,
    /// Message for user received over open, plaintext transport.
    Plaintext(Vec<u8>),
    /// While encrypted sessions are present or the policy requires encryption, a message is
    /// received in plaintext. The client must know such that it can issue a warning.
    WarningUnencrypted(Vec<u8>),
    /// OTR error message received.
    // TODO under what circumstances should the error message abort anything in-progress and fall back to unencrypted/finished state?
    Error(Vec<u8>),
    /// Message state reset to "plaintext". (by user action)
    Reset(InstanceTag),
    /// Confidential session started, transitioned to "encrypted" state.
    ConfidentialSessionStarted(InstanceTag),
    /// Message for user received over confidential OTR transport.
    Confidential(InstanceTag, Vec<u8>, Vec<TLV>),
    /// Confidential session ended, transitioned to "finished" state. (Session ended by other
    /// party.)
    ConfidentialSessionFinished(InstanceTag),
    /// SMP process succeeded, signaling the client that authenticity is verified.
    SMPSucceeded(InstanceTag),
    /// SMP process failed, signaling the client that some final concluion was reached.
    // TODO consider carrying the reason for the failure, but may contain technical details, so may be better queried at `smp`.
    SMPFailed(InstanceTag),
}

/// OTRError is the enum containing the various errors that can occur.
// TODO consider implementing `std::fmt::Display` trait for passing on error messages.
#[derive(Debug)]
pub enum OTRError {
    /// Message contained invalid data according to the OTR protocol.
    ProtocolViolation(&'static str),
    /// Message payload is incomplete. The message cannot be reconstructed from the received bytes.
    IncompleteMessage,
    /// Encrypted message is unreadable due to loss of keys and/or wrong protocol state.
    UnreadableMessage(InstanceTag),
    /// An OTR message was received that is intended for a different instance (client).
    MessageForOtherInstance,
    /// Message to be sent to an unknown instance. (FIXME need to check with spec on details)
    UnknownInstance(InstanceTag),
    // FIXME not sure if this is the way to go...
    /// No acceptable version available in proposed protocol versions.
    NoAcceptableVersion,
    UnsupportedVersion(u16),
    /// Messaging is blocked in OTR protocol "Finished" state to ensure no accidental disclosure occurs.
    IncorrectState(&'static str),
    /// Violation of cryptographic or mathematical requirement for correct/secure operation.
    CryptographicViolation(CryptoError),
    /// (AKE) AuthenticationError indicates that there was an error during AKE.
    AuthenticationError(AKEError),
    // TODO it would be sensible to define a SMPError(SMPError) type to encapsulate that whole process, like we did for AKE.
    /// (SMP) SMPInProgress indicates that an SMP exchange is in progress, so to initiate a new SMP,
    /// the previous one needs to be aborted first.
    SMPInProgress,
    /// SMPSuccess indicates successful finishing SMP without a follow-up TLV needing to be sent.
    SMPSuccess(Option<TLV>),
    /// SMP process aborted, most likely by user request. Provided TLV can be sent to other party to
    /// signal SMP abort. The boolean value indicates whether the abort-action needs to be
    /// communicated, that is: true to require sending abort-TLV, false if no further action needed.
    SMPAborted(bool),
    PolicyRestriction(&'static str),
}

#[derive(PartialEq, Debug)]
pub enum ProtocolStatus {
    Plaintext,
    Encrypted,
    Finished,
}

/// Version contains the various supported OTR protocol versions.
// TODO version preference may be hard-coded in places
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
    pub struct Policy: u32 {
    // TODO disabled all ALLOW_Vx flags, because it doesn't make much sense to disable the only version option.
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
    const SEND_WHITESPACE_TAG = 0b00010000;
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
    /// Inject a message into the messaging's transport stream. (I.e. protocol-related so not
    /// relevant to return to the client.)
    fn inject(&self, message: &[u8]);

    /// Acquire the long-term DSA keypair from the host application.
    fn keypair(&self) -> DSA::Keypair;

    /// smp_query_secret triggers a query in the client to ask for the secret answer that is
    /// necessary to continue the SMP.
    /// TODO NOTE: for now considering empty question same as asking for secret without question.
    fn query_smp_secret(&self, question: &[u8]) -> Option<Vec<u8>>;
}

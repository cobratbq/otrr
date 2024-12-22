// SPDX-License-Identifier: LGPL-3.0-only

// NOTES:
// - keeping score (significant OTRv4 spec errors): 1.) use of secret key material after clearing because receiving messages out of expected order.; 2.) need to process message numbers provisionally because these are early steps leading up to message authentication, therefore cannot be trusted; 3.) merging protocol state machine and DAKE state machine provides opening to Denial-of-Service attacks.

// TODO
// - risks/limitations of protocol version 3:
// - does not satisfy recent recommendation for DH moduli of `>= 2048`.
// - DH modulus in use is likely candidate for precomputation ()
// - Sources to check:
// - [WeakDH](<https://weakdh.org/> "Weak Diffie-Hellman and the Logjam Attack")
// - [LogJam](<https://en.wikipedia.org/wiki/Logjam_(computer_security)>)
// - [DHEat Attack](<https://dheatattack.com/> "DoS attack that can be performed by enforcing the Diffie-Hellman key exchange")
// - [RFC 5114](<https://www.rfc-editor.org/rfc/rfc5114.html>)

#![deny(unused_must_use)]
#![warn(clippy::pedantic)]
#![allow(
    dead_code,
    clippy::unnecessary_unwrap,
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::needless_range_loop,
    clippy::for_kv_map
)]

use ake::AKEError;
use bitflags::bitflags;
use crypto::{dsa, ed448, CryptoError};
use encoding::TLV;
use instancetag::InstanceTag;

extern crate log;

mod ake;
mod dake;
mod encoding;
mod fragment;
mod keymanager;
mod messages;
mod protocol;
mod smp;
mod smp4;
mod utils;

// TODO evaluate for each `pub mod` members whether to expose outside of crate
pub mod clientprofile;
pub mod crypto;
pub mod instancetag;
pub mod session;

// TODO initialization-time checking:
//   1. CPU capabilities: usize 32-bit or 64-bit, given checking for appropriate boundaries throughout code. (e.g. encoding.rs serialization)
//      - usize >= u32 for array-indexing in OTR-encoding.
//      - usize >= u32 for array-indexing using KeyID. (protocol.rs)
// TODO can we use top-level std::panic::catch_unwind for catching/diagnosing unexpected failures? (isolate panics within single session/instance)
// TODO `encoding#OTR_USE_INFORMATION_MESSAGE`: make accompanying message changeable, consider length for fragmenting.
// TODO add periodic heartbeat message
// TODO support messages in backlog for sending when confidential session established?
// TODO replace once_cell::Lazy with std::lazy::Lazy once the api is in stable.
// TODO check API guidelines (https://rust-lang.github.io/api-guidelines/checklist.html)
// TODO consider introducing (generally) logging to keep track of the internal process.
// TODO currently two different RNG types in use. (See DSA for OsRng)
// TODO global review of cleaning sensitive memory. (1. can we zeroize BigUint? for SMP, keymanager, etc. There is a cfg(zeroize) for biguint-dig crate, apparently. 2. Review existing uses of Biguint for clearing.)
// TODO review allow/warn/deny settings per file for clippy et al.
// TODO store plaintext message for possible retransmission (various states, see spec)
// TODO was there a requirement that other party's dh key must not be equal to a previous key? If so, would we need to remember more keys?
// TODO review all zeroing, trait drop::Drop
// TODO review need for constant-time handling (e.g. comparisons)
// TODO whitespace-tag is now placed at the beginning of the message. Better location?
// TODO hunt for variables that could be defined `const`.
// TODO consider using something like a NonZeroU16 trait for certain datatypes to enforce correct logic.
// TODO apply BigUint::zeroize for sensitive values
// TODO crypto: at this point, there is no zeroing of BigInt/BigUint values
// REMARK clean up asserts that are clearly only used to evalute/confirm (static) control flow logic. (may impact constant-time expectations)
// REMARK allow defining custom message to be included with the OTR Query-tag.
// REMARK expose TLV 0 for manual padding by client?
// REMARK switch from once_cell::lazy::Lazy to std::lazy::Lazy, once it is in rust nightly.
// REMARK there are two distinct implementations of many cryptography primitives (sha1, signatures) because individual implementations next to `ring`.

/// `UserMessage` represents the resulting Message intended for the messaging client, possibly
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
    Error(Vec<u8>),
    /// Message state reset to "plaintext". (by user action)
    Reset(InstanceTag),
    /// Confidential session started, transitioned to "encrypted" state.
    ConfidentialSessionStarted(InstanceTag),
    /// Message for user received over confidential OTR transport.
    Confidential(InstanceTag, Vec<u8>, Vec<TLV>),
    /// Confidential session ended, transitioned to "finished" state. (Session ended by other
    /// party.)
    ConfidentialSessionFinished(InstanceTag, Vec<u8>),
    /// SMP process succeeded, signaling the client that authenticity is verified.
    SMPSucceeded(InstanceTag),
    /// SMP process failed, signaling the client that some final concluion was reached.
    SMPFailed(InstanceTag),
}

/// `OTRError` is the enum containing the various errors that can occur.
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
    /// Message to be sent to an unknown instance.
    UnknownInstance(InstanceTag),
    /// Unsupported version encountered.
    UnsupportedVersion(u16),
    /// Messaging is blocked in OTR protocol "Finished" state to ensure no accidental disclosure occurs.
    IncorrectState(&'static str),
    /// Violation of cryptographic or mathematical requirement for correct/secure operation.
    CryptographicViolation(CryptoError),
    /// `PolicyRestriction` indicates an error caused by the active policy.
    PolicyRestriction(&'static str),
    /// (AKE) `AuthenticationError` indicates that there was an error during AKE.
    AuthenticationError(AKEError),
    /// `SMPInProgress` indicates that an SMP exchange is in progress, so to initiate a new SMP,
    /// the previous one needs to be aborted first.
    SMPInProgress,
    /// `SMPSuccess` indicates successful finishing SMP without a follow-up TLV needing to be sent.
    SMPSuccess(Option<TLV>),
    /// `SMPFailed` indicates a unsuccessfully completed SMP.
    SMPFailed(Option<TLV>),
    /// `SMPAborted` indicates SMP process was aborted, most likely by user request. Provided TLV
    /// can be sent to other party to signal SMP abort. The boolean value indicates whether the
    /// abort-action needs to be communicated, that is: true to require sending abort-TLV, false if
    /// no further action needed.
    SMPAborted(bool),
    /// `UserError` indicates a user error, with a description provided in the tuple.
    UserError(&'static str),
}

/// `ProtocolStatus` indicates the protocol status: plaintext, encrypted, finished.
/// If matching for exact protocol state, combine with `Version` to include version-matching.
#[derive(PartialEq, Eq, Debug)]
pub enum ProtocolStatus {
    Plaintext,
    Encrypted,
    Finished,
}

const SUPPORTED_VERSIONS: [Version; 2] = [Version::V3, Version::V4];

/// `Version` contains the various supported OTR protocol versions.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Version {
    None,
    // V1 will not be supported.
    // V2 will not be supported.
    V3,
    V4,
    Unsupported(u16),
}

bitflags! {
    /// `Policy` bit-flags can be set to indicate how OTR should respond to certain events related to messaging and the OTR protocol.
    pub struct Policy: u32 {
    // ALLOW_V1
    //     Allow version 1 of the OTR protocol to be used (in general this document will not address OTR protocol version 1; see previous protocol documents for these details).
    //const ALLOW_V1 = 0b00000001;
    // ALLOW_V2
    //     Allow version 2 of the OTR protocol to be used.
    //const ALLOW_V2 = 0b00000010;
    // ALLOW_V3
    //     Allow version 3 of the OTR protocol to be used.
    const ALLOW_V3 = 0b0000_0000_0000_0100;
    // REQUIRE_ENCRYPTION
    //     Refuse to send unencrypted messages.
    const REQUIRE_ENCRYPTION = 0b0000_0000_0000_1000;
    // SEND_WHITESPACE_TAG
    //     Advertise your support of OTR using the whitespace tag.
    const SEND_WHITESPACE_TAG = 0b0000_0000_0001_0000;
    // WHITESPACE_START_AKE
    //     Start the OTR AKE when you receive a whitespace tag.
    const WHITESPACE_START_AKE = 0b0000_0000_0010_0000;
    // ERROR_START_AKE
    //     Start the OTR AKE when you receive an OTR Error Message.
    const ERROR_START_AKE = 0b0000_0000_0100_0000;
    const ALLOW_V4 = 0b0000_0001_0000_0000;
    }
}

/// `TLV_TYPE` is an alias for an u16 value. The values are not restricted. Therefore define the type.
pub type TLVType = u16;

#[allow(clippy::upper_case_acronyms)]
pub type SSID = [u8; 8];

/// Host represents the interface to the host application, for calling back into the messaging
/// client.
// TODO consider what it would take to change the API to allow for e.g. failing `inject` calls, meaning that otrr would, for instance, need to abort and ask client to redo the action at a later time. (Probably not worth the effort.)
pub trait Host {
    /// `message_size` queries the maximum message size accepted by the underlying transport.
    ///
    /// It is expected that smaller message are allowed. The message size will be taken as a strict
    /// upper bound and it is expected that messages up to exactly that number in size are elligible
    /// for transport, while even a single byte more may mean -- in the worst case -- that the full
    /// message is dropped.
    ///
    /// `message_size` is called for every message constructed. If name changes, connection changes,
    /// etc. are determining factors for the maximum message size, then the size only has to be
    /// stable for a single (OTR-encoded) message to be constructed.
    fn message_size(&self) -> usize {
        usize::MAX
    }

    /// Inject a message into the messaging's transport stream. (I.e. protocol-related so not
    /// relevant to return to the client.)
    /// NOTE: `otrr` assumes that injection of the provided message into the transport succeeds.
    fn inject(&self, account: &[u8], message: &[u8]);

    /// Acquire the long-term (legacy) DSA keypair from the host application. The long-term keypair,
    /// that is used for authentication purposes, is requested from the host application. This
    /// allows the host control over which keypair to provide for which account.
    fn keypair(&self) -> Option<&dsa::Keypair>;

    /// keypair_identity is the OTRv4 long-term (identity) keypair.
    fn keypair_identity(&self) -> &ed448::EdDSAKeyPair;

    /// keypair_forging is the OTRv4 forging keypair.
    fn keypair_forging(&self) -> &ed448::EdDSAKeyPair;

    /// `query_smp_secret` triggers a query in the host application (chat client) to ask for the
    /// secret answer that is necessary to continue the SMP.
    fn query_smp_secret(&self, question: &[u8]) -> Option<Vec<u8>>;

    /// `client_profile` retrieves the client profile from the host application. An empty vector
    /// indicates that no client profile exists, therefore one will be generated from internally and
    /// keypairs will be queried from the host to complete a payload. `update_client_profile` is
    /// called with a (renewed) client profile payload that should be stored by the host/chat
    /// application.
    // TODO callers in DAKE will assume a readily-available profile payload is guaranteed. Is this ensured for all cases?
    fn client_profile(&self) -> Vec<u8>;

    /// `update_client_profile` sends the host an encoded client profile payload to be stored for
    /// use and restoring.
    fn update_client_profile(&self, encoded_payload: Vec<u8>);
}

extern crate base64;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate hex;
extern crate num_bigint;

mod decoder;
mod fragment;
mod session;
mod protocol;
mod authentication;

pub enum Message {
    None,
    Plain(Vec<u8>),
    Confidential(Vec<u8>),
    Error(Vec<u8>),
}

/// OTRError is the enum containing the various errors that can occur.
pub enum OTRError {
    /// Message contained invalid data according to the OTR protocol.
    ProtocolViolation(&'static str),
    IncompleteMessage,
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

// TODO: introduce fragmenter.
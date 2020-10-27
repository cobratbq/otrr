extern crate base64;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate hex;

mod fragment;
mod message;
mod session;
mod wire;

/// OTRError is the enum containing the various errors that can occur.
pub enum OTRError {
    InvalidProtocolData(&'static str),
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

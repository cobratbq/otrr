extern crate base64;
extern crate regex;
#[macro_use]
extern crate lazy_static;

mod message;

#[derive(PartialEq)]
pub enum Version {
    Unsupported(u16),
    // V1, // most likely never going to be needed.
    // V2, // will not be supported.
    V3,
}

pub type InstanceTag = u32;

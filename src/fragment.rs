use regex::bytes::Regex;
use std::{collections::HashMap, io::{Error, ErrorKind}};
use crate::InstanceTag;

const OTR_FRAGMENT_V2_PREFIX: &[u8] = b"?OTR,";
const OTR_FRAGMENT_V3_PREFIX: &[u8] = b"?OTR|";

lazy_static! {
    static ref FRAGMENT_PATTERN: Regex = Regex::new(r"\?OTR\|([0-9a-fA-F]{1,8})\|([0-9a-fA-F]{1,8}),(\d{1,5}),(\d{1,5}),([\?A-Za-z0-9\.]+),").unwrap();
}

fn parse_fragment(content: &[u8]) -> Result<Fragment, Error> {
    let fragment_caps = FRAGMENT_PATTERN.captures(content);
    if fragment_caps.is_none() {
        return Err(Error::from(ErrorKind::InvalidInput))
    }
    let captures = fragment_caps.unwrap();
    // FIXME: can these arrays be smaller than 4 bytes?
    let senderBytes = hex::decode(captures.get(1).unwrap().as_bytes()).unwrap();
    let receiverBytes = hex::decode(captures.get(2).unwrap().as_bytes()).unwrap();
    return Ok(Fragment{
        sender: u32::from_be_bytes([senderBytes[0], senderBytes[1], senderBytes[2], senderBytes[3]]),
        receiver: u32::from_be_bytes([receiverBytes[0], receiverBytes[1], receiverBytes[2], receiverBytes[3]]),
        part: u16::from_str_radix(std::str::from_utf8(captures.get(3).unwrap().as_bytes()).unwrap(), 10).unwrap(),
        total: u16::from_str_radix(std::str::from_utf8(captures.get(4).unwrap().as_bytes()).unwrap(), 10).unwrap(),
        payload: Vec::from(captures.get(5).unwrap().as_bytes()),
    })
}

pub struct Fragment {
    sender: InstanceTag,
    receiver: InstanceTag,
    part: u16,
    total: u16,
    payload: Vec<u8>,
}

struct Assembler {
    assemblies: HashMap<InstanceTag,Assembly>,
}

impl Assembler {

    pub fn assemble(fragment: Fragment) {

    }
}

struct Assembly {
    current: u8,
    total: u8,
    content: Vec<u8>,
}

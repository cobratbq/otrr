use regex::bytes::Regex;
use crate::InstanceTag;

lazy_static! {
    static ref FRAGMENT_PATTERN: Regex = Regex::new(r"\?OTR\|([0-9a-fA-F]{1,8})\|([0-9a-fA-F]{1,8}),(\d{1,5}),(\d{1,5}),([\?A-Za-z0-9:\.]+),").unwrap();
}

pub fn parse_fragment(content: &[u8]) -> Fragment {
    let fragment_caps = FRAGMENT_PATTERN.captures(content);
    if fragment_caps.is_none() {
        panic!("Input is unsupported fragment format or no fragment at all.");
    }
    let captures = fragment_caps.unwrap();
    // FIXME: can these arrays be smaller than 4 bytes?
    let sender_bytes = hex::decode(captures.get(1).unwrap().as_bytes()).unwrap();
    let receiver_bytes = hex::decode(captures.get(2).unwrap().as_bytes()).unwrap();
    return Fragment{
        sender: u32::from_be_bytes([sender_bytes[0], sender_bytes[1], sender_bytes[2], sender_bytes[3]]),
        receiver: u32::from_be_bytes([receiver_bytes[0], receiver_bytes[1], receiver_bytes[2], receiver_bytes[3]]),
        part: u16::from_str_radix(std::str::from_utf8(captures.get(3).unwrap().as_bytes()).unwrap(), 10).unwrap(),
        total: u16::from_str_radix(std::str::from_utf8(captures.get(4).unwrap().as_bytes()).unwrap(), 10).unwrap(),
        payload: Vec::from(captures.get(5).unwrap().as_bytes()),
    }
}

pub struct Fragment {
    pub sender: InstanceTag,
    pub receiver: InstanceTag,
    pub part: u16,
    pub total: u16,
    pub payload: Vec<u8>,
}

pub enum FragmentError {
    IllegalFragment,
}

pub fn verify(fragment: &Fragment) -> Result<(), FragmentError> {
    if fragment.total == 0 || fragment.part == 0 || fragment.part > fragment.total {
        return Err(FragmentError::IllegalFragment);
    }
    Ok(())
}

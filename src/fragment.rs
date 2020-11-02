use regex::bytes::Regex;

use crate::InstanceTag;

const OTR_FRAGMENT_V2_PREFIX: &[u8] = b"?OTR,";
const OTR_FRAGMENT_V3_PREFIX: &[u8] = b"?OTR|";
const OTR_FRAGMENT_SUFFIX: &[u8] = b",";

const INDEX_FIRST_FRAGMENT: u16 = 1;

lazy_static! {
    static ref FRAGMENT_PATTERN: Regex = Regex::new(
        r"\?OTR\|([0-9a-fA-F]{1,8})\|([0-9a-fA-F]{1,8}),(\d{1,5}),(\d{1,5}),([\?A-Za-z0-9:\.]+),"
    )
    .unwrap();
}

pub fn is_fragment(content: &[u8]) -> bool {
    return (content.starts_with(OTR_FRAGMENT_V2_PREFIX)
        || content.starts_with(OTR_FRAGMENT_V3_PREFIX))
        && content.ends_with(OTR_FRAGMENT_SUFFIX);
}

pub fn parse(content: &[u8]) -> Fragment {
    let fragment_caps = FRAGMENT_PATTERN.captures(content);
    if fragment_caps.is_none() {
        // FIXME this currently includes OTRv2 fragments, which we will not support but should handle gracefully.
        panic!("Input is unsupported fragment format or no fragment at all.");
    }
    let captures = fragment_caps.unwrap();
    // FIXME: can these arrays be smaller than 4 bytes?
    let sender_bytes = hex::decode(captures.get(1).unwrap().as_bytes()).unwrap();
    let receiver_bytes = hex::decode(captures.get(2).unwrap().as_bytes()).unwrap();
    return Fragment {
        sender: u32::from_be_bytes([
            sender_bytes[0],
            sender_bytes[1],
            sender_bytes[2],
            sender_bytes[3],
        ]),
        receiver: u32::from_be_bytes([
            receiver_bytes[0],
            receiver_bytes[1],
            receiver_bytes[2],
            receiver_bytes[3],
        ]),
        part: u16::from_str_radix(
            std::str::from_utf8(captures.get(3).unwrap().as_bytes()).unwrap(),
            10,
        )
        .unwrap(),
        total: u16::from_str_radix(
            std::str::from_utf8(captures.get(4).unwrap().as_bytes()).unwrap(),
            10,
        )
        .unwrap(),
        payload: Vec::from(captures.get(5).unwrap().as_bytes()),
    };
}

pub fn verify(fragment: &Fragment) -> Result<(), FragmentError> {
    return if fragment.total == 0
        || fragment.part == 0
        || fragment.part > fragment.total
        || fragment.payload.is_empty()
    {
        Err(FragmentError::IllegalFragment)
    } else {
        Ok(())
    };
}

pub struct Fragment {
    pub sender: InstanceTag,
    pub receiver: InstanceTag,
    part: u16,
    total: u16,
    payload: Vec<u8>,
}

pub enum FragmentError {
    IllegalFragment,
}

pub fn new_assembler() -> Assembler {
    return Assembler {
        total: 0,
        last: 0,
        content: Vec::new(),
    };
}

pub struct Assembler {
    total: u16,
    last: u16,
    content: Vec<u8>,
}

impl Assembler {
    pub fn assemble(&mut self, fragment: Fragment) -> Result<Vec<u8>, AssemblingError> {
        verify(&fragment).or(Err(AssemblingError::IllegalFragment))?;
        if fragment.part == INDEX_FIRST_FRAGMENT {
            self.total = fragment.total;
            self.last = 1;
            self.content.clone_from(&fragment.payload);
        } else if fragment.total == self.total && fragment.part == self.last + 1 {
            self.last = fragment.part;
            self.content.extend_from_slice(&fragment.payload);
        } else {
            self.total = 0;
            self.last = 0;
            self.content.clear();
            return Err(AssemblingError::UnexpectedFragment);
        }
        return if self.last == self.total {
            Ok(Vec::from(self.content.as_slice()))
        } else {
            Err(AssemblingError::IncompleteResult)
        };
    }
}

/// Errors that may occur while assembling message fragments into a full OTR-encoded message.
pub enum AssemblingError {
    /// Illegal fragment received. Fragment contains bad data and cannot be processed.
    IllegalFragment,
    /// Incomplete result. Waiting for more fragments to arrive.
    IncompleteResult,
    /// Unexpected fragment received. Resetting assembler.
    UnexpectedFragment,
}

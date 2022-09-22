use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::{
    encoding::OTREncodable,
    instancetag::{verify_instance_tag, InstanceTag},
    utils,
};

const OTR_FRAGMENT_V2_PREFIX: &[u8] = b"?OTR,";
const OTR_FRAGMENT_V3_PREFIX: &[u8] = b"?OTR|";
const OTR_FRAGMENT_SUFFIX: &[u8] = b",";

const INDEX_FIRST_FRAGMENT: u16 = 1;

// TODO for now assuming that instance tag is always fully represented, i.e. all 32 bits = 8 hexadecimals.
static FRAGMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\?OTR\|([0-9a-fA-F]{8,8})\|([0-9a-fA-F]{8,8}),(\d{1,5}),(\d{1,5}),([\?A-Za-z0-9:\.]+),",
    )
    .unwrap()
});

// TODO match matches OTRv2 prefix but parsing does not handling OTRv2 fragments, so somewhere we need to handle.
pub fn match_fragment(content: &[u8]) -> bool {
    (content.starts_with(OTR_FRAGMENT_V2_PREFIX) || content.starts_with(OTR_FRAGMENT_V3_PREFIX))
        && content.ends_with(OTR_FRAGMENT_SUFFIX)
}

pub fn parse(content: &[u8]) -> Result<Fragment, FragmentError> {
    let fragment_caps = FRAGMENT_PATTERN.captures(content);
    if fragment_caps.is_none() {
        // TODO this currently includes OTRv2 fragments, which we will not support but maybe should handle gracefully.
        return Err(FragmentError::UnsupportedFormat);
    }
    let captures = fragment_caps.unwrap();
    let sender_bytes = hex::decode(captures.get(1).unwrap().as_bytes()).unwrap();
    let receiver_bytes = hex::decode(captures.get(2).unwrap().as_bytes()).unwrap();
    // NOTE that in the conversion to bytes we assume that a full-size instance tag is present,
    // therefore decodes into 4 bytes of data.
    return Ok(Fragment {
        sender: verify_instance_tag(utils::std::u32::from_4byte_be(&sender_bytes))
            .or(Err(FragmentError::InvalidData))?,
        receiver: verify_instance_tag(utils::std::u32::from_4byte_be(&receiver_bytes))
            .or(Err(FragmentError::InvalidData))?,
        part: std::str::from_utf8(captures.get(3).unwrap().as_bytes())
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        total: std::str::from_utf8(captures.get(4).unwrap().as_bytes())
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        payload: Vec::from(captures.get(5).unwrap().as_bytes()),
    });
}

pub fn verify(fragment: &Fragment) -> Result<(), FragmentError> {
    if fragment.total == 0
        || fragment.part == 0
        || fragment.part > fragment.total
        || fragment.payload.is_empty()
    {
        Err(FragmentError::InvalidData)
    } else {
        Ok(())
    }
}

pub struct Fragment {
    pub sender: InstanceTag,
    pub receiver: InstanceTag,
    part: u16,
    total: u16,
    payload: Vec<u8>,
}

impl OTREncodable for Fragment {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        encoder
            .write(OTR_FRAGMENT_V3_PREFIX)
            // NOTE not very explicit in the specification, but examples seem to indicate that
            // `part` and `total` should be padded with prefix zeroes.
            .write(
                format!(
                    "{:08x}|{:08x},{:05},{:05},",
                    &self.sender, &self.receiver, &self.part, &self.total
                )
                .as_bytes(),
            )
            .write(&self.payload)
            .write(OTR_FRAGMENT_SUFFIX);
    }
}

pub struct Assembler {
    total: u16,
    last: u16,
    content: Vec<u8>,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            total: 0,
            last: 0,
            content: Vec::new(),
        }
    }

    pub fn assemble(&mut self, fragment: &Fragment) -> Result<Vec<u8>, FragmentError> {
        verify(fragment)?;
        if fragment.part == INDEX_FIRST_FRAGMENT {
            // First fragment encountered.
            self.total = fragment.total;
            self.last = 1;
            self.content.clone_from(&fragment.payload);
        } else if fragment.total == self.total && fragment.part == self.last + 1 {
            // Next fragment encountered.
            self.last = fragment.part;
            self.content.extend(&fragment.payload);
        } else {
            // Unexpected fragment encountered. Resetting state.
            self.reset();
            return Err(FragmentError::UnexpectedFragment);
        }
        if self.last == self.total {
            Ok(std::mem::take(&mut self.content))
        } else {
            Err(FragmentError::IncompleteResult)
        }
    }

    pub fn reset(&mut self) {
        self.total = 0;
        self.last = 0;
        self.content.clear();
    }
}

#[derive(std::fmt::Debug)]
pub enum FragmentError {
    /// Fragment has invalid format and cannot be parsed. This is most likely an OTRv2 fragment,
    /// which does not include sender and receiver tags. This protocol version is not supported.
    UnsupportedFormat,
    /// Fragment contains invalid part information that would result in an invalid partitioning of
    /// the content.
    InvalidData,
    /// Incomplete result. Waiting for more fragments to arrive.
    IncompleteResult,
    /// Unexpected fragment received. Resetting assembler.
    UnexpectedFragment,
}

#[cfg(test)]
mod tests {
    use super::{match_fragment, parse, verify, Fragment};

    #[test]
    fn test_is_fragment_empty_string() {
        assert!(!match_fragment(b""));
    }

    #[test]
    fn test_is_fragment_arbitrary_string() {
        assert!(!match_fragment(b"fda6s7d8g6sa78f76ewaf687e"));
    }

    #[test]
    fn test_is_fragment_otrv2_fragment() {
        assert!(match_fragment(b"?OTR,"));
    }

    #[test]
    fn test_is_fragment_otrv3_fragment_incomplete() {
        assert!(!match_fragment(b"?OTR|"));
    }

    #[test]
    fn test_is_fragment_otrv3_fragment() {
        assert!(match_fragment(b"?OTR|,"));
    }

    #[test]
    fn test_is_fragment_otr_partly_arbitrary() {
        assert!(!match_fragment(b"?OTRsomethingrandom,"));
    }

    #[test]
    fn test_is_fragment_otr_encoded() {
        assert!(!match_fragment(b"?OTR:."));
    }

    #[test]
    fn test_is_fragment_otr_encoded_mixed() {
        assert!(!match_fragment(b"?OTR:,"));
    }

    #[test]
    fn test_verify_fragment_zero() {
        let f = Fragment {
            sender: 0,
            receiver: 0,
            total: 0,
            part: 0,
            payload: Vec::new(),
        };
        assert!(verify(&f).is_err());
    }

    #[test]
    fn test_verify_fragment_correct() {
        let f = Fragment {
            sender: 256,
            receiver: 256,
            total: 1,
            part: 1,
            payload: Vec::from("Hello"),
        };
        assert!(verify(&f).is_ok());
    }

    #[test]
    fn test_verify_fragment_zero_part() {
        let f = Fragment {
            sender: 256,
            receiver: 256,
            total: 1,
            part: 0,
            payload: Vec::from("Hello"),
        };
        assert!(verify(&f).is_err());
    }

    #[test]
    fn test_verify_fragment_zero_total() {
        let f = Fragment {
            sender: 256,
            receiver: 256,
            total: 0,
            part: 1,
            payload: Vec::from("Hello"),
        };
        assert!(verify(&f).is_err());
    }

    #[test]
    fn test_verify_fragment_empty_payload() {
        let f = Fragment {
            sender: 256,
            receiver: 256,
            total: 1,
            part: 1,
            payload: Vec::new(),
        };
        assert!(verify(&f).is_err());
    }

    #[test]
    fn test_verify_fragment_part_larger_total() {
        let f = Fragment {
            sender: 256,
            receiver: 256,
            total: 1,
            part: 2,
            payload: Vec::from("Hello"),
        };
        assert!(verify(&f).is_err());
    }

    #[test]
    fn test_verify_fragment_last_part() {
        let f = Fragment {
            sender: 256,
            receiver: 256,
            total: 11,
            part: 11,
            payload: Vec::from("Hello"),
        };
        assert!(verify(&f).is_ok());
    }

    #[test]
    fn test_parse_fragment_empty() {
        let result = parse(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fragment_arbitrary() {
        let result = parse(b"fds7ag56sdaf67sd8a5f6se7895f6asd");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fragment() {
        let f = parse(b"?OTR|1f2e3d4c|1a2b3c4d,1,2,?OTR:encoded.,").unwrap();
        assert_eq!(0x1f2e_3d4c_u32, f.sender);
        assert_eq!(0x1a2b_3c4d_u32, f.receiver);
        assert_eq!(1u16, f.part);
        assert_eq!(2u16, f.total);
        assert_eq!(b"?OTR:encoded.", f.payload.as_slice());
    }
}

// SPDX-License-Identifier: LGPL-3.0-only

use core::fmt::Debug;
use std::{collections::HashMap, sync::LazyLock};

use regex::bytes::Regex;

use crate::{
    encoding::OTREncodable,
    instancetag::{self, InstanceTag},
    utils, Version,
};

const OTR_FRAGMENT_V2_PREFIX: &[u8] = b"?OTR,";
const OTR_FRAGMENT_V3_PREFIX: &[u8] = b"?OTR|";
const OTR_FRAGMENT_SUFFIX: &[u8] = b",";

const INDEX_FIRST_FRAGMENT: u16 = 1;

/// OTR: "Start with the OTR message as you would normally transmit it. Break it up into
/// sufficiently small pieces. Let the number of pieces be (`n`), and the pieces be `piece[1]`,
/// `piece[2]`,`...`,`piece[n]`. Transmit (`n`) OTR version 3 fragmented messages with the following
/// (printf-like) structure (as `k` runs from `1` to `n` inclusive):
///
/// > `"?OTR|%x|%x,%hu,%hu,%s," , sender_instance, receiver_instance, k , n , piece[k]`
///
/// Note that `k` and `n` are unsigned short ints (`2` bytes), and each has a maximum value of
/// `65535`. Also, each `piece[k]` must be non-empty. The instance tags (if applicable) and the `k`
/// and `n` values may have leading zeroes.
static FRAGMENT_V3_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\?OTR\|([0-9a-fA-F]{1,8})\|([0-9a-fA-F]{1,8}),(\d{1,5}),(\d{1,5}),([A-Za-z0-9\+/=\?:\.]+),",
    )
    .unwrap()
});

/// The OTRv4 fragment format is like OTR3 but contains a message identifier before the sender and
/// receiver instance tags. This allows distinguishing fragments from multiple messages in out-of-
/// order delivery.
static FRAGMENT_V4_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\?OTR\|([0-9a-fA-F]{8})\|([0-9a-fA-F]{1,8})\|([0-9a-fA-F]{1,8}),(\d{1,5}),(\d{1,5}),([A-Za-z0-9\+/=\?:\.]+),",
    )
    .unwrap()
});

/// `match_fragment` recognizes both `OTRv2` an`OTRv3` fragment patterns. This allows for a more
/// graceful control flow. `OTRv2` fragments are not processed though.
pub fn match_fragment(content: &[u8]) -> bool {
    (content.starts_with(OTR_FRAGMENT_V2_PREFIX) || content.starts_with(OTR_FRAGMENT_V3_PREFIX))
        && content.ends_with(OTR_FRAGMENT_SUFFIX)
}

/// `parse` parses fragments. `OTRv3` and `OTRv4` fragment patterns are supported. `OTRv2` fragments
/// will not match, therefore result in a `None` result.
pub fn parse(content: &[u8]) -> Option<Fragment> {
    let version: Version;
    let identifier: [u8; 4];
    let sender_bytes: Vec<u8>;
    let receiver_bytes: Vec<u8>;
    let part: u16;
    let total: u16;
    let payload: Vec<u8>;
    if let Some(captures) = (*FRAGMENT_V4_PATTERN).captures(content) {
        version = Version::V4;
        identifier = hex::decode(as_sized_hexarray::<8>(captures.get(1).unwrap().as_bytes()))
            .unwrap()
            .try_into()
            .unwrap();
        sender_bytes =
            hex::decode(as_sized_hexarray::<8>(captures.get(2).unwrap().as_bytes())).unwrap();
        receiver_bytes =
            hex::decode(as_sized_hexarray::<8>(captures.get(3).unwrap().as_bytes())).unwrap();
        part = core::str::from_utf8(captures.get(4).unwrap().as_bytes())
            .unwrap()
            .parse::<u16>()
            .unwrap();
        total = core::str::from_utf8(captures.get(5).unwrap().as_bytes())
            .unwrap()
            .parse::<u16>()
            .unwrap();
        payload = Vec::from(captures.get(6).unwrap().as_bytes());
    } else if let Some(captures) = (*FRAGMENT_V3_PATTERN).captures(content) {
        version = Version::V3;
        identifier = [0u8; 4];
        sender_bytes =
            hex::decode(as_sized_hexarray::<8>(captures.get(1).unwrap().as_bytes())).unwrap();
        receiver_bytes =
            hex::decode(as_sized_hexarray::<8>(captures.get(2).unwrap().as_bytes())).unwrap();
        part = core::str::from_utf8(captures.get(3).unwrap().as_bytes())
            .unwrap()
            .parse::<u16>()
            .unwrap();
        total = core::str::from_utf8(captures.get(4).unwrap().as_bytes())
            .unwrap()
            .parse::<u16>()
            .unwrap();
        payload = Vec::from(captures.get(5).unwrap().as_bytes());
    } else {
        return None;
    }
    // Note that in the conversion to bytes we assume that a full-size instance tag is present,
    // therefore decodes into 4 bytes of data.
    Some(Fragment {
        version,
        identifier,
        sender: instancetag::verify(utils::u32::from_4byte_be(&sender_bytes)).ok()?,
        receiver: instancetag::verify(utils::u32::from_4byte_be(&receiver_bytes)).ok()?,
        part,
        total,
        payload,
    })
}

fn as_sized_hexarray<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut result = [b'0'; N];
    result[N - data.len()..].copy_from_slice(data);
    result
}

// TODO currently applying max-fragment-size to all fragments, including protocol 3. This is not according to OTR3 spec, but does prevent injecting extreme, malicious fragments.
pub fn verify(fragment: &Fragment) -> Result<(), FragmentError> {
    if (fragment.version == Version::V3 && fragment.identifier != [0u8; 4])
        || fragment.total == 0
        || fragment.part == 0
        || fragment.part > fragment.total
        || fragment.payload.is_empty()
    {
        Err(FragmentError::InvalidData)
    } else if fragment.payload.len() > MAX_FRAGMENT_SIZE {
        log::info!(
            "Dropping fragment for excessive size (max {:}, safety/stability): {:}",
            MAX_FRAGMENT_SIZE,
            fragment.payload.len()
        );
        Err(FragmentError::InvalidData)
    } else {
        Ok(())
    }
}

/// `fragment` partitions given content into fragments of a specified maximum size.
///
/// To fragment content, a maximum fragment size must be specified. The fragmentation overhead is
/// part of this maximum size. What is left will be used for partial (fragmented) content. The
/// function expects to be called when applicable, and panics otherwise.
///
/// # Panics
///
/// Panics if illegal user input is provided.
#[allow(clippy::cast_possible_truncation)]
pub fn fragment(
    max_size: usize,
    version: &Version,
    sender: InstanceTag,
    receiver: InstanceTag,
    content: &[u8],
) -> Vec<Fragment> {
    const OTRV3_HEADER_SIZE: usize = 36;
    const OTRV4_HEADER_SIZE: usize = 45;
    // TODO need to handle impossible fragmentation if max_size < OTRV#_HEADER_SIZE
    assert!(
        *version != Version::V3 || max_size > OTRV3_HEADER_SIZE,
        "BUG: Maximum allowed fragment size must be larger than the overhead necessary for fragmentation."
    );
    assert!(
        *version != Version::V4 || max_size > OTRV4_HEADER_SIZE,
        "BUG: Maximum allowed fragment size must be larger than the overhead necessary for fragmentation."
    );
    assert!(
        content.len() > max_size,
        "Content must be larger than fragment size, otherwise content can be sent as-is."
    );
    let (fragment_size, identifier) = match version {
        Version::V3 => (max_size - OTRV3_HEADER_SIZE, [0u8; 4]),
        Version::V4 => (
            max_size - OTRV4_HEADER_SIZE,
            utils::random::secure_bytes::<4>(),
        ),
        _ => panic!("BUG: illegal version specified"),
    };
    let num_fragments = u16::try_from(
        content.len() / fragment_size + utils::usize::signum(content.len() % fragment_size),
    )
    .unwrap();
    let mut fragments = Vec::<Fragment>::new();
    for pos in (0..content.len()).step_by(fragment_size) {
        let payload = &content[pos..usize::min(pos + fragment_size, content.len())];
        fragments.push(Fragment {
            version: version.clone(),
            identifier,
            sender,
            receiver,
            part: u16::try_from(fragments.len()).unwrap() + 1,
            total: num_fragments,
            payload: Vec::from(payload),
        });
    }
    fragments
}

pub struct Fragment {
    pub version: Version,
    identifier: [u8; 4],
    pub sender: InstanceTag,
    pub receiver: InstanceTag,
    part: u16,
    total: u16,
    payload: Vec<u8>,
}

impl Debug for Fragment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fragment")
            .field("version", &self.version)
            .field("identifier", &self.identifier)
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("part", &self.part)
            .field("total", &self.total)
            .field("payload", &core::str::from_utf8(&self.payload).unwrap())
            .finish()
    }
}

impl OTREncodable for Fragment {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        log::trace!("Fragment to encode: {:?}", &self);
        // ensure that the fragments we send are valid. (used to capture internal logic errors)
        assert_ne!(self.version, Version::None);
        assert!(!matches!(self.version, Version::Unsupported(_)));
        assert!(instancetag::verify(self.sender).is_ok());
        assert_ne!(self.sender, 0);
        assert!(instancetag::verify(self.receiver).is_ok());
        assert_ne!(self.part, 0);
        assert_ne!(self.total, 0);
        assert!(self.part <= self.total);
        assert!(!self.payload.is_empty());
        encoder.write(OTR_FRAGMENT_V3_PREFIX);
        if self.version > Version::V3 {
            encoder.write(
                format!(
                    "{:02x}{:02x}{:02x}{:02x}|",
                    &self.identifier[0],
                    &self.identifier[1],
                    &self.identifier[2],
                    &self.identifier[3]
                )
                .as_bytes(),
            );
        }
        encoder
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
    inorder: InOrderAssembler,
    unordered: UnorderedAssembler,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            inorder: InOrderAssembler::new(),
            unordered: UnorderedAssembler::new(),
        }
    }

    pub fn assemble(&mut self, fragment: &Fragment) -> Result<Vec<u8>, FragmentError> {
        match fragment.version {
            Version::V3 => self.inorder.assemble(fragment),
            Version::V4 => self.unordered.assemble(fragment),
            Version::None | Version::Unsupported(_) => {
                panic!("BUG: unexpected version for fragment")
            }
        }
    }

    pub fn cleanup(&mut self, version: &Version) {
        match version {
            Version::V3 => self.inorder.reset(),
            Version::V4 => self.unordered.cleanup(),
            Version::None | Version::Unsupported(_) => panic!("BUG: bad use of assembler reset"),
        }
    }
}

struct InOrderAssembler {
    total: u16,
    last: u16,
    content: Vec<u8>,
}

impl InOrderAssembler {
    fn new() -> Self {
        Self {
            total: 0,
            last: 0,
            content: Vec::new(),
        }
    }

    fn assemble(&mut self, fragment: &Fragment) -> Result<Vec<u8>, FragmentError> {
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
            Ok(core::mem::take(&mut self.content))
        } else {
            Err(FragmentError::IncompleteResult)
        }
    }

    fn reset(&mut self) {
        self.total = 0;
        self.last = 0;
        self.content.clear();
    }
}

struct Assembly {
    tick: u32,
    parts: Vec<Vec<u8>>,
}

struct UnorderedAssembler {
    tick: u32,
    fragments: HashMap<[u8; 4], Assembly>,
}

const MAX_MESSAGES: usize = 100;
const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;
const MAX_FRAGMENT_SIZE: usize = 250 * 1024;
const MAX_MEMORY_USE: usize = 100 * 1024 * 1024;

// TODO memory usage may explode if fragments are being assembled that
impl UnorderedAssembler {
    fn new() -> Self {
        Self {
            tick: 0,
            fragments: HashMap::new(),
        }
    }

    fn cleanup(&mut self) {
        // FIXME implement reset/cleanup for OTRv4 assembler
        todo!("TODO: implement reset for OTRv4 assembler")
    }

    fn assemble(&mut self, fragment: &Fragment) -> Result<Vec<u8>, FragmentError> {
        verify(fragment)?;
        // Make room for `fragment` belonging to a new message.
        while !self.fragments.contains_key(&fragment.identifier)
            && self.fragments.len() >= MAX_MESSAGES
        {
            let eldest = *self
                .fragments
                .iter()
                .reduce(|acc, e| if acc.1.tick < e.1.tick { acc } else { e })
                .unwrap()
                .0;
            self.fragments.remove(&eldest);
        }
        assert!(self.fragments.len() <= MAX_MESSAGES);
        let store = self
            .fragments
            .entry(fragment.identifier)
            .or_insert(Assembly {
                tick: 0,
                parts: vec![Vec::new(); fragment.total as usize],
            });
        // Increment tick every time, even if contributing to existing reassembly, but does not
        // really matter. Only monotonic increase is necessary. (We only care about the lowest
        // value, relatively, to determine which fragment-assembly-effort to drop.)
        store.tick = self.tick;
        self.tick += 1;
        if store.parts.capacity() != fragment.total as usize {
            return Err(FragmentError::InvalidData);
        }
        let idx = fragment.part as usize - 1;
        if !store.parts[idx].is_empty() {
            // TODO handle duplicate fragment differently?
            log::debug!("Duplicate fragment encountered: fragment already present in store.");
            return Err(FragmentError::UnexpectedFragment);
        }
        store.parts[idx].clone_from(&fragment.payload);
        if store.parts.iter().fold(0, |acc, f| acc + f.len()) > MAX_MESSAGE_SIZE
            && store.parts.iter().any(std::vec::Vec::is_empty)
        {
            // Dropping fragments of message that is still incomplete but exceeding allowed maximum
            // message-size.
            assert!(self.fragments.remove(&fragment.identifier).is_some());
            log::info!("Dropping fragments for incomplete message with ID {:?} as they already exceed maximum message-size. (max {:}, safety/stability)",
                fragment.identifier, MAX_MESSAGE_SIZE);
            return Err(FragmentError::IncompleteResult);
        }
        if store.parts.iter().any(std::vec::Vec::is_empty) {
            return Err(FragmentError::IncompleteResult);
        }
        let mut payload: Vec<u8> =
            Vec::with_capacity(store.parts.iter().fold(0, |a, f| a + f.len()));
        for f in &store.parts {
            payload.extend(f);
        }
        let removed = self.fragments.remove(&fragment.identifier);
        debug_assert!(removed.is_some());
        Ok(payload)
    }
}

#[derive(Debug)]
pub enum FragmentError {
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
    use core::cmp::Ordering;
    use std::collections::HashMap;

    use crate::{encoding::OTREncoder, fragment::parse, utils, Version};

    use super::{fragment, match_fragment, verify, Fragment, UnorderedAssembler, MAX_MESSAGES};

    #[test]
    fn test_match_fragment() {
        assert!(!match_fragment(b""));
        assert!(!match_fragment(b"fda6s7d8g6sa78f76ewaf687e"));
        assert!(match_fragment(b"?OTR,"));
        assert!(!match_fragment(b"?OTR|"));
        assert!(match_fragment(b"?OTR|,"));
        assert!(!match_fragment(b"?OTRsomethingrandom,"));
        assert!(!match_fragment(b"?OTR:."));
        assert!(!match_fragment(b"?OTR:,"));
    }

    #[test]
    fn test_verify_fragments() {
        assert!(verify(&Fragment {
            version: Version::V3,
            identifier: [0u8; 4],
            sender: 256,
            receiver: 256,
            total: 1,
            part: 1,
            payload: Vec::from("Hello"),
        })
        .is_ok());
        assert!(verify(&Fragment {
            version: Version::V3,
            identifier: [0u8; 4],
            sender: 256,
            receiver: 256,
            total: 1,
            part: 0,
            payload: Vec::from("Hello"),
        })
        .is_err());
        assert!(verify(&Fragment {
            version: Version::V3,
            identifier: [0u8; 4],
            sender: 256,
            receiver: 256,
            total: 0,
            part: 1,
            payload: Vec::from("Hello"),
        })
        .is_err());
        assert!(verify(&Fragment {
            version: Version::V3,
            identifier: [0u8; 4],
            sender: 256,
            receiver: 256,
            total: 1,
            part: 1,
            payload: Vec::new(),
        })
        .is_err());
        assert!(verify(&Fragment {
            version: Version::V3,
            identifier: [0u8; 4],
            sender: 256,
            receiver: 256,
            total: 1,
            part: 2,
            payload: Vec::from("Hello"),
        })
        .is_err());
        assert!(verify(&Fragment {
            version: Version::V3,
            identifier: [0u8; 4],
            sender: 256,
            receiver: 256,
            total: 11,
            part: 11,
            payload: Vec::from("Hello"),
        })
        .is_ok());
    }

    #[test]
    fn test_parse_fragment_empty() {
        let result = parse(b"");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_fragment_arbitrary() {
        let result = parse(b"fds7ag56sdaf67sd8a5f6se7895f6asd");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_fragment() {
        let f = parse(b"?OTR|1f2e3d4c|1a2b3c4d,1,2,?OTR:encoded.,").unwrap();
        assert_eq!(Version::V3, f.version);
        assert_eq!([0u8; 4], f.identifier);
        assert_eq!(0x1f2e_3d4c_u32, f.sender);
        assert_eq!(0x1a2b_3c4d_u32, f.receiver);
        assert_eq!(1u16, f.part);
        assert_eq!(2u16, f.total);
        assert_eq!(b"?OTR:encoded.", f.payload.as_slice());
    }

    #[test]
    fn test_parse_fragment_otrv4() {
        let f = parse(b"?OTR|ffaa6600|1f2e3d4c|1a2b3c4d,1,2,?OTR:encoded.,").unwrap();
        assert_eq!(Version::V4, f.version);
        assert_eq!([0xff, 0xaa, 0x66, 0x00], f.identifier);
        assert_eq!(0x1f2e_3d4c_u32, f.sender);
        assert_eq!(0x1a2b_3c4d_u32, f.receiver);
        assert_eq!(1u16, f.part);
        assert_eq!(2u16, f.total);
        assert_eq!(b"?OTR:encoded.", f.payload.as_slice());
    }

    #[test]
    fn test_parse_fragment_dont_be_stupid_you_know_base64_has_additional_characters() {
        let f = parse(b"?OTR|7a38ec40|60b07b61,00026,00029,+/5b9OkBSaV3fsR=,").unwrap();
        assert_eq!(Version::V3, f.version);
        assert_eq!([0u8; 4], f.identifier);
        assert_eq!(0x7a38_ec40_u32, f.sender);
        assert_eq!(0x60b0_7b61_u32, f.receiver);
        assert_eq!(26u16, f.part);
        assert_eq!(29u16, f.total);
        assert_eq!(b"+/5b9OkBSaV3fsR=", f.payload.as_slice());
    }

    #[test]
    fn test_parse_fragment_with_shorter_instance_tags_and_part_data() {
        let f = parse(b"?OTR|ec40|161,26,29,ab5b9OkBSaV3fsR=,").unwrap();
        assert_eq!(Version::V3, f.version);
        assert_eq!([0u8; 4], f.identifier);
        assert_eq!(0x0000_ec40_u32, f.sender);
        assert_eq!(0x0000_0161_u32, f.receiver);
        assert_eq!(26u16, f.part);
        assert_eq!(29u16, f.total);
        assert_eq!(b"ab5b9OkBSaV3fsR=", f.payload.as_slice());
    }

    #[test]
    fn test_fragment_specified_test_case() {
        const TESTCASE: &[u8;354] = b"?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.";
        const FRAGMENT0: &[u8;199] = b"?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,";
        const FRAGMENT1: &[u8;199] = b"?OTR|5a73a599|27e31597,00002,00003,jPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2i,";
        const FRAGMENT2: &[u8; 64] =
            b"?OTR|5a73a599|27e31597,00003,00003,pkTtquknfx6HodLvk3RAAAAAA==.,";
        let result = fragment(199, &Version::V3, 0x5a73_a599, 0x27e3_1597, TESTCASE);
        assert_eq!(
            Ordering::Equal,
            utils::bytes::cmp(
                FRAGMENT0,
                &OTREncoder::new().write_encodable(&result[0]).to_vec()
            )
        );
        assert_eq!(
            Ordering::Equal,
            utils::bytes::cmp(
                FRAGMENT1,
                &OTREncoder::new().write_encodable(&result[1]).to_vec()
            )
        );
        assert_eq!(
            Ordering::Equal,
            utils::bytes::cmp(
                FRAGMENT2,
                &OTREncoder::new().write_encodable(&result[2]).to_vec()
            )
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_assemble_max_messages() {
        let mut assembler = UnorderedAssembler {
            tick: 1,
            fragments: HashMap::new(),
        };
        let mut prev = 0u32;
        for i in 0u32..MAX_MESSAGES as u32 + 3 {
            let sender_id = u32::MAX - i;
            let receiver_id = 0x0000_ffff - i;
            // print!(r"?OTR|{i:08X}|{sender_id:08X}|{receiver_id:08X},00001,00003,He");
            let p1 = Fragment {
                version: Version::V4,
                identifier: i.to_be_bytes(),
                sender: sender_id,
                receiver: receiver_id,
                part: 1,
                total: 3,
                payload: Vec::from("He"),
            };
            let p2 = Fragment {
                version: Version::V4,
                identifier: i.to_be_bytes(),
                sender: sender_id,
                receiver: receiver_id,
                part: 2,
                total: 3,
                payload: Vec::from("ll"),
            };
            assert!(assembler.assemble(&p1).is_err());
            assert!(assembler.assemble(&p2).is_err());
            assert_eq!(
                (i + 1).min(MAX_MESSAGES as u32),
                assembler.fragments.len() as u32
            );
            assert!(prev < assembler.tick);
            prev = assembler.tick;
        }
    }

    #[test]
    fn test_huge_fragment_rejected() {
        let mut big = Vec::with_capacity(200 * 1024);
        big.resize(200 * 1024, 0);
        utils::random::fill_secure_bytes(&mut big);
        assert!(!big.is_empty());
        let fragment = Fragment {
            version: Version::V4,
            identifier: 1u32.to_be_bytes(),
            sender: u32::MAX - 1,
            receiver: u32::MAX,
            part: 2,
            total: 3,
            payload: big,
        };
        assert!(super::verify(&fragment).is_ok());
        let mut huge = Vec::with_capacity(1024 * 1024);
        huge.resize(1024 * 1024, 0);
        utils::random::fill_secure_bytes(&mut huge);
        assert!(!huge.is_empty());
        let fragment = Fragment {
            version: Version::V4,
            identifier: 1u32.to_be_bytes(),
            sender: u32::MAX - 1,
            receiver: u32::MAX,
            part: 1,
            total: 3,
            payload: huge,
        };
        assert!(super::verify(&fragment).is_err());
    }
}

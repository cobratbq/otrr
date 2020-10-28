use regex::bytes::Regex;

use crate::{InstanceTag, OTRError, Version};

const OTR_FRAGMENT_V2_PREFIX: &[u8] = b"?OTR,";
const OTR_FRAGMENT_V3_PREFIX: &[u8] = b"?OTR|";
const OTR_FRAGMENT_SUFFIX: &[u8] = b",";

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";
const OTR_ENCODED_SUFFIX: &[u8] = b".";

const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";

const INDEX_FIRST_FRAGMENT: u16 = 1;

lazy_static! {
    static ref FRAGMENT_PATTERN: Regex = Regex::new(
        r"\?OTR\|([0-9a-fA-F]{1,8})\|([0-9a-fA-F]{1,8}),(\d{1,5}),(\d{1,5}),([\?A-Za-z0-9:\.]+),"
    )
    .unwrap();
    static ref QUERY_PATTERN: Regex = Regex::new(r"\?OTR\??(:?v(\d*))?\?").unwrap();
    static ref WHITESPACE_PATTERN: Regex =
        Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*").unwrap();
}

pub struct Decoder {
    assembler: Assembler,
}

// FIXME: perfect fuzzing target!
impl Decoder {
    fn parse(&mut self, data: &[u8]) -> Result<MessageType, OTRError> {
        if data.starts_with(OTR_FRAGMENT_V2_PREFIX) {
            return Err(OTRError::InvalidProtocolData(
                "OTRv2 fragments are not supported.",
            ));
        }
        if data.starts_with(OTR_FRAGMENT_V3_PREFIX) {
            if !data.ends_with(OTR_FRAGMENT_SUFFIX) {
                return Err(OTRError::InvalidProtocolData(
                    "Incomplete OTR version 3 fragment data.",
                ));
            }
            let fragment = parse_fragment(data);
            // TODO: need to verify that fragment instance data corresponds with assembled payload instance data.
            return match self.assembler.assemble(fragment) {
                Ok(payload) => return self.parse(&payload),
                Err(AssemblingError::IncompleteResult) => Err(OTRError::MessageIncomplete),
                Err(AssemblingError::UnexpectedFragment) => Err(OTRError::InvalidProtocolData(
                    "Unexpected fragment received. Data will be ignored.",
                )),
                Err(AssemblingError::IllegalFragment) => Err(OTRError::InvalidProtocolData(
                    "Illegal fragment received. Data will be ignored.",
                )),
            };
        }
        if data.starts_with(OTR_ENCODED_PREFIX) {
            if !data.ends_with(OTR_ENCODED_SUFFIX) {
                return Err(OTRError::InvalidProtocolData(
                    "Incomplete OTR-encoded data.",
                ));
            }
            return match base64::decode(&data[OTR_ENCODED_PREFIX.len()..data.len() - 1]) {
                // TODO: can we do this without losing the original error?
                Err(_) => Err(OTRError::InvalidProtocolData(
                    "Failure decoding base64-encoded payload.",
                )),
                Ok(decoded) => parse_encoded_message(&decoded),
            };
        }
        if data.starts_with(OTR_ERROR_PREFIX) {
            return Ok(MessageType::ErrorMessage {
                // TODO: needs trimming to remove possible prefix space?
                content: Vec::from(&data[OTR_ERROR_PREFIX.len()..]),
            });
        }
        return parse_plain_message(data);
    }
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let v: u16 = (data[0] as u16) << 8 + data[1] as u16;
    let version: Version = match v {
        3u16 => Version::V3,
        _ => {
            return Err(OTRError::InvalidProtocolData(
                "Invalid or unknown protocol version.",
            ))
        }
    };
    let message_type: EncodedMessageType = match data[2] {
        0x02 => EncodedMessageType::DHCommit,
        0x0a => EncodedMessageType::DHKey,
        0x11 => EncodedMessageType::RevealSignature,
        0x12 => EncodedMessageType::Signature,
        0x03 => EncodedMessageType::Data,
        _ => {
            return Err(OTRError::InvalidProtocolData(
                "Invalid or unknown message type.",
            ))
        }
    };
    let sender: u32 =
        (data[3] as u32) << 24 + (data[4] as u32) << 16 + (data[5] as u32) << 8 + data[6] as u32;
    let receiver: u32 =
        (data[7] as u32) << 24 + (data[8] as u32) << 16 + (data[9] as u32) << 8 + data[10] as u32;
    return Result::Ok(MessageType::EncodedMessage {
        version: version,
        messagetype: message_type,
        sender: sender,
        receiver: receiver,
        content: Vec::from(&data[11..]),
    });
}

fn parse_plain_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let query_caps = QUERY_PATTERN.captures(data);
    if query_caps.is_some() {
        return match query_caps.unwrap().get(1) {
            None => Ok(MessageType::QueryMessage {
                versions: Vec::new(),
            }),
            Some(versions) => Ok(MessageType::QueryMessage {
                versions: versions
                    .as_bytes()
                    .iter()
                    .map(|v| {
                        match v {
                            // '1' is not actually allowed according to OTR-spec. (illegal)
                            b'1' => Version::Unsupported(1u16),
                            b'2' => Version::Unsupported(2u16),
                            b'3' => Version::V3,
                            // TODO: Use u16::MAX here as placeholder for unparsed textual value representation.
                            _ => Version::Unsupported(std::u16::MAX),
                        }
                    })
                    .filter(|v| match v {
                        Version::V3 => true,
                        Version::Unsupported(_) => false,
                    })
                    .collect(),
            }),
        };
    }
    // TODO: search for multiple occurrences?
    let whitespace_caps = WHITESPACE_PATTERN.captures(data);
    if whitespace_caps.is_some() {
        let cleaned = WHITESPACE_PATTERN.replace_all(data, b"".as_ref()).to_vec();
        return match whitespace_caps.unwrap().get(1) {
            None => Ok(MessageType::TaggedMessage {
                versions: Vec::new(),
                content: cleaned,
            }),
            Some(cap) => Ok(MessageType::TaggedMessage {
                versions: parse_whitespace_tags(cap.as_bytes()),
                content: cleaned,
            }),
        };
    }
    return Ok(MessageType::PlaintextMessage {
        content: data.to_vec(),
    });
}

fn parse_whitespace_tags(data: &[u8]) -> Vec<Version> {
    let mut result: Vec<Version> = Vec::new();
    for i in (0..data.len()).step_by(8) {
        match &data[i..i + 8] {
            WHITESPACE_TAG_OTRV1 => { /* ignore OTRv1 tag, unsupported version */ }
            WHITESPACE_TAG_OTRV2 => { /* ignore OTRv2 tag, unsupported version */ }
            WHITESPACE_TAG_OTRV3 => result.push(Version::V3),
            _ => { /* ignore unknown tags */ }
        }
    }
    return result;
}

pub enum MessageType {
    PlaintextMessage {
        content: Vec<u8>,
    },
    TaggedMessage {
        versions: Vec<Version>,
        content: Vec<u8>,
    },
    QueryMessage {
        versions: Vec<Version>,
    },
    ErrorMessage {
        content: Vec<u8>,
    },
    EncodedMessage {
        version: Version,
        messagetype: EncodedMessageType,
        sender: InstanceTag,
        receiver: InstanceTag,
        content: Vec<u8>,
    },
}

pub enum EncodedMessageType {
    DHCommit,
    DHKey,
    RevealSignature,
    Signature,
    Data,
}

struct Assembler {
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
enum AssemblingError {
    /// Illegal fragment received. Fragment contains bad data and cannot be processed.
    IllegalFragment,
    /// Incomplete result. Waiting for more fragments to arrive.
    IncompleteResult,
    /// Unexpected fragment received. Resetting assembler.
    UnexpectedFragment,
}

fn parse_fragment(content: &[u8]) -> Fragment {
    let fragment_caps = FRAGMENT_PATTERN.captures(content);
    if fragment_caps.is_none() {
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

struct Fragment {
    sender: InstanceTag,
    receiver: InstanceTag,
    part: u16,
    total: u16,
    payload: Vec<u8>,
}

enum FragmentError {
    IllegalFragment,
}

fn verify(fragment: &Fragment) -> Result<(), FragmentError> {
    return if fragment.total == 0 || fragment.part == 0 || fragment.part > fragment.total {
        Err(FragmentError::IllegalFragment)
    } else {
        Ok(())
    };
}

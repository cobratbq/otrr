use regex::bytes::Regex;

use crate::{InstanceTag, OTRError, Version};

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";
const OTR_ENCODED_SUFFIX: &[u8] = b".";

const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";

lazy_static! {
    static ref QUERY_PATTERN: Regex = Regex::new(r"\?OTR\??(:?v(\d*))?\?").unwrap();
    static ref WHITESPACE_PATTERN: Regex =
        Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*").unwrap();
}

pub fn parse(data: &[u8]) -> Result<MessageType, OTRError> {
    return if is_otr_encoded(data) {
        parse_encoded_message(data)
    } else {
        parse_plain_message(data)
    };
}

fn is_otr_encoded(data: &[u8]) -> bool {
    return data.starts_with(OTR_ENCODED_PREFIX) && data.ends_with(OTR_ENCODED_SUFFIX);
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let v: u16 = (data[0] as u16) << 8 + data[1] as u16;
    let version: Version = match v {
        3u16 => Version::V3,
        _ => {
            return Err(OTRError::ProtocolViolation(
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
            return Err(OTRError::ProtocolViolation(
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
    if data.starts_with(OTR_ERROR_PREFIX) {
        // `?OTR Error:` prefix must start at beginning of message to avoid people messing with OTR in normal plaintext messages.
        return Ok(MessageType::ErrorMessage(Vec::from(
            &data[OTR_ERROR_PREFIX.len()..],
        )));
    }
    let query_caps = QUERY_PATTERN.captures(data);
    if query_caps.is_some() {
        return match query_caps.unwrap().get(1) {
            None => Ok(MessageType::QueryMessage(Vec::new())),
            Some(versions) => Ok(MessageType::QueryMessage(
                versions
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
            )),
        };
    }
    // TODO: search for multiple occurrences?
    let whitespace_caps = WHITESPACE_PATTERN.captures(data);
    if whitespace_caps.is_some() {
        let cleaned = WHITESPACE_PATTERN.replace_all(data, b"".as_ref()).to_vec();
        return match whitespace_caps.unwrap().get(1) {
            None => Ok(MessageType::TaggedMessage(Vec::new(), cleaned)),
            Some(cap) => Ok(MessageType::TaggedMessage(
                parse_whitespace_tags(cap.as_bytes()),
                cleaned,
            )),
        };
    }
    return Ok(MessageType::PlaintextMessage(data.to_vec()));
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
    ErrorMessage(Vec<u8>),
    PlaintextMessage(Vec<u8>),
    TaggedMessage(Vec<Version>, Vec<u8>),
    QueryMessage(Vec<Version>),
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

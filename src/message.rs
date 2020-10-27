use regex::bytes::Regex;
use crate::{InstanceTag, OTRError, Version};

const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";

lazy_static! {
    static ref QUERY_PATTERN: Regex = Regex::new(r"\?OTR\??(:?v(\d*))?\?").unwrap();
    static ref WHITESPACE_PATTERN: Regex = Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*").unwrap();
}

pub fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let v: u16 = (data[0] as u16) << 8 + data[1] as u16;
    let version: Version = match v {
        3u16 => Version::V3,
        _ => return Err(OTRError::InvalidProtocolData("Invalid or unknown protocol version.")),
    };
    let message_type: EncodedMessageType = match data[2] {
        0x02 => EncodedMessageType::DHCommit,
        0x0a => EncodedMessageType::DHKey,
        0x11 => EncodedMessageType::RevealSignature,
        0x12 => EncodedMessageType::Signature,
        0x03 => EncodedMessageType::Data,
        _ => return Err(OTRError::InvalidProtocolData("Invalid or unknown message type.")),
    };
    let sender: u32 = (data[3] as u32) << 24 + (data[4] as u32) << 16 + (data[5] as u32) << 8 + data[6] as u32;
    let receiver: u32 = (data[7] as u32) << 24 + (data[8] as u32) << 16 + (data[9] as u32) << 8 + data[10] as u32;
    return Result::Ok(MessageType::EncodedMessage{
        version: version,
        messagetype: message_type,
        sender: sender,
        receiver: receiver,
        content: Vec::from(&data[11..]),
    });
}

pub fn parse_unencoded_message(data: &[u8]) -> Result<MessageType, OTRError> {    
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
            None => Ok(MessageType::TaggedMessage{
                versions: Vec::new(),
                content: cleaned,
            }),
            Some(cap) => Ok(MessageType::TaggedMessage{
                versions: parse_whitespace_tags(cap.as_bytes()),
                content: cleaned,
            }),
        }
    }
    return Ok(MessageType::PlaintextMessage {
        content: data.to_vec(),
    })
}

fn parse_whitespace_tags(data: &[u8]) -> Vec<Version> {
    let mut result: Vec<Version> = Vec::new();
    for i in (0..data.len()).step_by(8) {
        match &data[i..i+8] {
            WHITESPACE_TAG_OTRV1 => { /* ignore OTRv1 tag, unsupported version */ },
            WHITESPACE_TAG_OTRV2 => { /* ignore OTRv2 tag, unsupported version */ },
            WHITESPACE_TAG_OTRV3 => result.push(Version::V3),
            _ => { /* ignore unknown tags */ },
        }
    }
    return result
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

#[cfg(test)]
mod tests {
    // FIXME: add test for mid-string query tag, at start and at end of message.
    use crate::message::{parse_message, MessageType, Version};

    #[test]
    fn parse_empty_message() {
        match parse_message(b"").unwrap() {
            MessageType::PlaintextMessage { content } => assert_eq!(b"", content.as_slice()),
            _ => panic!("Incorret message type received."),
        }
    }

    #[test]
    fn parse_hello_world_message() {
        match parse_message(b"Hello world! Greetings from <undisclosed location>").unwrap() {
            MessageType::PlaintextMessage { content } => assert_eq!(
                b"Hello world! Greetings from <undisclosed location>".as_ref(),
                content.as_slice()
            ),
            _ => panic!("Incorret message type received."),
        }
    }

    #[test]
    fn parse_message_false_query_tag() {
        match parse_message(b"?OTRv Hello world!").unwrap() {
            MessageType::PlaintextMessage { content } => {
                assert_eq!(b"?OTRv Hello world!".as_ref(), content.as_slice())
            }
            _ => panic!("Incorret message type received."),
        }
    }

    #[test]
    fn parse_message_false_query_tag_2() {
        match parse_message(b"OTRv3? Hello world!").unwrap() {
            MessageType::PlaintextMessage { content } => {
                assert_eq!(b"OTRv3? Hello world!".as_ref(), content.as_slice())
            }
            _ => panic!("Incorret message type received."),
        }
    }

    #[test]
    fn parse_query_message_otrv1_format() {
        match parse_message(b"?OTR?").unwrap() {
            MessageType::QueryMessage { versions } => assert!(versions.is_empty()),
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_empty() {
        match parse_message(b"?OTRv?").unwrap() {
            MessageType::QueryMessage { versions } => assert!(versions.is_empty()),
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_v1_illegal() {
        match parse_message(b"?OTRv1?").unwrap() {
            MessageType::QueryMessage { versions } => assert!(versions.is_empty()),
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_v2() {
        match parse_message(b"?OTRv2?").unwrap() {
            MessageType::QueryMessage { versions } => assert!(versions.is_empty()),
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_v3() {
        match parse_message(b"?OTRv3?").unwrap() {
            MessageType::QueryMessage { versions } => {
                assert_eq!(1, versions.len());
                assert!(versions[0] == Version::V3);
            }
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_v23() {
        match parse_message(b"?OTRv23?").unwrap() {
            MessageType::QueryMessage { versions } => {
                assert_eq!(1, versions.len());
                assert!(Version::V3 == versions[0]);
            }
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_v234() {
        match parse_message(b"?OTRv234?").unwrap() {
            MessageType::QueryMessage { versions } => {
                assert_eq!(1, versions.len());
                assert!(Version::V3 == versions[0]);
            }
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_query_message_otrv2_format_v34() {
        match parse_message(b"?OTRv34?").unwrap() {
            MessageType::QueryMessage { versions } => {
                assert_eq!(1, versions.len());
                assert!(Version::V3 == versions[0]);
            }
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_tagged_message_no_versions() {
        match parse_message(b"Hello \t  \t\t\t\t \t \t \t   world!").unwrap() {
            MessageType::TaggedMessage {versions, content} => {
                assert_eq!(0, versions.len());
                assert_eq!(b"Hello world!", content.as_slice());
            }
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_tagged_message_versions_v1v2() {
        match parse_message(b"Hello \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t  world!").unwrap() {
            MessageType::TaggedMessage {versions, content} => {
                assert_eq!(0, versions.len());
                assert_eq!(b"Hello world!", content.as_slice());
            }
            _ => panic!("Unexpected message type."),
        }
    }

    #[test]
    fn parse_tagged_message_versions_v3() {
        match parse_message(b"Hello \t  \t\t\t\t \t \t \t    \t\t  \t\t world!").unwrap() {
            MessageType::TaggedMessage {versions, content} => {
                assert_eq!(1, versions.len());
                assert!(versions[0] == Version::V3);
                assert_eq!(b"Hello world!", content.as_slice());
            }
            _ => panic!("Unexpected message type."),
        }
    }
}

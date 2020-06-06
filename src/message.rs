use regex::bytes::Regex;
use std::io::Error;

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";

const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRv3: &[u8] = b"  \t\t  \t\t";

fn parse_message(data: &[u8]) -> Result<MessageType, Error> {
    if data.starts_with(OTR_ENCODED_PREFIX) {
        return parse_encoded_message(data);
    }
    if data.starts_with(OTR_ERROR_PREFIX) {
        return Ok(MessageType::ErrorMessage {
            // FIXME needs trimming to remove possible prefix space?
            content: Vec::from(&data[OTR_ERROR_PREFIX.len()..]),
        });
    }
    return parse_unencoded_message(data);
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, Error> {
    panic!("To be implemented")
    // return Ok(Message::EncodedMessage{
    //     version: Version::V3,
    //     messagetype: EncodedMessageType::Temp,
    //     sender: 256,
    //     receiver: 257,
    //     content: data.to_vec(),
    // })
}

fn parse_unencoded_message(data: &[u8]) -> Result<MessageType, Error> {
    // TODO: extract RegEx pattern as constant.
    let query_pattern = Regex::new(r"\?OTR\??(:?v(\d*))?\?").unwrap();
    let query_caps = query_pattern.captures(data);
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
                            b'1' => Version::Unsupported(*v),
                            b'2' => Version::Unsupported(*v),
                            b'3' => Version::V3,
                            _ => Version::Unsupported(*v),
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
    // FIXME: extract RegEx pattern as constant.
    let whitespace_pattern = Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*").unwrap();
    let whitespace_caps = whitespace_pattern.captures(data);
    if whitespace_caps.is_some() {
        let cleaned = whitespace_pattern.replace_all(data, b"".as_ref()).to_vec();
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
            WHITESPACE_TAG_OTRV1 => { /* ignore OTRv1 tag */ },
            WHITESPACE_TAG_OTRV2 => { /* ignore OTRv2 tag */ },
            WHITESPACE_TAG_OTRv3 => result.push(Version::V3),
            _ => { /* ignore unknown tag */ },
        }
    }
    return result
}

enum MessageType {
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

#[derive(PartialEq)]
enum Version {
    // V1, // most likely never going to be needed.
    // V2, // will not be supported.
    V3,
    Unsupported(u8),
}

type InstanceTag = u32;

enum EncodedMessageType {}

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

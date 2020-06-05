use regex::bytes::Regex;
use std::io::Error;

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";

fn parse_message(data: &[u8]) -> Result<MessageType, Error> {
    if data.starts_with(OTR_ENCODED_PREFIX) {
        return parse_encoded_message(data);
    }
    if data.starts_with(OTR_ERROR_PREFIX) {
        return Ok(MessageType::ErrorMessage {
            // TODO needs trimming to remove possible prefix space?
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
                        Version::Unsupported(_) => false,
                        Version::V3 => true,
                    })
                    .collect(),
            }),
        };
    }
    // TODO continue with parsing whitespace patterns.
    let whitespace_pattern = Regex::new(" \t  \t\t\t\t \t \t \t  ").unwrap();
    let whitespace_caps = whitespace_pattern.captures(data);
    if whitespace_caps.is_some() {
        panic!("Whitespace pattern matching to be implemented.");
    }
    return Ok(MessageType::PlaintextMessage {
        content: data.to_vec(),
    })
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
}

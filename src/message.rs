use std::io::Error;
use regex::bytes::Regex;

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";

fn parse_message(data: &[u8]) -> Result<MessageType, Error> {
    println!("Parsing raw message content ....");
    if data.starts_with(OTR_ENCODED_PREFIX) {
        return parse_encoded_message(data)
    }
    if data.starts_with(OTR_ERROR_PREFIX) {
        return Ok(MessageType::ErrorMessage{
            content: Vec::from(&data[OTR_ERROR_PREFIX.len()..]),
        })
    }
    return parse_unencoded_message(data)
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
        let versions_cap = query_caps.unwrap().get(1);
        if versions_cap.is_some() {
            return Ok(MessageType::QueryMessage{
                versions: versions_cap.unwrap().as_bytes().iter().map(|v| {
                    match v {
                        // '1' is not actually allowed according to OTR-spec.
                        // FIXME consider b'1' a protocol violation, return error.
                        // b'1' => Version::V1,
                        // b'2' => Version::V2,
                        b'3' => Version::V3,
                        _ => Version::Unsupported(*v),
                    }
                }).collect(),
            })
        }
        return Ok(MessageType::QueryMessage{versions: Vec::new()})
    }
    let whitespace_pattern = Regex::new(r"").unwrap();    
    let whitespace_caps = whitespace_pattern.captures(data);
    if whitespace_caps.is_some() {
        panic!("Whitespace pattern matching to be implemented.");
    }
    return Ok(MessageType::PlaintextMessage{
        content: data.to_vec(),
    })
}

enum MessageType {
    PlaintextMessage{
        content: Vec<u8>,
    },
    TaggedMessage{
        versions: Vec<Version>,
        content: Vec<u8>,
    },
    QueryMessage{
        versions: Vec<Version>,
    },
    ErrorMessage{
        content: Vec<u8>,
    },
    EncodedMessage{
        version: Version,
        messagetype: EncodedMessageType,
        sender: InstanceTag,
        receiver: InstanceTag,
        content: Vec<u8>,
    },
}

enum Version {
    // V1, // most likely never going to be needed.
    // V2,
    V3,
    Unsupported(u8),
}

type InstanceTag = u32;

enum EncodedMessageType {
}

#[cfg(test)]
mod tests {
    // FIXME: add test for mid-string query tag, at start and at end of message.
    use crate::message::{parse_message,MessageType};

    #[test]
    fn parse_query_message_OTRv1_format() {
        parse_message(b"?OTR?").unwrap();
    }

    #[test]
    fn parse_query_message_OTRv2_format_empty() {
        match parse_message(b"?OTRv?").unwrap() {
            MessageType::QueryMessage{versions} => assert!(versions.is_empty()),
            _ => panic!("Unexpected message type."),
        }
    }

    // #[test]
    // fn parse_query_message_OTRv2_format_v1_illegal() {
    //     parse_message(b"?OTRv1?").unwrap();
    // }

    // #[test]
    // fn parse_query_message_OTRv2_format_v2() {
    //     parse_message(b"?OTRv2?").unwrap();
    // }

    // #[test]
    // fn parse_query_message_OTRv2_format_v3() {
    //     parse_message(b"?OTRv3?").unwrap();
    // }

    // #[test]
    // fn parse_query_message_OTRv2_format_v23() {
    //     parse_message(b"?OTRv3?").unwrap();
    // }

    // #[test]
    // fn parse_query_message_OTRv2_format_v234() {
    //     parse_message(b"?OTRv3?").unwrap();
    // }

    // #[test]
    // fn parse_query_message_OTRv2_format_v34() {
    //     parse_message(b"?OTRv3?").unwrap();
    // }

    #[test]
    fn parse_empty() {
        let msg = parse_message(b"").unwrap();
        match msg {
            super::MessageType::PlaintextMessage{content} => {
                assert_eq!(b"", content.as_slice());
            }
            _ => panic!("Incorrect type received.")
        }
    }
}
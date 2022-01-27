// FIXME move tests to appropriate modules.
#[cfg(test)]
mod tests {
    // FIXME add test for mid-string query tag, at start and at end of message.
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

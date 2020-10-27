use crate::{OTRError, fragment::parse_fragment, message::{MessageType, parse_encoded_message, parse_unencoded_message}};

const OTR_FRAGMENT_V2_PREFIX: &[u8] = b"?OTR,";
const OTR_FRAGMENT_V3_PREFIX: &[u8] = b"?OTR|";
const OTR_FRAGMENT_SUFFIX: &[u8] = b",";

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";
const OTR_ENCODED_SUFFIX: &[u8] = b".";

pub fn parse(data: &[u8]) -> Result<MessageType, OTRError> {
    if data.starts_with(OTR_FRAGMENT_V2_PREFIX) {
        return Err(OTRError::InvalidProtocolData("OTRv2 fragments are not supported."))
    }
    if data.starts_with(OTR_FRAGMENT_V3_PREFIX) {
        if !data.ends_with(OTR_FRAGMENT_SUFFIX) {
            return Err(OTRError::InvalidProtocolData("Incomplete OTR version 3 fragment data."))
        }
        let fragment = parse_fragment(data);
        // FIXME continue here
    }
    if data.starts_with(OTR_ENCODED_PREFIX) {
        if !data.ends_with(OTR_ENCODED_SUFFIX) {
            return Err(OTRError::InvalidProtocolData("Incomplete OTR-encoded data."))
        }
        return match base64::decode(&data[OTR_ENCODED_PREFIX.len()..data.len()-1]) {
            // TODO: can we do this without losing the original error?
            Err(_) => Err(OTRError::InvalidProtocolData("Failure decoding base64-encoded payload.")),
            Ok(decoded) => parse_encoded_message(&decoded),
        };
    }
    if data.starts_with(OTR_ERROR_PREFIX) {
        return Ok(MessageType::ErrorMessage {
            // FIXME needs trimming to remove possible prefix space?
            content: Vec::from(&data[OTR_ERROR_PREFIX.len()..]),
        });
    }
    return parse_unencoded_message(data);
}
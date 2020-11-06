use num_bigint::BigUint;
use regex::bytes::Regex;

use crate::{InstanceTag, OTRError, Version};

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";
const OTR_ENCODED_SUFFIX: &[u8] = b".";

const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";

const OTR_DH_COMMIT_TYPE_CODE: u8 = 0x02;
const OTR_DH_KEY_TYPE_CODE: u8 = 0x0a;
const OTR_REVEAL_SIGNATURE_TYPE_CODE: u8 = 0x11;
const OTR_SIGNATURE_TYPE_CODE: u8 = 0x12;
const OTR_DATA_TYPE_CODE: u8 = 0x03;

const FLAG_IGNORE_UNREADABLE: u8 = 0b00000001;

lazy_static! {
    static ref QUERY_PATTERN: Regex = Regex::new(r"\?OTR\??(:?v(\d*))?\?").unwrap();
    static ref WHITESPACE_PATTERN: Regex =
        Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*").unwrap();
}

// TODO over all I/O parsing/interpreting do explicit message length checking and fail if fewer bytes available than expected.

pub fn parse(data: &[u8]) -> Result<MessageType, OTRError> {
    return if data.starts_with(OTR_ENCODED_PREFIX) && data.ends_with(OTR_ENCODED_SUFFIX) {
        parse_encoded_message(data)
    } else {
        parse_plain_message(data)
    };
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let v: u16 = (data[0] as u16) << 8 + data[1] as u16;
    let version: Version = match v {
        3u16 => Version::V3,
        _ => return Err(OTRError::ProtocolViolation("Invalid or unknown protocol version.")),
    };
    let sender: u32 =
        (data[3] as u32) << 24 + (data[4] as u32) << 16 + (data[5] as u32) << 8 + data[6] as u32;
    let receiver: u32 =
        (data[7] as u32) << 24 + (data[8] as u32) << 16 + (data[9] as u32) << 8 + data[10] as u32;
    let encoded = interpret_encoded_content(data[2], &data[11..])?;
    return Result::Ok(MessageType::EncodedMessage {
        version: version,
        sender: sender,
        receiver: receiver,
        message: encoded,
    });
}

fn interpret_encoded_content(message_type: u8, content: &[u8]) -> Result<OTRMessage, OTRError> {
    let mut decoder = OTRDecoder{content: content};
    return match message_type {
        OTR_DH_COMMIT_TYPE_CODE => {
            let encrypted = decoder.readData()?;
            let hashed = decoder.readData()?;
            Ok(OTRMessage::DHCommit{
                gx_encrypted: encrypted,
                gx_hashed: hashed,
            })
        }
        OTR_DH_KEY_TYPE_CODE => {
            let gy = decoder.readMPI()?;
            Ok(OTRMessage::DHKey{
                gy: gy,
            })
        }
        OTR_REVEAL_SIGNATURE_TYPE_CODE => {
            let key = decoder.readData()?;
            let encrypted = decoder.readData()?;
            let mac = decoder.readMAC()?;
            Ok(OTRMessage::RevealSignature{
                key: key,
                signature_encrypted: Vec::from(encrypted),
                signature_mac: mac,
            })
        }
        OTR_SIGNATURE_TYPE_CODE => {
            let encrypted = decoder.readData()?;
            let mac = decoder.readMAC()?;
            Ok(OTRMessage::Signature{
                signature_encrypted: Vec::from(encrypted),
                signature_mac: mac,
            })
        }
        OTR_DATA_TYPE_CODE => {
            let flags = decoder.readByte()?;
            let sender_keyid = decoder.readInt()?;
            let receiver_keyid = decoder.readInt()?;
            let dh_y = decoder.readMPI()?;
            let ctr = decoder.readCTR()?;
            let encrypted = decoder.readData()?;
            let authenticator = decoder.readMAC()?;
            let revealed = decoder.readData()?;
            Ok(OTRMessage::Data{
                flags: flags,
                sender_keyid: sender_keyid,
                receiver_keyid: receiver_keyid,
                dh_y: dh_y,
                ctr: ctr,
                encrypted: encrypted,
                authenticator: authenticator,
                revealed: revealed,
            })
        }
        _ => Err(OTRError::ProtocolViolation("Invalid or unknown message type.")),
    }
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
        sender: InstanceTag,
        receiver: InstanceTag,
        message: OTRMessage,
    },
}

pub enum OTRMessage {
    DHCommit{
        gx_encrypted: Vec<u8>,
        gx_hashed: Vec<u8>,
    },
    DHKey{
        gy: BigUint
    },
    RevealSignature{
        key: Vec<u8>,
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    },
    Signature{
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    },
    Data{
        flags: u8,
        sender_keyid: u32,
        receiver_keyid: u32,
        dh_y: BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: MAC,
        /// revealed contains all the keys used to generate MACs for authentication.
        revealed: Vec<u8>,
    },
}

pub type CTR = [u8;8];

pub type MAC = [u8;20];

// TODO predefine TLVs according to spec or keep open for custom implementation? (seems that predefining with exact fields might be more useful/controllable)
/// Type-Length-Value records that are optionally appended to content of an OTR Data Message.
pub struct TLV {
    typ: u16,
    value: Vec<u8>,
}

struct OTRDecoder<'a>  {
    content: &'a [u8],
}

// FIXME use decoder for initial message metadata (protocol, message type, sender instance, receiver instance)
/// OTRDecoder contains the logic for reading entries from byte-buffer.
impl OTRDecoder<'_> {

    /// readByte reads a single byte from buffer.
    fn readByte(&mut self) -> Result<u8, OTRError> {
        if self.content.len() < 1 {
            return Err(OTRError::IncompleteMessage)
        }
        let value = self.content[0];
        self.content = &self.content[1..];
        return Ok(value)
    }

    /// readShort reads a short value (2 bytes, big-endian) from buffer.
    fn readShort(&mut self) -> Result<u16, OTRError> {
        if self.content.len() < 2 {
            return Err(OTRError::IncompleteMessage)
        }
        let value = (self.content[0] as u16) << 8 + self.content[1] as u16;
        self.content = &self.content[2..];
        return Ok(value)
    }

    /// readInt reads an integer value (4 bytes, big-endian) from buffer.
    fn readInt(&mut self) -> Result<u32, OTRError> {
        if self.content.len() < 4 {
            return Err(OTRError::IncompleteMessage)
        }
        let value = (self.content[0] as u32) << 24 + (self.content[1] as u32) << 16 + (self.content[2] as u32) << 8 + self.content[3] as u32;
        self.content = &self.content[4..];
        return Ok(value)
    }

    /// readData reads variable-length data from buffer.
    fn readData(&mut self) -> Result<Vec<u8>, OTRError> {
        let len = self.readLength()?;
        if self.content.len() < len {
            return Err(OTRError::IncompleteMessage)
        }
        let data = Vec::from(&self.content[..]);
        self.content = &self.content[data.len()..];
        return Ok(data)
    }

    /// readMPI reads MPI from buffer.
    fn readMPI(&mut self) -> Result<BigUint, OTRError> {
        let len = self.readLength()?;
        if self.content.len() < len {
            return Err(OTRError::IncompleteMessage)
        }
        let mpi = BigUint::from_bytes_be(&self.content[..len]);
        self.content = &self.content[len..];
        return Ok(mpi)
    }

    fn readCTR(&mut self) -> Result<CTR, OTRError> {
        if self.content.len() < 8 {
            return Err(OTRError::IncompleteMessage)
        }
        let mut ctr: CTR = [0;8];
        ctr.copy_from_slice(&self.content[0..8]);
        self.content = &self.content[8..];
        return Ok(ctr)
    }

    /// readMAC reads a MAC value from buffer.
    fn readMAC(&mut self) -> Result<MAC, OTRError> {
        if self.content.len() < 20 {
            return Err(OTRError::IncompleteMessage)
        }
        let mut mac: MAC = [0;20];
        mac.copy_from_slice(&self.content[0..20]);
        self.content = &self.content[20..];
        return Ok(mac);
    }

    /// readContent reads content until null-terminated or end of buffer.
    fn readContent(&mut self) -> Result<Vec<u8>, OTRError> {
        let mut content_end_index = self.content.len();
        for i in 0..self.content.len() {
            if self.content[i] == 0 {
                content_end_index = i;
                break;
            }
        }
        let content = Vec::from(&self.content[0..content_end_index]);
        self.content = &self.content[content_end_index+1..];
        return Ok(content)
    }

    /// readTLVs reads TLV-records until end of buffer.
    fn readTLVs(&mut self) -> Result<Vec<TLV>, OTRError> {
        // FIXME check for content length before reading type, length and value from the content array
        let mut tlvs = Vec::new();
        while self.content.len() > 0 {
            if self.content.len() < 4 {
                return Err(OTRError::IncompleteMessage)
            }
            let typ = (self.content[0] as u16) << 8 + self.content[1] as u16;
            let len = (self.content[2] as usize) << 8 + self.content[3] as usize;
            if self.content.len() < 4+len {
                return Err(OTRError::IncompleteMessage)
            }
            tlvs.push(TLV{typ: typ, value: Vec::from(&self.content[4..4+len])});
            self.content = &self.content[4+len..];
        }
        return Ok(tlvs);
    }

    /// readLength reads 4-byte unsigned big-endian length.
    fn readLength(&mut self) -> Result<usize, OTRError> {
        if self.content.len() < 4 {
            return Err(OTRError::IncompleteMessage);
        }
        let length = (self.content[0] as usize) << 24 + (self.content[1] as usize) << 16 + (self.content[2] as usize) << 8 + self.content[3] as usize;
        self.content = &self.content[4..];
        return Ok(length)
    }
}
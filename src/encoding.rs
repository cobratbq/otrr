use std::convert::TryInto;

use num_bigint::BigUint;
use regex::bytes::Regex;

use crate::{crypto::AES128, crypto::DSA, InstanceTag, OTRError, Signature, Version, CTR, MAC};

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

// TODO over all necessary writes, do usize size-of assertions.
// TODO over all I/O parsing/interpreting do explicit message length checking and fail if fewer bytes available than expected.

pub fn parse(data: &[u8]) -> Result<MessageType, OTRError> {
    return if data.starts_with(OTR_ENCODED_PREFIX) && data.ends_with(OTR_ENCODED_SUFFIX) {
        parse_encoded_message(data)
    } else {
        parse_plain_message(data)
    };
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let mut decoder = OTRDecoder(data);
    let version: Version = match decoder.read_short()? {
        3u16 => Version::V3,
        _ => {
            return Err(OTRError::ProtocolViolation(
                "Invalid or unknown protocol version.",
            ))
        }
    };
    let message_type = decoder.read_byte()?;
    let sender = decoder.read_int()?;
    let receiver = decoder.read_int()?;
    let encoded = interpret_encoded_content(message_type, decoder)?;
    return Result::Ok(MessageType::EncodedMessage {
        version: version,
        sender: sender,
        receiver: receiver,
        message: encoded,
    });
}

fn interpret_encoded_content(
    message_type: u8,
    mut decoder: OTRDecoder,
) -> Result<OTRMessage, OTRError> {
    return match message_type {
        OTR_DH_COMMIT_TYPE_CODE => {
            let encrypted = decoder.read_data()?;
            let hashed = decoder.read_data()?;
            Ok(OTRMessage::DHCommit {
                gx_encrypted: encrypted,
                gx_hashed: hashed,
            })
        }
        OTR_DH_KEY_TYPE_CODE => {
            let gy = decoder.read_mpi()?;
            Ok(OTRMessage::DHKey { gy })
        }
        OTR_REVEAL_SIGNATURE_TYPE_CODE => {
            let key = decoder.read_data()?;
            let encrypted = decoder.read_data()?;
            let mac = decoder.read_mac()?;
            Ok(OTRMessage::RevealSignature {
                key: AES128::Key(key.try_into().unwrap()),
                signature_encrypted: Vec::from(encrypted),
                signature_mac: mac,
            })
        }
        OTR_SIGNATURE_TYPE_CODE => {
            let encrypted = decoder.read_data()?;
            let mac = decoder.read_mac()?;
            Ok(OTRMessage::Signature {
                signature_encrypted: Vec::from(encrypted),
                signature_mac: mac,
            })
        }
        OTR_DATA_TYPE_CODE => {
            let flags = decoder.read_byte()?;
            let sender_keyid = decoder.read_int()?;
            let receiver_keyid = decoder.read_int()?;
            let dh_y = decoder.read_mpi()?;
            let ctr = decoder.read_ctr()?;
            let encrypted = decoder.read_data()?;
            let authenticator = decoder.read_mac()?;
            let revealed = decoder.read_data()?;
            Ok(OTRMessage::Data {
                flags,
                sender_keyid,
                receiver_keyid,
                dh_y,
                ctr,
                encrypted,
                authenticator,
                revealed,
            })
        }
        _ => Err(OTRError::ProtocolViolation(
            "Invalid or unknown message type.",
        )),
    };
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
                            // TODO Use u16::MAX here as placeholder for unparsed textual value representation.
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
    // TODO search for multiple occurrences?
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
    let mut result = Vec::new();
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
    DHCommit {
        gx_encrypted: Vec<u8>,
        gx_hashed: Vec<u8>,
    },
    DHKey {
        gy: BigUint,
    },
    RevealSignature {
        key: AES128::Key,
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    },
    Signature {
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    },
    Data {
        flags: u8,
        sender_keyid: u32,
        receiver_keyid: u32,
        dh_y: BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: MAC,
        /// revealed contains recent keys previously used for authentication.
        revealed: Vec<u8>,
    },
}

pub struct OTRDecoder<'a>(&'a [u8]);

// FIXME use decoder for initial message metadata (protocol, message type, sender instance, receiver instance)
/// OTRDecoder contains the logic for reading entries from byte-buffer.
impl<'a> OTRDecoder<'a> {
    pub fn new(content: &'a [u8]) -> Self {
        return Self(content);
    }

    /// read_byte reads a single byte from buffer.
    pub fn read_byte(&mut self) -> Result<u8, OTRError> {
        if self.0.len() < 1 {
            return Err(OTRError::IncompleteMessage);
        }
        let value = self.0[0];
        self.0 = &self.0[1..];
        return Ok(value);
    }

    /// read_short reads a short value (2 bytes, big-endian) from buffer.
    pub fn read_short(&mut self) -> Result<u16, OTRError> {
        if self.0.len() < 2 {
            return Err(OTRError::IncompleteMessage);
        }
        let value = (self.0[0] as u16) << 8 + self.0[1] as u16;
        self.0 = &self.0[2..];
        return Ok(value);
    }

    /// read_int reads an integer value (4 bytes, big-endian) from buffer.
    pub fn read_int(&mut self) -> Result<u32, OTRError> {
        if self.0.len() < 4 {
            return Err(OTRError::IncompleteMessage);
        }
        // FIXME error with operator precedence?
        let value = (self.0[0] as u32)
            << 24 + (self.0[1] as u32)
            << 16 + (self.0[2] as u32)
            << 8 + self.0[3] as u32;
        self.0 = &self.0[4..];
        return Ok(value);
    }

    /// read_data reads variable-length data from buffer.
    pub fn read_data(&mut self) -> Result<Vec<u8>, OTRError> {
        let len = self.read_int()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let data = Vec::from(&self.0[..len]);
        self.0 = &self.0[len..];
        return Ok(data);
    }

    /// read_mpi reads MPI from buffer.
    pub fn read_mpi(&mut self) -> Result<BigUint, OTRError> {
        let len = self.read_int()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let mpi = BigUint::from_bytes_be(&self.0[..len]);
        self.0 = &self.0[len..];
        return Ok(mpi);
    }

    /// Read sequence of MPI values as defined by SMP.
    pub fn read_mpi_sequence(&mut self) -> Result<Vec<BigUint>, OTRError> {
        let len = self.read_int()? as usize;
        let mut mpis = Vec::new();
        for _ in 0..len {
            mpis.push(self.read_mpi()?);
        }
        Ok(mpis)
    }

    /// read_ctr reads CTR value from buffer.
    pub fn read_ctr(&mut self) -> Result<CTR, OTRError> {
        if self.0.len() < 8 {
            return Err(OTRError::IncompleteMessage);
        }
        let mut ctr: CTR = [0; 8];
        ctr.copy_from_slice(&self.0[..8]);
        self.0 = &self.0[8..];
        return Ok(ctr);
    }

    /// read_mac reads a MAC value from buffer.
    pub fn read_mac(&mut self) -> Result<MAC, OTRError> {
        if self.0.len() < 20 {
            return Err(OTRError::IncompleteMessage);
        }
        let mut mac: MAC = [0; 20];
        mac.copy_from_slice(&self.0[..20]);
        self.0 = &self.0[20..];
        return Ok(mac);
    }

    /// read_public_key reads a DSA public key from the buffer.
    pub fn read_public_key(&mut self) -> Result<DSA::PublicKey, OTRError> {
        let typ = self.read_short()?;
        if typ != 0u16 {
            return Err(OTRError::ProtocolViolation(
                "Unsupported/invalid public key type.",
            ));
        }
        // TODO: not sure if I like the fact that read_mpi is mutable, so fields must remain in this order or we're reading wrong data into wrong field.
        Ok(DSA::PublicKey {
            p: self.read_mpi()?,
            q: self.read_mpi()?,
            g: self.read_mpi()?,
            y: self.read_mpi()?,
        })
    }

    /// read_signature reads a DSA signature (IEEE-P1393 format) from buffer.
    pub fn read_signature(&mut self) -> Result<Signature, OTRError> {
        if self.0.len() < 40 {
            return Err(OTRError::IncompleteMessage);
        }
        let mut sig: Signature = [0; 40];
        sig.copy_from_slice(&self.0[..40]);
        self.0 = &self.0[40..];
        return Ok(sig);
    }

    /// read_tlv reads a type-length-value record from the content.
    pub fn read_tlv(&mut self) -> Result<TLV, OTRError> {
        let typ = self.read_short()?;
        let len = self.read_short()? as usize;
        let data = Vec::from(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(TLV(typ, data))
    }
}

pub struct OTREncoder {
    content: Vec<u8>,
}

// TODO can we use 'mut self' so that we move the original instance around mutably?
impl OTREncoder {
    pub fn new() -> Self {
        return Self {
            content: Vec::new(),
        };
    }

    pub fn write_byte(&mut self, v: u8) -> &mut Self {
        self.content.push(v);
        self
    }

    pub fn write_short(&mut self, v: u16) -> &mut Self {
        let b = v.to_be_bytes();
        self.content.push(b[0]);
        self.content.push(b[1]);
        self
    }

    pub fn write_int(&mut self, v: u32) -> &mut Self {
        let b = v.to_be_bytes();
        self.content.push(b[0]);
        self.content.push(b[1]);
        self.content.push(b[2]);
        self.content.push(b[3]);
        self
    }

    pub fn write_data(&mut self, v: &Vec<u8>) -> &mut Self {
        self.write_int(v.len() as u32);
        self.content.extend_from_slice(v);
        self
    }

    pub fn write_mpi(&mut self, v: &BigUint) -> &mut Self {
        self.write_data(&v.to_bytes_be())
    }

    /// Write sequence of MPI values in format defined in SMP: num_mpis, mpi1, mpi2, ...
    pub fn write_mpi_sequence(&mut self, mpis: &[&BigUint]) -> &mut Self {
        self.write_int(mpis.len() as u32);
        for mpi in mpis {
            self.write_mpi(mpi);
        }
        self
    }

    pub fn write_ctr(&mut self, v: &CTR) -> &mut Self {
        assert_eq!(8, v.len());
        self.content.extend_from_slice(v);
        self
    }

    pub fn write_mac(&mut self, v: &MAC) -> &mut Self {
        assert_eq!(20, v.len());
        self.content.extend_from_slice(v);
        self
    }

    // TODO solve using OTREncodable trait and implementation inside encodable types
    pub fn write_public_key(&mut self, key: &DSA::PublicKey) -> &mut Self {
        self.write_short(0u16)
            .write_mpi(&key.p)
            .write_mpi(&key.q)
            .write_mpi(&key.g)
            .write_mpi(&key.y)
    }

    pub fn write_signature(&mut self, sig: &Signature) -> &mut Self {
        assert_eq!(40, sig.len());
        self.content.extend_from_slice(sig);
        self
    }

    pub fn write_tlv(&mut self, tlv: TLV) -> &mut Self {
        assert!(tlv.1.len() <= u16::MAX as usize);
        self.write_short(tlv.0).write_short(tlv.1.len() as u16);
        self.content.extend(tlv.1);
        self
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.content.clone()
    }
}

pub struct TLV(pub u16, pub Vec<u8>);

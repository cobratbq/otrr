use std::convert::TryInto;

use bitflags::bitflags;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::{
    crypto::AES128, crypto::DSA, OTRError, Signature, Version, CTR, CTR_LEN, MAC, MAC_LEN,
    SIGNATURE_LEN, TLV, instancetag::{InstanceTag, verify_instance_tag},
};

bitflags! {
    /// MessageFlag bit-flags can set for OTR-encoded messages.
    struct MessageFlag: u8 {
        /// FLAG_IGNORE_UNREADABLE indicates that the message can be ignored if it cannot be read. This is typically used for control messages that have no value to the user, to indicate that there is no point in alerting the user of an inaccessible message.
        const FLAG_IGNORE_UNREADABLE = 0b00000001;
    }
}

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_QUERY_PREFIX: &[u8] = b"?OTRv";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";
const OTR_ENCODED_SUFFIX: &[u8] = b".";

// TODO tweak / make accompanying message changeable
const OTR_USE_INFORMATION_MESSAGE: &[u8] = b"An Off-The-Record conversation has been requested.";

const WHITESPACE_PREFIX: &[u8] = b" \t  \t\t\t\t \t \t \t  ";
const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";

// TODO does this pattern support the OTRv1 query-pattern, as it deviates from the others, in order to correctly identify the protocol being present.
static QUERY_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\?OTR\??(:?v(\d*))?\?").unwrap());
static WHITESPACE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*").unwrap());

const OTR_DH_COMMIT_TYPE_CODE: u8 = 0x02;
const OTR_DH_KEY_TYPE_CODE: u8 = 0x0a;
const OTR_REVEAL_SIGNATURE_TYPE_CODE: u8 = 0x11;
const OTR_SIGNATURE_TYPE_CODE: u8 = 0x12;
const OTR_DATA_TYPE_CODE: u8 = 0x03;

// TODO over all necessary writes, do usize size-of assertions. (or use type-aliasing to ensure appropriate size)
// TODO over all I/O parsing/interpreting do explicit message length checking and fail if fewer bytes available than expected.

pub fn parse(data: &[u8]) -> Result<MessageType, OTRError> {
    return if data.starts_with(OTR_ENCODED_PREFIX) && data.ends_with(OTR_ENCODED_SUFFIX) {
        let start = OTR_ENCODED_PREFIX.len();
        let end = data.len() - OTR_ENCODED_SUFFIX.len();
        parse_encoded_message(&data[start..end])
    } else {
        parse_plain_message(data)
    };
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let data = decode_base64(&data)?;
    let mut decoder = OTRDecoder(&data);
    let version: Version = match decoder.read_short()? {
        3u16 => Version::V3,
        _ => {
            return Err(OTRError::ProtocolViolation(
                "Invalid or unknown protocol version.",
            ))
        }
    };
    let message_type = decoder.read_byte()?;
    let sender: InstanceTag = decoder.read_instance_tag()?;
    let receiver: InstanceTag = decoder.read_instance_tag()?;
    let encoded = parse_encoded_content(message_type, decoder)?;
    return Result::Ok(MessageType::EncodedMessage(EncodedMessage {
        version: version,
        sender: sender,
        receiver: receiver,
        message: encoded,
    }));
}

fn parse_encoded_content(
    message_type: u8,
    mut decoder: OTRDecoder,
) -> Result<OTRMessage, OTRError> {
    return match message_type {
        OTR_DH_COMMIT_TYPE_CODE => Ok(OTRMessage::DHCommit(DHCommitMessage::decode(&mut decoder)?)),
        OTR_DH_KEY_TYPE_CODE => Ok(OTRMessage::DHKey(DHKeyMessage::decode(&mut decoder)?)),
        OTR_REVEAL_SIGNATURE_TYPE_CODE => Ok(OTRMessage::RevealSignature(
            RevealSignatureMessage::decode(&mut decoder)?,
        )),
        OTR_SIGNATURE_TYPE_CODE => Ok(OTRMessage::Signature(SignatureMessage::decode(
            &mut decoder,
        )?)),
        OTR_DATA_TYPE_CODE => Ok(OTRMessage::Data(DataMessage::decode(&mut decoder)?)),
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
    EncodedMessage(EncodedMessage),
}

pub struct EncodedMessage {
    pub version: Version,
    pub sender: InstanceTag,
    pub receiver: InstanceTag,
    pub message: OTRMessage,
}

impl OTREncodable for EncodedMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        // FIXME: correctly derive short-value from Version-type. (now hard-coded)
        encoder
            .write_short(3u16)
            .write_byte(match self.message {
                OTRMessage::DHCommit(_) => OTR_DH_COMMIT_TYPE_CODE,
                OTRMessage::DHKey(_) => OTR_DH_KEY_TYPE_CODE,
                OTRMessage::RevealSignature(_) => OTR_REVEAL_SIGNATURE_TYPE_CODE,
                OTRMessage::Signature(_) => OTR_SIGNATURE_TYPE_CODE,
                OTRMessage::Data(_) => OTR_DATA_TYPE_CODE,
            })
            .write_int(self.sender)
            .write_int(self.receiver)
            .write_encodable(match &self.message {
                OTRMessage::DHCommit(msg) => msg,
                OTRMessage::DHKey(msg) => msg,
                OTRMessage::RevealSignature(msg) => msg,
                OTRMessage::Signature(msg) => msg,
                OTRMessage::Data(msg) => msg,
            });
    }
}

/// OTR-message represents all of the existing OTR-encoded message structures in use by OTR.
pub enum OTRMessage {
    /// DH-Commit-message in the AKE-process.
    DHCommit(DHCommitMessage),
    /// DH-Key-message in the AKE-process.
    DHKey(DHKeyMessage),
    /// RevealSignature-message in the AKE-process.
    RevealSignature(RevealSignatureMessage),
    /// Signature-message in the AKE-process.
    Signature(SignatureMessage),
    /// (Encrypted) data message.
    Data(DataMessage),
}

pub struct DHCommitMessage {
    pub gx_encrypted: Vec<u8>,
    pub gx_hashed: Vec<u8>,
}

impl DHCommitMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<DHCommitMessage, OTRError> {
        Ok(DHCommitMessage {
            gx_encrypted: decoder.read_data()?,
            gx_hashed: decoder.read_data()?,
        })
    }
}

impl OTREncodable for DHCommitMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_data(&self.gx_encrypted)
            .write_data(&self.gx_hashed);
    }
}

pub struct DHKeyMessage {
    pub gy: BigUint,
}

impl DHKeyMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<DHKeyMessage, OTRError> {
        Ok(DHKeyMessage {
            gy: decoder.read_mpi()?,
        })
    }
}

impl OTREncodable for DHKeyMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder.write_mpi(&self.gy);
    }
}

pub struct RevealSignatureMessage {
    pub key: AES128::Key,
    pub signature_encrypted: Vec<u8>,
    pub signature_mac: MAC,
}

impl RevealSignatureMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<RevealSignatureMessage, OTRError> {
        Ok(RevealSignatureMessage {
            key: AES128::Key(decoder.read_data()?.try_into().or(Err(
                OTRError::ProtocolViolation("Invalid format for 128-bit AES key."),
            ))?),
            signature_encrypted: decoder.read_data()?,
            signature_mac: decoder.read_mac()?,
        })
    }
}

impl OTREncodable for RevealSignatureMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_data(&self.key.0)
            .write_data(&self.signature_encrypted)
            .write_mac(&self.signature_mac);
    }
}

pub struct SignatureMessage {
    pub signature_encrypted: Vec<u8>,
    pub signature_mac: MAC,
}

impl SignatureMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<SignatureMessage, OTRError> {
        Ok(SignatureMessage {
            signature_encrypted: decoder.read_data()?,
            signature_mac: decoder.read_mac()?,
        })
    }
}

impl OTREncodable for SignatureMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_data(&self.signature_encrypted)
            .write_mac(&self.signature_mac);
    }
}

pub struct DataMessage {
    pub flags: u8,
    pub sender_keyid: u32,
    pub receiver_keyid: u32,
    pub dh_y: BigUint,
    pub ctr: CTR,
    pub encrypted: Vec<u8>,
    pub authenticator: MAC,
    /// revealed contains recent keys, previously used for authentication, that should now become public.
    pub revealed: Vec<u8>,
}

impl DataMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<DataMessage, OTRError> {
        Ok(DataMessage {
            flags: decoder.read_byte()?,
            sender_keyid: decoder.read_int()?,
            receiver_keyid: decoder.read_int()?,
            dh_y: decoder.read_mpi()?,
            ctr: decoder.read_ctr()?,
            encrypted: decoder.read_data()?,
            authenticator: decoder.read_mac()?,
            revealed: decoder.read_data()?,
        })
    }
}

impl OTREncodable for DataMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_byte(self.flags)
            .write_int(self.sender_keyid)
            .write_int(self.receiver_keyid)
            .write_mpi(&self.dh_y)
            .write_ctr(&self.ctr)
            .write_data(&self.encrypted)
            .write_mac(&self.authenticator)
            .write_data(&self.revealed);
    }
}

pub fn encode(msg: &MessageType) -> Vec<u8> {
    let mut buffer = Vec::<u8>::new();
    match msg {
        MessageType::ErrorMessage(error) => {
            buffer.extend_from_slice(OTR_ERROR_PREFIX);
            buffer.extend(error);
            buffer
        }
        MessageType::PlaintextMessage(message) => {
            buffer.extend(message);
            buffer
        }
        MessageType::TaggedMessage(versions, message) => {
            if !versions.is_empty() {
                // TODO test for valid versions before adding whitespace-prefix.
                // TODO determine/look-up best location, e.g. beginning or end of string or somewhere in between?
                buffer.extend_from_slice(WHITESPACE_PREFIX);
                for v in versions {
                    // FIXME strictly speaking there must be at least one tag or we violate spec.
                    match v {
                        Version::V3 => buffer.extend_from_slice(WHITESPACE_TAG_OTRV3),
                        Version::Unsupported(_) => {},
                    }
                }
            }
            buffer.extend(message);
            buffer
        }
        MessageType::QueryMessage(versions) => {
            buffer.extend_from_slice(OTR_QUERY_PREFIX);
            for v in versions {
                // TODO versions not guaranteed unique.
                // TODO versions not necessarily ordered.
                match v {
                    Version::V3 => {
                        buffer.push(b'3');
                    }
                    Version::Unsupported(unsupported) => {
                        panic!(
                            "BUG: unsupported version {} leaked into encoding logic.",
                            unsupported
                        )
                    }
                }
            }
            buffer.push(b'?');
            buffer.push(b' ');
            buffer.extend_from_slice(OTR_USE_INFORMATION_MESSAGE);
            buffer
        }
        MessageType::EncodedMessage(encoded_message) => {
            buffer.extend_from_slice(OTR_ENCODED_PREFIX);
            buffer.extend(encode_base64(
                OTREncoder::new().write_encodable(encoded_message).to_vec(),
            ));
            buffer.push(b'.');
            buffer
        }
    }
}

pub struct OTRDecoder<'a>(&'a [u8]);

// FIXME use decoder for initial message metadata (protocol, message type, sender instance, receiver instance)
/// OTRDecoder contains the logic for reading entries from byte-buffer.
#[allow(dead_code)]
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
        let value = ((self.0[0] as u32) << 24)
            + ((self.0[1] as u32) << 16)
            + ((self.0[2] as u32) << 8)
            + (self.0[3] as u32);
        self.0 = &self.0[4..];
        return Ok(value);
    }

    pub fn read_instance_tag(&mut self) -> Result<InstanceTag, OTRError> {
        verify_instance_tag(self.read_int()?)
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
        if self.0.len() < CTR_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut ctr: CTR = [0; CTR_LEN];
        ctr.copy_from_slice(&self.0[..CTR_LEN]);
        self.0 = &self.0[CTR_LEN..];
        return Ok(ctr);
    }

    /// read_mac reads a MAC value from buffer.
    pub fn read_mac(&mut self) -> Result<MAC, OTRError> {
        if self.0.len() < MAC_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut mac: MAC = [0; MAC_LEN];
        mac.copy_from_slice(&self.0[..MAC_LEN]);
        self.0 = &self.0[MAC_LEN..];
        return Ok(mac);
    }

    /// read_public_key reads a DSA public key from the buffer.
    pub fn read_public_key(&mut self) -> Result<DSA::PublicKey, OTRError> {
        let pktype = self.read_short()?;
        if pktype != 0u16 {
            return Err(OTRError::ProtocolViolation(
                "Unsupported/invalid public key type.",
            ));
        }
        // TODO not sure if I like the fact that read_mpi is mutable, so fields must remain in this order or we're reading wrong data into wrong field.
        Ok(DSA::PublicKey {
            p: self.read_mpi()?,
            q: self.read_mpi()?,
            g: self.read_mpi()?,
            y: self.read_mpi()?,
        })
    }

    /// read_signature reads a DSA signature (IEEE-P1393 format) from buffer.
    pub fn read_signature(&mut self) -> Result<Signature, OTRError> {
        if self.0.len() < SIGNATURE_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut sig: Signature = [0; SIGNATURE_LEN];
        sig.copy_from_slice(&self.0[..SIGNATURE_LEN]);
        self.0 = &self.0[SIGNATURE_LEN..];
        return Ok(sig);
    }

    /// read_tlv reads a type-length-value record from the content.
    pub fn read_tlv(&mut self) -> Result<TLV, OTRError> {
        let typ = self.read_short()?;
        let len = self.read_short()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let data = Vec::from(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(TLV(typ, data))
    }

    pub fn read_fingerprint(&mut self) -> Result<Fingerprint, OTRError> {
        if self.0.len() < FINGERPRINT_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut fingerprint = [0u8; FINGERPRINT_LEN];
        fingerprint.clone_from_slice(&self.0[..FINGERPRINT_LEN]);
        self.0 = &self.0[FINGERPRINT_LEN..];
        Ok(fingerprint)
    }

    pub fn read_ssid(&mut self) -> Result<SSID, OTRError> {
        if self.0.len() < SSID_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut ssid = [0u8; SSID_LEN];
        ssid.clone_from_slice(&self.0[..SSID_LEN]);
        self.0 = &self.0[SSID_LEN..];
        Ok(ssid)
    }

    pub fn read_bytes_null_terminated(&mut self) -> Result<Vec<u8>, OTRError> {
        todo!()
    }
}

pub trait OTREncodable {
    fn encode(&self, encoder: &mut OTREncoder);
}

pub struct OTREncoder {
    buffer: Vec<u8>,
}

// TODO can we use 'mut self' so that we move the original instance around mutably?
#[allow(dead_code)]
impl OTREncoder {
    pub fn new() -> Self {
        return Self { buffer: Vec::new() };
    }

    pub fn write_encodable(&mut self, encodable: &dyn OTREncodable) -> &mut Self {
        encodable.encode(self);
        self
    }

    pub fn write_byte(&mut self, v: u8) -> &mut Self {
        self.buffer.push(v);
        self
    }

    pub fn write_short(&mut self, v: u16) -> &mut Self {
        let b = v.to_be_bytes();
        self.buffer.push(b[0]);
        self.buffer.push(b[1]);
        self
    }

    pub fn write_int(&mut self, v: u32) -> &mut Self {
        let b = v.to_be_bytes();
        self.buffer.push(b[0]);
        self.buffer.push(b[1]);
        self.buffer.push(b[2]);
        self.buffer.push(b[3]);
        self
    }

    pub fn write_data(&mut self, v: &[u8]) -> &mut Self {
        assert!(v.len() <= (u32::MAX as usize));
        self.write_int(v.len() as u32);
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_mpi(&mut self, v: &BigUint) -> &mut Self {
        self.write_data(&v.to_bytes_be())
    }

    /// Write sequence of MPI values in format defined in SMP: num_mpis, mpi1, mpi2, ...
    pub fn write_mpi_sequence(&mut self, mpis: &[&BigUint]) -> &mut Self {
        self.write_int(mpis.len() as u32);
        for mpi in mpis {
            self.write_mpi(*mpi);
        }
        self
    }

    pub fn write_ctr(&mut self, v: &CTR) -> &mut Self {
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_mac(&mut self, v: &MAC) -> &mut Self {
        self.buffer.extend_from_slice(v);
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
        self.buffer.extend_from_slice(sig);
        self
    }

    pub fn write_tlv(&mut self, tlv: TLV) -> &mut Self {
        assert!(tlv.1.len() <= (u16::MAX as usize));
        self.write_short(tlv.0).write_short(tlv.1.len() as u16);
        self.buffer.extend(tlv.1);
        self
    }

    pub fn write_bytes_null_terminated(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(data);
        self.buffer.push(0u8);
        self
    }

    pub fn write_fingerprint(&mut self, fingerprint: &Fingerprint) -> &mut Self {
        self.buffer.extend_from_slice(fingerprint);
        self
    }

    pub fn write_ssid(&mut self, ssid: &SSID) -> &mut Self {
        self.buffer.extend_from_slice(ssid);
        self
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.clone()
    }
}

fn encode_base64(content: Vec<u8>) -> Vec<u8> {
    base64::encode(&content).into_bytes()
}

fn decode_base64(content: &[u8]) -> Result<Vec<u8>, OTRError> {
    base64::decode(content).or(Err(OTRError::ProtocolViolation(
        "Invalid message content: content cannot be decoded from base64.",
    )))
}

const FINGERPRINT_LEN: usize = 20;
pub type Fingerprint = [u8; FINGERPRINT_LEN];

const SSID_LEN: usize = 8;
pub type SSID = [u8; SSID_LEN];

#![allow(clippy::upper_case_acronyms)]

use std::convert::TryInto;

use bitflags::bitflags;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::{
    crypto::DSA,
    crypto::{
        AES128,
        DSA::{Signature, PARAM_Q_LENGTH},
    },
    instancetag::{verify_instance_tag, InstanceTag},
    utils, OTRError, TLVType, Version,
};

bitflags! {
    /// MessageFlag bit-flags can set for OTR-encoded messages.
    pub struct MessageFlags: u8 {
        /// FLAG_IGNORE_UNREADABLE indicates that the message can be ignored if it cannot be read.
        /// If set, no user-error is produced. This is typically used for control messages that have
        /// no value to the user, to indicate that there is no point in alerting the user of an
        /// inaccessible message.
        const IGNORE_UNREADABLE = 0b0000_0001;
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

static QUERY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\?OTR\??(:?v(\d*))?\?").expect("BUG: failed to compile hard-coded regex-pattern.")
});
const QUERY_GROUP_VERSIONS: usize = 1;
static WHITESPACE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*")
        .expect("BUG: failed to compile hard-coded regex-pattern.")
});
const WHITESPACE_GROUP_TAGS: usize = 1;

const OTR_DH_COMMIT_TYPE_CODE: u8 = 0x02;
const OTR_DH_KEY_TYPE_CODE: u8 = 0x0a;
const OTR_REVEAL_SIGNATURE_TYPE_CODE: u8 = 0x11;
const OTR_SIGNATURE_TYPE_CODE: u8 = 0x12;
const OTR_DATA_TYPE_CODE: u8 = 0x03;

// TODO over all necessary writes, do usize size-of assertions. (or use type-aliasing to ensure appropriate size)
// TODO over all I/O parsing/interpreting do explicit message length checking and fail if fewer bytes available than expected.

pub fn parse(data: &[u8]) -> Result<MessageType, OTRError> {
    if data.starts_with(OTR_ENCODED_PREFIX) && data.ends_with(OTR_ENCODED_SUFFIX) {
        let start = OTR_ENCODED_PREFIX.len();
        let end = data.len() - OTR_ENCODED_SUFFIX.len();
        parse_encoded_message(&data[start..end])
    } else {
        Ok(parse_plain_message(data))
    }
}

fn parse_encoded_message(data: &[u8]) -> Result<MessageType, OTRError> {
    let data = decode_base64(data)?;
    let mut decoder = OTRDecoder(&data);
    let version: Version = match decoder.read_short()? {
        3u16 => Version::V3,
        version => return Err(OTRError::UnsupportedVersion(version)),
    };
    let message_type = decoder.read_byte()?;
    let sender: InstanceTag = decoder.read_instance_tag()?;
    let receiver: InstanceTag = decoder.read_instance_tag()?;
    let encoded = parse_encoded_content(message_type, decoder)?;
    Result::Ok(MessageType::Encoded(EncodedMessage {
        version,
        sender,
        receiver,
        message: encoded,
    }))
}

fn parse_encoded_content(
    message_type: u8,
    mut decoder: OTRDecoder,
) -> Result<OTRMessageType, OTRError> {
    match message_type {
        OTR_DH_COMMIT_TYPE_CODE => Ok(OTRMessageType::DHCommit(DHCommitMessage::decode(
            &mut decoder,
        )?)),
        OTR_DH_KEY_TYPE_CODE => Ok(OTRMessageType::DHKey(DHKeyMessage::decode(&mut decoder)?)),
        OTR_REVEAL_SIGNATURE_TYPE_CODE => Ok(OTRMessageType::RevealSignature(
            RevealSignatureMessage::decode(&mut decoder)?,
        )),
        OTR_SIGNATURE_TYPE_CODE => Ok(OTRMessageType::Signature(SignatureMessage::decode(
            &mut decoder,
        )?)),
        OTR_DATA_TYPE_CODE => Ok(OTRMessageType::Data(DataMessage::decode(&mut decoder)?)),
        _ => Err(OTRError::ProtocolViolation(
            "Invalid or unknown message type.",
        )),
    }
}

fn parse_plain_message(data: &[u8]) -> MessageType {
    if data.starts_with(OTR_ERROR_PREFIX) {
        // `?OTR Error:` prefix must start at beginning of message to avoid people messing with OTR in normal plaintext messages.
        return MessageType::Error(Vec::from(&data[OTR_ERROR_PREFIX.len()..]));
    }
    if let Some(caps) = (&*QUERY_PATTERN).captures(data) {
        let versions = caps
            .get(QUERY_GROUP_VERSIONS)
            .expect("BUG: hard-coded regex should contain capture group for versions");
        return MessageType::Query(
            versions
                .as_bytes()
                .iter()
                .map(|v| {
                    match v {
                        // '1' is not actually allowed according to OTR-spec. (illegal)
                        // (The pattern ignores the original format for v1.)
                        b'1' => Version::Unsupported(1u16),
                        b'2' => Version::Unsupported(2u16),
                        b'3' => Version::V3,
                        // TODO Use u16::MAX here as placeholder for unparsed textual value representation.
                        _ => Version::Unsupported(u16::from(*v)),
                    }
                })
                .filter(|v| match v {
                    Version::V3 => true,
                    Version::Unsupported(_) | Version::None => false,
                })
                .collect(),
        );
    }
    // TODO search for multiple occurrences?
    if let Some(caps) = (&*WHITESPACE_PATTERN).captures(data) {
        let cleaned = (&*WHITESPACE_PATTERN)
            .replace_all(data, b"".as_ref())
            .to_vec();
        let cap = caps
            .get(WHITESPACE_GROUP_TAGS)
            .expect("BUG: hard-coded regex should include capture group");
        return MessageType::Tagged(parse_whitespace_tags(cap.as_bytes()), cleaned);
    }
    MessageType::Plaintext(data.to_vec())
}

fn parse_whitespace_tags(data: &[u8]) -> Vec<Version> {
    let mut result = Vec::new();
    for i in (0..data.len()).step_by(8) {
        match &data[i..i + 8] {
            WHITESPACE_TAG_OTRV1 | WHITESPACE_TAG_OTRV2 => {
                // ignore OTRv1, OTRv2 tags as we do not support these versions
            }
            WHITESPACE_TAG_OTRV3 => result.push(Version::V3),
            _ => { /* ignore unknown tags */ }
        }
    }
    result
}

// TODO it would probably make more sense for some of the types to accept '&[u8]'-style content
pub enum MessageType {
    Error(Vec<u8>),
    Plaintext(Vec<u8>),
    Tagged(Vec<Version>, Vec<u8>),
    Query(Vec<Version>),
    Encoded(EncodedMessage),
}

pub struct EncodedMessage {
    pub version: Version,
    pub sender: InstanceTag,
    pub receiver: InstanceTag,
    pub message: OTRMessageType,
}

impl OTREncodable for EncodedMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_short(encode_version(&self.version))
            .write_byte(match self.message {
                OTRMessageType::Undefined(_) => panic!(
                    "BUG: 'Undefined' message-type must be reprocessed. It cannot be sent as-is."
                ),
                OTRMessageType::DHCommit(_) => OTR_DH_COMMIT_TYPE_CODE,
                OTRMessageType::DHKey(_) => OTR_DH_KEY_TYPE_CODE,
                OTRMessageType::RevealSignature(_) => OTR_REVEAL_SIGNATURE_TYPE_CODE,
                OTRMessageType::Signature(_) => OTR_SIGNATURE_TYPE_CODE,
                OTRMessageType::Data(_) => OTR_DATA_TYPE_CODE,
            })
            .write_int(self.sender)
            .write_int(self.receiver)
            .write_encodable(match &self.message {
                OTRMessageType::Undefined(_) => panic!(
                    "BUG: 'Undefined' message-type must be reprocessed. It cannot be sent as-is."
                ),
                OTRMessageType::DHCommit(msg) => msg,
                OTRMessageType::DHKey(msg) => msg,
                OTRMessageType::RevealSignature(msg) => msg,
                OTRMessageType::Signature(msg) => msg,
                OTRMessageType::Data(msg) => msg,
            });
    }
}

/// OTR-message represents all of the existing OTR-encoded message structures in use by OTR.
pub enum OTRMessageType {
    // FIXME this seems like a workaround because the separation of concerns between 'session' and 'authentication' isn't clear.
    /// Undefined message type. This is used as an indicator that the content is not any one of the standard OTR-encoded message-types. Possibly a Plaintext message or a (partial) body in a Query message.
    Undefined(Vec<u8>),
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
    pub flags: MessageFlags,
    pub sender_keyid: KeyID,
    pub receiver_keyid: KeyID,
    pub dh_y: BigUint,
    // FIXME make sure right counter value used in all cases.
    // OTR-spec:
    //   "The initial counter is a 16-byte value whose first 8 bytes
    //    are the above "top half of counter init" value, and whose last 8
    //    bytes are all 0x00. Note that counter mode does not change the length
    //    of the message, so no message padding needs to be done. If you *want*
    //    to do message padding (to disguise the length of your message), use
    //    the above TLV of type 0."
    pub ctr: CTR,
    pub encrypted: Vec<u8>,
    pub authenticator: MAC,
    /// revealed contains recent keys, previously used for authentication, that should now become public.
    pub revealed: Vec<u8>,
}

pub type KeyID = u32;

impl DataMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<DataMessage, OTRError> {
        // TODO should we handle unknown message flags differently? (ignore what we don't know?)
        Ok(DataMessage {
            flags: MessageFlags::from_bits(decoder.read_byte()?)
                .ok_or(OTRError::ProtocolViolation("Invalid message flags"))?,
            sender_keyid: utils::std::u32::nonzero(decoder.read_int()?)
                .ok_or(OTRError::ProtocolViolation("Invalid KeyID: cannot be 0"))?,
            receiver_keyid: utils::std::u32::nonzero(decoder.read_int()?)
                .ok_or(OTRError::ProtocolViolation("Invalid KeyID: cannot be 0"))?,
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
            .write_byte(self.flags.bits())
            .write_int(self.sender_keyid)
            .write_int(self.receiver_keyid)
            .write_mpi(&self.dh_y)
            .write_ctr(&self.ctr)
            .write_data(&self.encrypted)
            .write_mac(&self.authenticator)
            .write_data(&self.revealed);
    }
}

pub fn encode_otr_message(
    version: Version,
    sender: InstanceTag,
    receiver: InstanceTag,
    message: OTRMessageType,
) -> Vec<u8> {
    encode_message(&MessageType::Encoded(EncodedMessage {
        version,
        sender,
        receiver,
        message,
    }))
}

pub fn encode_message(msg: &MessageType) -> Vec<u8> {
    let mut buffer = Vec::<u8>::new();
    match msg {
        MessageType::Error(error) => {
            buffer.extend_from_slice(OTR_ERROR_PREFIX);
            buffer.extend(error);
            buffer
        }
        MessageType::Plaintext(message) => {
            buffer.extend(message);
            buffer
        }
        MessageType::Tagged(versions, message) => {
            assert!(!versions.is_empty());
            // TODO test for valid versions before adding whitespace-prefix.
            // TODO determine/look-up best location, e.g. beginning or end of string or somewhere in between?
            buffer.extend_from_slice(WHITESPACE_PREFIX);
            for v in utils::std::alloc::vec_unique(versions.clone()) {
                // FIXME strictly speaking there must be at least one tag or we violate spec.
                match v {
                    Version::None => panic!("BUG: version 0 cannot be used for tagging"),
                    Version::V3 => buffer.extend_from_slice(WHITESPACE_TAG_OTRV3),
                    Version::Unsupported(_) => {
                        panic!("BUG: unsupported versions should be avoided.")
                    }
                }
            }
            buffer.extend(message);
            buffer
        }
        MessageType::Query(versions) => {
            assert!(!versions.is_empty());
            // NOTE: each version listed at most once, in arbitrary order.
            // (Version 1 has deviating syntax but is no longer supported.)
            buffer.extend_from_slice(OTR_QUERY_PREFIX);
            for v in utils::std::alloc::vec_unique(versions.clone()) {
                match v {
                    Version::None => panic!("BUG: version 0 cannot be used for query messages"),
                    Version::V3 => buffer.push(b'3'),
                    Version::Unsupported(_) => {
                        panic!("BUG: unsupported version should be avoided.")
                    }
                }
            }
            buffer.push(b'?');
            buffer.push(b' ');
            buffer.extend_from_slice(OTR_USE_INFORMATION_MESSAGE);
            buffer
        }
        MessageType::Encoded(encoded_message) => {
            buffer.extend_from_slice(OTR_ENCODED_PREFIX);
            buffer.extend(encode_base64(
                &OTREncoder::new().write_encodable(encoded_message).to_vec(),
            ));
            buffer.extend_from_slice(OTR_ENCODED_SUFFIX);
            buffer
        }
    }
}

pub fn encode_authenticator_data(
    version: &Version,
    sender: InstanceTag,
    receiver: InstanceTag,
    message: &DataMessage,
) -> Vec<u8> {
    OTREncoder::new()
        .write_short(encode_version(version))
        .write_byte(OTR_DATA_TYPE_CODE)
        .write_int(sender)
        .write_int(receiver)
        .write_byte(message.flags.bits())
        .write_int(message.sender_keyid)
        .write_int(message.receiver_keyid)
        .write_mpi(&message.dh_y)
        .write_ctr(&message.ctr)
        .write_data(&message.encrypted)
        .to_vec()
}

fn encode_version(version: &Version) -> u16 {
    match version {
        Version::None => 0,
        Version::V3 => 3,
        Version::Unsupported(_) => panic!("BUG: unsupported version"),
    }
}

// FIXME continue here: restructure encoding of signature into byte-based R and S components.
const SIGNATURE_LEN: usize = 40;

pub struct OTRDecoder<'a>(&'a [u8]);

// FIXME use decoder for initial message metadata (protocol, message type, sender instance, receiver instance)
/// `OTRDecoder` contains the logic for reading entries from byte-buffer.
///
/// The `OTRDecoder` is construct to assume that any read can fail due to unexpected EOL or unexpected data. The
///  input cannot be trusted, so we try to handle everything as an Err-result.
// TODO review every read-operation to ensure each access of the buffer has a corresponding shift to avoid reading same data twice.
impl<'a> OTRDecoder<'a> {
    pub fn new(content: &'a [u8]) -> Self {
        Self(content)
    }

    /// `read_byte` reads a single byte from buffer.
    pub fn read_byte(&mut self) -> Result<u8, OTRError> {
        if self.0.is_empty() {
            return Err(OTRError::IncompleteMessage);
        }
        let value = self.0[0];
        self.0 = &self.0[1..];
        Ok(value)
    }

    /// `read_short` reads a short value (2 bytes, big-endian) from buffer.
    pub fn read_short(&mut self) -> Result<u16, OTRError> {
        if self.0.len() < 2 {
            return Err(OTRError::IncompleteMessage);
        }
        let value = (u16::from(self.0[0]) << 8) + u16::from(self.0[1]);
        self.0 = &self.0[2..];
        Ok(value)
    }

    /// `read_int` reads an integer value (4 bytes, big-endian) from buffer.
    pub fn read_int(&mut self) -> Result<u32, OTRError> {
        if self.0.len() < 4 {
            return Err(OTRError::IncompleteMessage);
        }
        let value = (u32::from(self.0[0]) << 24)
            + (u32::from(self.0[1]) << 16)
            + (u32::from(self.0[2]) << 8)
            + u32::from(self.0[3]);
        self.0 = &self.0[4..];
        Ok(value)
    }

    pub fn read_instance_tag(&mut self) -> Result<InstanceTag, OTRError> {
        verify_instance_tag(self.read_int()?)
            .or(Err(OTRError::ProtocolViolation("Illegal instance tag.")))
    }

    /// `read_data` reads variable-length data from buffer.
    pub fn read_data(&mut self) -> Result<Vec<u8>, OTRError> {
        let len = self.read_int()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let data = Vec::from(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(data)
    }

    /// `read_mpi` reads MPI from buffer.
    pub fn read_mpi(&mut self) -> Result<BigUint, OTRError> {
        let len = self.read_int()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let mpi = BigUint::from_bytes_be(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(mpi)
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

    /// `read_ctr` reads CTR value from buffer.
    pub fn read_ctr(&mut self) -> Result<CTR, OTRError> {
        if self.0.len() < CTR_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut ctr: CTR = [0; CTR_LEN];
        ctr.copy_from_slice(&self.0[..CTR_LEN]);
        self.0 = &self.0[CTR_LEN..];
        Ok(ctr)
    }

    /// `read_mac` reads a MAC value from buffer.
    pub fn read_mac(&mut self) -> Result<MAC, OTRError> {
        if self.0.len() < MAC_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut mac: MAC = [0; MAC_LEN];
        mac.copy_from_slice(&self.0[..MAC_LEN]);
        self.0 = &self.0[MAC_LEN..];
        Ok(mac)
    }

    /// `read_public_key` reads a DSA public key from the buffer.
    pub fn read_public_key(&mut self) -> Result<DSA::PublicKey, OTRError> {
        let pktype = self.read_short()?;
        if pktype != 0u16 {
            return Err(OTRError::ProtocolViolation(
                "Unsupported/invalid public key type.",
            ));
        }
        let p = self.read_mpi()?;
        let q = self.read_mpi()?;
        let g = self.read_mpi()?;
        let y = self.read_mpi()?;
        DSA::PublicKey::from_components(p, q, g, y).map_err(OTRError::CryptographicViolation)
    }

    /// `read_signature` reads a DSA signature (IEEE-P1393 format) from buffer.
    pub fn read_signature(&mut self) -> Result<Signature, OTRError> {
        if self.0.len() < SIGNATURE_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let sig = Signature::from_components(
            BigUint::from_bytes_be(&self.0[..PARAM_Q_LENGTH]),
            BigUint::from_bytes_be(&self.0[PARAM_Q_LENGTH..SIGNATURE_LEN]),
        );
        self.0 = &self.0[SIGNATURE_LEN..];
        Ok(sig)
    }

    pub fn read_tlvs(&mut self) -> Result<Vec<TLV>, OTRError> {
        let mut tlvs = Vec::new();
        while !self.0.is_empty() {
            tlvs.push(self.read_tlv()?);
        }
        Ok(tlvs)
    }

    /// `read_tlv` reads a type-length-value record from the content.
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
    /// `read_bytes_null_terminated` reads bytes until a NULL-byte is found or the buffer is empty.
    /// The NULL-byte is consumed, but will not be returned in the result. If no NULL-byte is
    /// present, read until no more bytes left. Returns all bytes read, except the terminating NULL
    /// if present.
    pub fn read_bytes_null_terminated(&mut self) -> Result<Vec<u8>, OTRError> {
        let mut bytes = Vec::new();
        loop {
            let b = self.read_byte()?;
            if b == b'\0' {
                break;
            }
            bytes.push(b);
        }
        Ok(bytes)
    }
}

// TODO consider moving `OTREncodable` to API, then implementing OTREncodable for crypto::dsa::Signature to further separate dependency on encoding.
pub trait OTREncodable {
    fn encode(&self, encoder: &mut OTREncoder);
}

pub struct OTREncoder {
    buffer: Vec<u8>,
}

impl OTREncoder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn write(&mut self, raw_bytes: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(raw_bytes);
        self
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
        assert!(u32::try_from(v.len()).is_ok());
        self.write_int(v.len() as u32);
        self.buffer.extend_from_slice(v);
        self
    }

    /// Write sequence of MPI values in format defined in SMP: `num_mpis`, `mpi1`, `mpi2`, `...`
    pub fn write_mpi_sequence(&mut self, mpis: &[&BigUint]) -> &mut Self {
        self.write_int(mpis.len() as u32);
        for mpi in mpis {
            self.write_mpi(*mpi);
        }
        self
    }

    pub fn write_mpi(&mut self, v: &BigUint) -> &mut Self {
        // - 4-byte unsigned len, big-endian
        // - <len> byte unsigned value, big-endian
        // (MPIs must use the minimum-length encoding; i.e. no leading 0x00 bytes. This is important when calculating public key fingerprints.)
        // FIXME this is not guaranteed minimum-length encoding, as it is reversed little-endian(???)
        self.write_data(&v.to_bytes_be())
    }

    pub fn write_ctr(&mut self, v: &CTR) -> &mut Self {
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_mac(&mut self, v: &MAC) -> &mut Self {
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_public_key(&mut self, key: &DSA::PublicKey) -> &mut Self {
        self.write_short(0)
            .write_mpi(key.p())
            .write_mpi(key.q())
            .write_mpi(key.g())
            .write_mpi(key.y())
    }

    pub fn write_signature(&mut self, sig: &Signature) -> &mut Self {
        // sig = [u8;20] ++ [u8;20] = r ++ s = 2 * SIGNATURE_PARAM_Q_LEN
        self.buffer.extend_from_slice(&sig.r().to_bytes_be());
        self.buffer.extend_from_slice(&sig.s().to_bytes_be());
        // TODO ensure {r(),s()}.to_bytes_be() always produce 20 bytes.
        assert_eq!(self.buffer.len(), 2 * PARAM_Q_LENGTH);
        self
    }

    pub fn write_tlv(&mut self, tlv: TLV) -> &mut Self {
        assert!(u16::try_from(tlv.1.len()).is_ok());
        self.write_short(tlv.0).write_short(tlv.1.len() as u16);
        self.buffer.extend(tlv.1);
        self
    }

    pub fn write_bytes_null_terminated(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(data);
        self.buffer.push(0u8);
        self
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.clone()
    }
}

fn encode_base64(content: &[u8]) -> Vec<u8> {
    base64::encode(&content).into_bytes()
}

fn decode_base64(content: &[u8]) -> Result<Vec<u8>, OTRError> {
    base64::decode(content).or(Err(OTRError::ProtocolViolation(
        "Invalid message content: content cannot be decoded from base64.",
    )))
}

// TODO how can I initialize arrays using their type aliases, such that I don't have to repeat the size?
/// CTR type represents the first half of the counter value used for encryption, which is transmitted between communicating parties.
pub const CTR_LEN: usize = 8;
pub type CTR = [u8; CTR_LEN];

/// MAC type represents the 20-byte MAC value.
pub const MAC_LEN: usize = 20;
pub type MAC = [u8; MAC_LEN];

pub const FINGERPRINT_LEN: usize = 20;
pub type Fingerprint = [u8; FINGERPRINT_LEN];

const SSID_LEN: usize = 8;
pub type SSID = [u8; SSID_LEN];

#[derive(Debug)]
pub struct TLV(pub TLVType, pub Vec<u8>);

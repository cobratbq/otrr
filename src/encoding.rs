// SPDX-License-Identifier: LGPL-3.0-only

#![allow(clippy::trivially_copy_pass_by_ref)]

use std::convert::TryInto;

use bitflags::bitflags;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::{
    crypto::{aes128, dsa::Signature},
    crypto::{dsa, ed448},
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

const OTR_USE_INFORMATION_MESSAGE: &[u8] = b"An Off-The-Record conversation has been requested.";

const WHITESPACE_PREFIX: &[u8] = b" \t  \t\t\t\t \t \t \t  ";
const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";
const WHITESPACE_TAG_OTRV4: &[u8] = b"  \t\t \t  ";

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
    let data = base64_decode(data)?;
    let mut decoder = OTRDecoder(&data);
    let version: Version = match decoder.read_u16()? {
        0u16 => {
            return Err(OTRError::ProtocolViolation(
                "A protocol version must be provided.",
            ))
        }
        3u16 => Version::V3,
        version => return Err(OTRError::UnsupportedVersion(version)),
    };
    let message_type = decoder.read_u8()?;
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
) -> Result<EncodedMessageType, OTRError> {
    match message_type {
        OTR_DH_COMMIT_TYPE_CODE => Ok(EncodedMessageType::DHCommit(DHCommitMessage::decode(
            &mut decoder,
        )?)),
        OTR_DH_KEY_TYPE_CODE => Ok(EncodedMessageType::DHKey(DHKeyMessage::decode(
            &mut decoder,
        )?)),
        OTR_REVEAL_SIGNATURE_TYPE_CODE => Ok(EncodedMessageType::RevealSignature(
            RevealSignatureMessage::decode(&mut decoder)?,
        )),
        OTR_SIGNATURE_TYPE_CODE => Ok(EncodedMessageType::Signature(SignatureMessage::decode(
            &mut decoder,
        )?)),
        OTR_DATA_TYPE_CODE => Ok(EncodedMessageType::Data(DataMessage::decode(&mut decoder)?)),
        _ => Err(OTRError::ProtocolViolation(
            "Invalid or unknown message type.",
        )),
    }
}

fn parse_plain_message(data: &[u8]) -> MessageType {
    if data.starts_with(OTR_ERROR_PREFIX) {
        // `?OTR Error:` prefix must start at beginning of message to avoid people messing with OTR
        // in normal plaintext messages.
        return MessageType::Error(Vec::from(&data[OTR_ERROR_PREFIX.len()..]));
    }
    if let Some(caps) = (*QUERY_PATTERN).captures(data) {
        let versions = caps
            .get(QUERY_GROUP_VERSIONS)
            .expect("BUG: hard-coded regex should contain capture group for versions");
        return MessageType::Query(
            versions
                .as_bytes()
                .iter()
                .map(|v| {
                    match v {
                        // TODO '1' is not actually an allowed version according to OTR, as there is a different form to express version 1.
                        // '1' is not actually allowed according to OTR-spec. (illegal)
                        // (The pattern ignores the original format for v1.)
                        b'1' => Version::Unsupported(1u16),
                        b'2' => Version::Unsupported(2u16),
                        b'3' => Version::V3,
                        b'4' => Version::V4,
                        // NOTE to use `u16::MAX` is a bit arbitrary. I wanted to choose a value
                        // that would clearly stand out and not accidentally match on anything
                        // significant. I did not want to copy the original byte, as there are bytes
                        // that would accidentally map on a valid value.
                        _ => Version::Unsupported(u16::MAX),
                    }
                })
                .filter(|v| match v {
                    Version::V3 => true,
                    Version::V4 => true,
                    Version::Unsupported(_) | Version::None => false,
                })
                .collect(),
        );
    }
    if let Some(caps) = (*WHITESPACE_PATTERN).captures(data) {
        let cleaned = (*WHITESPACE_PATTERN)
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
            WHITESPACE_TAG_OTRV1 => result.push(Version::Unsupported(1)),
            WHITESPACE_TAG_OTRV2 => result.push(Version::Unsupported(2)),
            WHITESPACE_TAG_OTRV3 => result.push(Version::V3),
            _ => { /* ignore unknown tags */ }
        }
    }
    result
}

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
    pub message: EncodedMessageType,
}

impl OTREncodable for EncodedMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_u16(encode_version(&self.version))
            .write_u8(match self.message {
                EncodedMessageType::Unencoded(_) => panic!(
                    "BUG: 'Unencoded' message-type must be reprocessed. It cannot be sent as-is."
                ),
                EncodedMessageType::DHCommit(_) => OTR_DH_COMMIT_TYPE_CODE,
                EncodedMessageType::DHKey(_) => OTR_DH_KEY_TYPE_CODE,
                EncodedMessageType::RevealSignature(_) => OTR_REVEAL_SIGNATURE_TYPE_CODE,
                EncodedMessageType::Signature(_) => OTR_SIGNATURE_TYPE_CODE,
                EncodedMessageType::Data(_) => OTR_DATA_TYPE_CODE,
            })
            .write_u32(self.sender)
            .write_u32(self.receiver)
            .write_encodable(match &self.message {
                EncodedMessageType::Unencoded(_) => panic!(
                    "BUG: 'Unencoded' message-type must be reprocessed. It cannot be sent as-is."
                ),
                EncodedMessageType::DHCommit(msg) => msg,
                EncodedMessageType::DHKey(msg) => msg,
                EncodedMessageType::RevealSignature(msg) => msg,
                EncodedMessageType::Signature(msg) => msg,
                EncodedMessageType::Data(msg) => msg,
            });
    }
}

/// OTR-message represents all of the existing OTR-encoded message structures in use by OTR.
pub enum EncodedMessageType {
    /// `Unencoded` message type. This is a special case, typically used as an indicator that the
    /// content is not any one of the standard OTR-encoded message-types. Possibly a
    /// plaintext-message or a (partial) body in a Query message.
    Unencoded(Vec<u8>),
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

#[derive(Clone)]
pub struct RevealSignatureMessage {
    pub key: aes128::Key,
    pub signature_encrypted: Vec<u8>,
    pub signature_mac: MAC,
}

impl Drop for RevealSignatureMessage {
    fn drop(&mut self) {
        self.signature_encrypted.fill(0);
        self.signature_mac.fill(0);
    }
}

impl RevealSignatureMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<RevealSignatureMessage, OTRError> {
        Ok(RevealSignatureMessage {
            key: aes128::Key(decoder.read_data()?.try_into().or(Err(
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
        Ok(DataMessage {
            flags: MessageFlags::from_bits(decoder.read_u8()?)
                .ok_or(OTRError::ProtocolViolation("Invalid message flags"))?,
            sender_keyid: utils::u32::nonzero(decoder.read_u32()?)
                .ok_or(OTRError::ProtocolViolation("Invalid KeyID: cannot be 0"))?,
            receiver_keyid: utils::u32::nonzero(decoder.read_u32()?)
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
            .write_u8(self.flags.bits())
            .write_u32(self.sender_keyid)
            .write_u32(self.receiver_keyid)
            .write_mpi(&self.dh_y)
            .write_ctr(&self.ctr)
            .write_data(&self.encrypted)
            .write_mac(&self.authenticator)
            .write_data(&self.revealed);
    }
}

pub fn encode_message(
    version: Version,
    sender: InstanceTag,
    receiver: InstanceTag,
    message: EncodedMessageType,
) -> Vec<u8> {
    serialize_message(&MessageType::Encoded(EncodedMessage {
        version,
        sender,
        receiver,
        message,
    }))
}

/// `serialize_message` (straight-forwardly) serializes provided message into a byte-sequence.
pub fn serialize_message(msg: &MessageType) -> Vec<u8> {
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
            buffer.extend_from_slice(WHITESPACE_PREFIX);
            for v in utils::alloc::vec_unique(versions.clone()) {
                match v {
                    Version::None => panic!("BUG: version 0 cannot be used for tagging"),
                    Version::V3 => buffer.extend_from_slice(WHITESPACE_TAG_OTRV3),
                    Version::V4 => buffer.extend_from_slice(WHITESPACE_TAG_OTRV4),
                    Version::Unsupported(_) => {
                        panic!("BUG: unsupported versions should be avoided.")
                    }
                }
            }
            assert!(
                buffer.len() >= 24,
                "OTR requires at least one protocol version tag."
            );
            buffer.extend(message);
            buffer
        }
        MessageType::Query(versions) => {
            assert!(!versions.is_empty());
            // NOTE: each version listed at most once, in arbitrary order.
            // (Version 1 has deviating syntax but is no longer supported.)
            buffer.extend_from_slice(OTR_QUERY_PREFIX);
            for v in utils::alloc::vec_unique(versions.clone()) {
                match v {
                    Version::None => panic!("BUG: version 0 cannot be used for query messages"),
                    Version::V3 => buffer.push(b'3'),
                    Version::V4 => buffer.push(b'4'),
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
            buffer.extend(base64_encode(
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
        .write_u16(encode_version(version))
        .write_u8(OTR_DATA_TYPE_CODE)
        .write_u32(sender)
        .write_u32(receiver)
        .write_u8(message.flags.bits())
        .write_u32(message.sender_keyid)
        .write_u32(message.receiver_keyid)
        .write_mpi(&message.dh_y)
        .write_ctr(&message.ctr)
        .write_data(&message.encrypted)
        .to_vec()
}

fn encode_version(version: &Version) -> u16 {
    match version {
        Version::None => 0,
        Version::V3 => 3,
        Version::V4 => 4,
        Version::Unsupported(_) => panic!("BUG: unsupported version"),
    }
}

pub struct OTRDecoder<'a>(&'a [u8]);

impl Drop for OTRDecoder<'_> {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // After having finished using the OTRDecoder, verify that the buffer is fully drained.
            // If the buffer is not fully drained, this may indicate that somewhere in the
            // implementation we went wrong, resulting in incomplete work. Or, alternatively, the
            // input data, that originated from the other party, does not confirm to the protocol.
            log::warn!("unread bytes remaining in buffer");
        }
    }
}

/// `OTRDecoder` contains the logic for reading entries from byte-buffer.
///
/// The `OTRDecoder` is construct to assume that any read can fail due to unexpected EOL or
/// unexpected data. The input cannot be trusted, so we try to handle everything as an Err-result.
impl<'a> OTRDecoder<'a> {
    pub fn new(content: &'a [u8]) -> Self {
        Self(content)
    }

    /// `read_byte` reads a single byte from buffer.
    pub fn read_u8(&mut self) -> Result<u8, OTRError> {
        log::trace!("read byte");
        if self.0.is_empty() {
            return Err(OTRError::IncompleteMessage);
        }
        let value = self.0[0];
        self.0 = &self.0[1..];
        Ok(value)
    }

    /// `read_short` reads a short value (2 bytes, big-endian) from buffer.
    pub fn read_u16(&mut self) -> Result<u16, OTRError> {
        log::trace!("read short");
        if self.0.len() < 2 {
            return Err(OTRError::IncompleteMessage);
        }
        let value = (u16::from(self.0[0]) << 8) + u16::from(self.0[1]);
        self.0 = &self.0[2..];
        Ok(value)
    }

    /// `read_int` reads an integer value (4 bytes, big-endian) from buffer.
    pub fn read_u32(&mut self) -> Result<u32, OTRError> {
        log::trace!("read int");
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

    pub fn read_i64(&mut self) -> Result<i64, OTRError> {
        let bytes = self.read(8)?;
        assert_eq!(8, bytes.len());
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn read_instance_tag(&mut self) -> Result<InstanceTag, OTRError> {
        log::trace!("read instance tag");
        verify_instance_tag(self.read_u32()?)
            .or(Err(OTRError::ProtocolViolation("Illegal instance tag.")))
    }

    /// `read_data` reads variable-length data from buffer.
    pub fn read_data(&mut self) -> Result<Vec<u8>, OTRError> {
        log::trace!("read DATA");
        let len = self.read_u32()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let mut data = Vec::with_capacity(len);
        self.transfer(len, &mut data);
        Ok(data)
    }

    /// `read_mpi` reads MPI from buffer.
    pub fn read_mpi(&mut self) -> Result<BigUint, OTRError> {
        log::trace!("read MPI");
        let len = self.read_u32()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let mpi = BigUint::from_bytes_be(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(mpi)
    }

    /// Read sequence of MPI values as defined by SMP.
    pub fn read_mpi_sequence(&mut self) -> Result<Vec<BigUint>, OTRError> {
        log::trace!("read sequence of MPIs");
        let len = self.read_u32()? as usize;
        let mut mpis = Vec::new();
        for _ in 0..len {
            mpis.push(self.read_mpi()?);
        }
        Ok(mpis)
    }

    /// `read_ctr` reads CTR value from buffer.
    pub fn read_ctr(&mut self) -> Result<CTR, OTRError> {
        log::trace!("read CTR");
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
        log::trace!("read MAC");
        if self.0.len() < MAC_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        let mut mac: MAC = [0; MAC_LEN];
        mac.copy_from_slice(&self.0[..MAC_LEN]);
        self.0 = &self.0[MAC_LEN..];
        Ok(mac)
    }

    /// `read_public_key` reads a DSA public key from the buffer.
    pub fn read_public_key(&mut self) -> Result<dsa::PublicKey, OTRError> {
        log::trace!("read DSA public key");
        let pktype = self.read_u16()?;
        if pktype != 0u16 {
            return Err(OTRError::ProtocolViolation(
                "Unsupported/invalid public key type.",
            ));
        }
        let p = self.read_mpi()?;
        let q = self.read_mpi()?;
        let g = self.read_mpi()?;
        let y = self.read_mpi()?;
        dsa::PublicKey::from_components(p, q, g, y).map_err(OTRError::CryptographicViolation)
    }

    /// `read_signature` reads a DSA signature (IEEE-P1393 format) from buffer.
    pub fn read_dsa_signature(&mut self) -> Result<Signature, OTRError> {
        const SIGNATURE_LEN: usize = Signature::size();
        const PARAM_LEN: usize = Signature::parameter_size();
        log::trace!("read signature");
        if self.0.len() < Signature::size() {
            return Err(OTRError::IncompleteMessage);
        }
        let sig = Signature::from_components(
            BigUint::from_bytes_be(&self.0[..PARAM_LEN]),
            BigUint::from_bytes_be(&self.0[PARAM_LEN..SIGNATURE_LEN]),
        );
        self.0 = &self.0[SIGNATURE_LEN..];
        Ok(sig)
    }

    pub fn read_tlvs(&mut self) -> Result<Vec<TLV>, OTRError> {
        log::trace!("read all TLVs");
        let mut tlvs = Vec::new();
        while !self.0.is_empty() {
            tlvs.push(self.read_tlv()?);
        }
        Ok(tlvs)
    }

    /// `read_tlv` reads a type-length-value record from the content.
    pub fn read_tlv(&mut self) -> Result<TLV, OTRError> {
        log::trace!("read TLV");
        let typ = self.read_u16()?;
        let len = self.read_u16()? as usize;
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let mut data = Vec::with_capacity(len);
        self.transfer(len, &mut data);
        Ok(TLV(typ, data))
    }
    /// `read_bytes_null_terminated` reads bytes until a NULL-byte is found or the buffer is empty.
    /// The NULL-byte is consumed, but will not be returned in the result. If no NULL-byte is
    /// present, read until no more bytes left. Returns all bytes read, except the terminating NULL
    /// if present.
    pub fn read_bytes_null_terminated(&mut self) -> Vec<u8> {
        log::trace!("read until null-terminated or empty");
        let mut bytes = Vec::new();
        for i in 0..self.0.len() {
            if self.0[i] == 0 {
                self.transfer(i, &mut bytes);
                self.0 = &self.0[1..];
                return bytes;
            }
        }
        self.transfer(self.0.len(), &mut bytes);
        bytes
    }

    pub fn read_ed448_signature(&mut self) -> Result<ed448::Signature, OTRError> {
        const LENGTH: usize = 114;
        Ok(ed448::Signature::from(self.read(LENGTH)?))
    }

    pub fn read_ed448_public_key(&mut self) -> Result<ed448::PublicKey, OTRError> {
        const LENGTH: usize = 57;
        Ok(ed448::PublicKey::from(self.read(LENGTH)?))
    }

    fn read(&mut self, n: usize) -> Result<Vec<u8>, OTRError> {
        if self.0.len() < n {
            return Err(OTRError::IncompleteMessage);
        }
        let mut buffer = Vec::with_capacity(n);
        self.transfer(n, &mut buffer);
        Ok(buffer)
    }

    fn transfer(&mut self, n: usize, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
    }

    /// `done` can be used to express the end of decoding. The instance is consumed.
    /// NOTE during clean-up we verify if the buffer is fully drained.
    pub fn done(self) -> Result<(), OTRError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(OTRError::ProtocolViolation("data remaining in buffer"))
        }
    }
}

pub trait OTREncodable {
    fn encode(&self, encoder: &mut OTREncoder);
}

pub struct OTREncoder {
    buffer: Vec<u8>,
}

// TODO change API to accept references to primitive types? (See e.g. clientprofile expiration)
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

    pub fn write_u8(&mut self, v: u8) -> &mut Self {
        self.buffer.push(v);
        self
    }

    pub fn write_u16(&mut self, v: u16) -> &mut Self {
        let b = v.to_be_bytes();
        self.buffer.push(b[0]);
        self.buffer.push(b[1]);
        self
    }

    pub fn write_u32(&mut self, v: u32) -> &mut Self {
        let b = v.to_be_bytes();
        self.buffer.push(b[0]);
        self.buffer.push(b[1]);
        self.buffer.push(b[2]);
        self.buffer.push(b[3]);
        self
    }

    pub fn write_i64(&mut self, v: i64) -> &mut Self {
        let bytes: [u8; 8] = v.to_be_bytes();
        self.buffer.extend_from_slice(&bytes);
        self
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_data(&mut self, v: &[u8]) -> &mut Self {
        assert!(u32::try_from(v.len()).is_ok());
        self.write_u32(v.len() as u32);
        self.buffer.extend_from_slice(v);
        self
    }

    /// Write sequence of MPI values in format defined in SMP: `num_mpis`, `mpi1`, `mpi2`, `...`
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_mpi_sequence(&mut self, mpis: &[&BigUint]) -> &mut Self {
        self.write_u32(mpis.len() as u32);
        for mpi in mpis {
            self.write_mpi(mpi);
        }
        self
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_mpi(&mut self, v: &BigUint) -> &mut Self {
        // - 4-byte unsigned len, big-endian
        // - <len> byte unsigned value, big-endian
        // (MPIs must use the minimum-length encoding; i.e. no leading 0x00 bytes. This is important when calculating public key fingerprints.)
        let encoded = v.to_bytes_be();
        assert_ne!(
            0, encoded[0],
            "Assertion checking for minimum-length encoding has failed."
        );
        self.write_u32(encoded.len() as u32);
        self.write(&encoded)
    }

    pub fn write_ctr(&mut self, v: &CTR) -> &mut Self {
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_mac(&mut self, v: &MAC) -> &mut Self {
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_public_key(&mut self, key: &dsa::PublicKey) -> &mut Self {
        self.write_u16(0)
            .write_mpi(key.p())
            .write_mpi(key.q())
            .write_mpi(key.g())
            .write_mpi(key.y())
    }

    pub fn write_signature(&mut self, sig: &Signature) -> &mut Self {
        const PARAM_LEN: usize = Signature::parameter_size();
        const SIGNATURE_LEN: usize = Signature::size();
        // sig = [u8;20] ++ [u8;20] = r ++ s = 2 * SIGNATURE_PARAM_LEN
        let startlen = self.buffer.len();
        self.buffer
            .extend_from_slice(&utils::biguint::to_bytes_be_fixed::<PARAM_LEN>(sig.r()));
        assert_eq!(PARAM_LEN, self.buffer.len() - startlen);
        self.buffer
            .extend_from_slice(&utils::biguint::to_bytes_be_fixed::<PARAM_LEN>(sig.s()));
        assert_eq!(SIGNATURE_LEN, self.buffer.len() - startlen);
        self
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_tlv(&mut self, tlv: &TLV) -> &mut Self {
        assert!(u16::try_from(tlv.1.len()).is_ok());
        self.write_u16(tlv.0).write_u16(tlv.1.len() as u16);
        self.buffer.extend(&tlv.1);
        self
    }

    pub fn write_bytes_null_terminated(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(data);
        self.buffer.push(0u8);
        self
    }

    pub fn write_ed448_public_key(&mut self, pk: &ed448::PublicKey) -> &mut Self {
        todo!("Implement ED448 public key encoding")
    }

    pub fn write_ed448_signature(&mut self, sig: &ed448::Signature) -> &mut Self {
        todo!("Implement ED448 signature encoding")
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.clone()
    }
}

fn base64_encode(content: &[u8]) -> Vec<u8> {
    base64::encode(content).into_bytes()
}

fn base64_decode(content: &[u8]) -> Result<Vec<u8>, OTRError> {
    base64::decode(content).or(Err(OTRError::ProtocolViolation(
        "Invalid message content: content cannot be decoded from base64.",
    )))
}

/// CTR type represents the first half of the counter value used for encryption, which is transmitted between communicating parties.
pub const CTR_LEN: usize = 8;
#[allow(clippy::upper_case_acronyms)]
pub type CTR = [u8; CTR_LEN];

/// MAC type represents the 20-byte MAC value.
pub const MAC_LEN: usize = 20;
#[allow(clippy::upper_case_acronyms)]
pub type MAC = [u8; MAC_LEN];

pub const FINGERPRINT_LEN: usize = 20;
pub type Fingerprint = [u8; FINGERPRINT_LEN];

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub struct TLV(pub TLVType, pub Vec<u8>);

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use num_bigint::BigUint;

    use crate::{encoding::TLV, utils};

    use super::{OTRDecoder, OTREncoder};

    #[test]
    fn test_consume_empty() {
        OTRDecoder::new(&[]).done().unwrap();
    }

    #[test]
    fn test_read_all_data_types_from_empty_buffer() {
        // This is a poor man's boundary test, as we don't try the actual boundary with only 1 byte
        // of data short, but at least it is something.
        let mut decoder = OTRDecoder::new(&[]);
        assert!(decoder.read_u8().is_err());
        assert!(decoder.read_bytes_null_terminated().is_empty());
        assert!(decoder.read_ctr().is_err());
        assert!(decoder.read_data().is_err());
        assert!(decoder.read_instance_tag().is_err());
        assert!(decoder.read_u32().is_err());
        assert!(decoder.read_mac().is_err());
        assert!(decoder.read_mpi().is_err());
        assert!(decoder.read_mpi_sequence().is_err());
        assert!(decoder.read_public_key().is_err());
        assert!(decoder.read_u16().is_err());
        assert!(decoder.read_dsa_signature().is_err());
        assert!(decoder.read_tlv().is_err());
        assert!(decoder.read_tlvs().unwrap().is_empty());
        assert!(decoder.done().is_ok());
    }

    #[test]
    fn test_consume_partial_buffer() {
        assert!(OTRDecoder::new(b"Hello world").done().is_err());
    }

    #[test]
    fn test_decode_encoded_static_case_1() {
        let tlv = TLV(666, Vec::from("This is content of the TLV payload"));
        let mpi = BigUint::from(123_456_789_009_876_543_211_234_567_890_u128);
        let buffer = OTREncoder::new()
            .write_u8(12)
            .write_u16(666)
            .write_u32(99999)
            .write_ctr(&[7u8; 8])
            .write_bytes_null_terminated(b"Hello world, how are you today?")
            .write_data(b"Another string of data, this time stored using the DATA format")
            .write_tlv(&tlv)
            .write_mpi(&mpi)
            .to_vec();
        let mut decoder = OTRDecoder::new(&buffer);
        assert_eq!(12, decoder.read_u8().unwrap());
        assert_eq!(666, decoder.read_u16().unwrap());
        assert_eq!(99999, decoder.read_u32().unwrap());
        assert_eq!([7u8; 8], decoder.read_ctr().unwrap());
        assert_eq!(
            Ordering::Equal,
            utils::bytes::cmp(
                b"Hello world, how are you today?",
                &decoder.read_bytes_null_terminated()
            )
        );
        assert_eq!(
            Ordering::Equal,
            utils::bytes::cmp(
                b"Another string of data, this time stored using the DATA format",
                &decoder.read_data().unwrap()
            )
        );
        assert_eq!(&tlv, &decoder.read_tlv().unwrap());
        assert_eq!(&mpi, &decoder.read_mpi().unwrap());
        decoder.done().unwrap();
    }
}

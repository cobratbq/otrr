// SPDX-License-Identifier: LGPL-3.0-only

use num_bigint::BigUint;
use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::{
    ake,
    crypto::{ed448, otr4},
    dake,
    encoding::{MessageFlags, OTRDecoder, OTREncodable, OTREncoder, CTR_LEN, MAC4_LEN, MAC_LEN},
    instancetag::InstanceTag,
    utils, OTRError, Version,
};

const OTR_USE_INFORMATION_MESSAGE: &[u8] = b"An Off-The-Record conversation has been requested.";

const OTR_ERROR_PREFIX: &[u8] = b"?OTR Error:";
const OTR_QUERY_PREFIX: &[u8] = b"?OTRv";
const OTR_ENCODED_PREFIX: &[u8] = b"?OTR:";
const OTR_ENCODED_SUFFIX: &[u8] = b".";

const OTR_DH_COMMIT_TYPE_CODE: u8 = 0x02;
const OTR_DH_KEY_TYPE_CODE: u8 = 0x0a;
const OTR_REVEAL_SIGNATURE_TYPE_CODE: u8 = 0x11;
const OTR_SIGNATURE_TYPE_CODE: u8 = 0x12;
const OTR_IDENTITY_TYPE_CODE: u8 = 0x35;
const OTR_AUTHR_TYPE_CODE: u8 = 0x36;
const OTR_AUTHI_TYPE_CODE: u8 = 0x37;

/// OTR encoded message type code for OTRv2 + OTRv3 + OTRv4 data messages.
const OTR_DATA_TYPE_CODE: u8 = 0x03;

static QUERY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\?OTR\??(:?v(\d*))?\?").expect("BUG: failed to compile hard-coded regex-pattern.")
});
const QUERY_GROUP_VERSIONS: usize = 1;
static WHITESPACE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r" \t  \t\t\t\t \t \t \t  ([ \t]{8})*")
        .expect("BUG: failed to compile hard-coded regex-pattern.")
});
const WHITESPACE_GROUP_TAGS: usize = 1;
const WHITESPACE_PREFIX: &[u8] = b" \t  \t\t\t\t \t \t \t  ";
const WHITESPACE_TAG_OTRV1: &[u8] = b" \t \t  \t ";
const WHITESPACE_TAG_OTRV2: &[u8] = b"  \t\t  \t ";
const WHITESPACE_TAG_OTRV3: &[u8] = b"  \t\t  \t\t";
const WHITESPACE_TAG_OTRV4: &[u8] = b"  \t\t \t  ";

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
    let data = base64::decode(data).or(Err(OTRError::ProtocolViolation(
        "Invalid message content: content cannot be decoded from base64.",
    )))?;
    let mut decoder = OTRDecoder::new(&data);
    let version: Version = match decoder.read_u16()? {
        0u16 => {
            return Err(OTRError::ProtocolViolation(
                "A protocol version must be provided.",
            ))
        }
        3u16 => Version::V3,
        4u16 => Version::V4,
        version => return Err(OTRError::UnsupportedVersion(version)),
    };
    let message_type = decoder.read_u8()?;
    let sender: InstanceTag = decoder.read_instance_tag()?;
    let receiver: InstanceTag = decoder.read_instance_tag()?;
    let encoded = parse_encoded_content(&version, message_type, &mut decoder)?;
    decoder.done()?;
    Result::Ok(MessageType::Encoded(EncodedMessage {
        version,
        sender,
        receiver,
        message: encoded,
    }))
}

fn parse_encoded_content(
    version: &Version,
    message_type: u8,
    decoder: &mut OTRDecoder,
) -> Result<EncodedMessageType, OTRError> {
    match (version, message_type) {
        (Version::V3, typecode) if typecode == OTR_DH_COMMIT_TYPE_CODE => Ok(
            EncodedMessageType::DHCommit(ake::DHCommitMessage::decode(decoder)?),
        ),
        (Version::V3, typecode) if typecode == OTR_DH_KEY_TYPE_CODE => Ok(
            EncodedMessageType::DHKey(ake::DHKeyMessage::decode(decoder)?),
        ),
        (Version::V3, typecode) if typecode == OTR_REVEAL_SIGNATURE_TYPE_CODE => Ok(
            EncodedMessageType::RevealSignature(ake::RevealSignatureMessage::decode(decoder)?),
        ),
        (Version::V3, typecode) if typecode == OTR_SIGNATURE_TYPE_CODE => Ok(
            EncodedMessageType::Signature(ake::SignatureMessage::decode(decoder)?),
        ),
        (Version::V3, typecode) if typecode == OTR_DATA_TYPE_CODE => {
            Ok(EncodedMessageType::Data(DataMessage::decode(decoder)?))
        }
        (Version::V4, typecode) if typecode == OTR_IDENTITY_TYPE_CODE => Ok(
            EncodedMessageType::Identity(dake::IdentityMessage::decode(decoder)?),
        ),
        (Version::V4, typecode) if typecode == OTR_AUTHR_TYPE_CODE => Ok(
            EncodedMessageType::AuthR(dake::AuthRMessage::decode(decoder)?),
        ),
        (Version::V4, typecode) if typecode == OTR_AUTHI_TYPE_CODE => Ok(
            EncodedMessageType::AuthI(dake::AuthIMessage::decode(decoder)?),
        ),
        (Version::V4, typecode) if typecode == OTR_DATA_TYPE_CODE => {
            Ok(EncodedMessageType::Data4(DataMessage4::decode(decoder)?))
        }
        _ => Err(OTRError::ProtocolViolation(
            "Invalid or unknown message type, or incorrect protocol version for message type.",
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
                    Version::V3 | Version::V4 => true,
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
            WHITESPACE_TAG_OTRV4 => result.push(Version::V4),
            _ => { /* ignore unknown tags */ }
        }
    }
    result
}

// TODO eventually, re-evaluate issue w.r.t. large-enum-variant static analysis issue
#[allow(clippy::large_enum_variant)]
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
                EncodedMessageType::Identity(_) => OTR_IDENTITY_TYPE_CODE,
                EncodedMessageType::AuthR(_) => OTR_AUTHR_TYPE_CODE,
                EncodedMessageType::AuthI(_) => OTR_AUTHI_TYPE_CODE,
                EncodedMessageType::Data(_) | EncodedMessageType::Data4(_) => OTR_DATA_TYPE_CODE,
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
                EncodedMessageType::Identity(msg) => msg,
                EncodedMessageType::AuthR(msg) => msg,
                EncodedMessageType::AuthI(msg) => msg,
                EncodedMessageType::Data4(msg) => msg,
            });
    }
}

/// OTR-message represents all of the existing OTR-encoded message structures in use by OTR.
#[allow(clippy::large_enum_variant)]
pub enum EncodedMessageType {
    /// `Unencoded` message type. This is a special case, typically used as an indicator that the
    /// content is not any one of the standard OTR-encoded message-types. Possibly a plain-text
    /// message or a (partial) body in a Query message.
    Unencoded(Vec<u8>),
    /// OTRv2/3 DH-Commit-message in the AKE-process.
    DHCommit(ake::DHCommitMessage),
    /// OTRv2/3 DH-Key-message in the AKE-process.
    DHKey(ake::DHKeyMessage),
    /// OTRv2/3 RevealSignature-message in the AKE-process.
    RevealSignature(ake::RevealSignatureMessage),
    /// OTRv2/3 Signature-message in the AKE-process.
    Signature(ake::SignatureMessage),
    /// OTRv2/3 (Encrypted) data-message.
    Data(DataMessage),
    /// OTRv4 Identity-message in interactive DAKE-process.
    Identity(dake::IdentityMessage),
    /// OTRv4 Auth-R-message in interactive DAKE-process.
    AuthR(dake::AuthRMessage),
    /// OTRv4 Auth-I-message in interactive DAKE-process.
    AuthI(dake::AuthIMessage),
    /// OTRv4 (Encrypted) data-message.
    Data4(DataMessage4),
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
    pub ctr: [u8; CTR_LEN],
    pub encrypted: Vec<u8>,
    pub authenticator: [u8; MAC_LEN],
    /// revealed contains recent keys, previously used for authentication, that should now become public.
    pub revealed: Vec<u8>,
}

// FIXME consider where to define `KeyID`
pub type KeyID = u32;

impl DataMessage {
    fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let flags = MessageFlags::from_bits(decoder.read_u8()?)
            .ok_or(OTRError::ProtocolViolation("Invalid message flags"))?;
        let sender_keyid = utils::u32::nonzero(decoder.read_u32()?)
            .ok_or(OTRError::ProtocolViolation("Invalid KeyID: cannot be 0"))?;
        let receiver_keyid = utils::u32::nonzero(decoder.read_u32()?)
            .ok_or(OTRError::ProtocolViolation("Invalid KeyID: cannot be 0"))?;
        let dh_y = decoder.read_mpi()?;
        let ctr = decoder.read_ctr()?;
        let encrypted = decoder.read_data()?;
        let authenticator = decoder.read_mac()?;
        let revealed = decoder.read_data()?;
        Ok(Self {
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

pub struct DataMessage4 {
    pub flags: MessageFlags,
    pub pn: u32,
    pub i: u32,
    pub j: u32,
    pub ecdh: ed448::Point,
    pub dh: BigUint,
    pub encrypted: Vec<u8>,
    pub authenticator: [u8; MAC4_LEN],
    pub revealed: Vec<u8>,
}

impl DataMessage4 {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let flags = MessageFlags::from_bits(decoder.read_u8()?)
            .ok_or(OTRError::ProtocolViolation("Invalid message flags"))?;
        let pn = decoder.read_u32()?;
        let i = decoder.read_u32()?;
        let j = decoder.read_u32()?;
        let ecdh = decoder.read_ed448_point()?;
        let dh = decoder.read_mpi()?;
        let encrypted = decoder.read_data()?;
        let authenticator = decoder.read_mac4()?;
        let revealed = decoder.read_data()?;
        Ok(Self {
            flags,
            pn,
            i,
            j,
            ecdh,
            dh,
            encrypted,
            authenticator,
            revealed,
        })
    }
}

impl OTREncodable for DataMessage4 {
    fn encode(&self, encoder: &mut OTREncoder) {
        assert_eq!(0, self.revealed.len() % MAC4_LEN);
        encoder
            .write_u8(self.flags.bits())
            .write_u32(self.pn)
            .write_u32(self.i)
            .write_u32(self.j)
            .write_ed448_point(&self.ecdh)
            .write_mpi(&self.dh)
            .write_data(&self.encrypted)
            .write_mac4(&self.authenticator)
            .write_data(&self.revealed);
    }
}

impl DataMessage4 {
    pub fn validate(&self) -> Result<(), OTRError> {
        if self.revealed.len() % otr4::MAC_LENGTH != 0 {
            return Err(OTRError::ProtocolViolation(
                "Revealed MACs data does not have expected length.",
            ));
        }
        // FIXME implement: validation of DataMessage4
        todo!("implement: validation of DataMessage4")
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
            buffer.extend(
                base64::encode(OTREncoder::new().write_encodable(encoded_message).to_vec())
                    .into_bytes(),
            );
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

pub fn encode_authenticator_data4(
    version: &Version,
    sender: InstanceTag,
    receiver: InstanceTag,
    message: &DataMessage4,
) -> Vec<u8> {
    OTREncoder::new()
        .write_u16(encode_version(version))
        .write_u8(OTR_DATA_TYPE_CODE)
        .write_u32(sender)
        .write_u32(receiver)
        .write_u8(message.flags.bits())
        .write_u32(message.pn)
        .write_u32(message.i)
        .write_u32(message.j)
        .write_ed448_point(&message.ecdh)
        .write_mpi(&message.dh)
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

// SPDX-License-Identifier: LGPL-3.0-only

#![allow(clippy::trivially_copy_pass_by_ref)]

use bitflags::bitflags;
use num_bigint::{BigInt, BigUint};

use crate::{
    crypto::{dsa, ed448},
    instancetag::{verify, InstanceTag},
    utils, OTRError, TLVType, SSID,
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

pub struct OTRDecoder<'a>(&'a [u8]);

impl Drop for OTRDecoder<'_> {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // After having finished using the OTRDecoder, verify that the buffer is fully drained.
            // If the buffer is not fully drained, this may indicate that somewhere in the
            // implementation we went wrong, resulting in incomplete work. Or, alternatively, the
            // input data, that originated from the other party, does not confirm to the protocol.
            log::warn!("{} unread bytes left in discarded buffer", self.0.len());
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

    pub fn available(&self) -> usize {
        self.0.len()
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

    /// `read_short_le` reads a short value (2 bytes, little-endian) from buffer.
    pub fn read_u16_le(&mut self) -> Result<u16, OTRError> {
        log::trace!("read short (little-endian)");
        if self.0.len() < 2 {
            return Err(OTRError::IncompleteMessage);
        }
        let value = (u16::from(self.0[1]) << 8) + u16::from(self.0[0]);
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
        log::trace!("read int (64-bit, signed)");
        Ok(i64::from_be_bytes(self.read::<8>()?))
    }

    pub fn read_instance_tag(&mut self) -> Result<InstanceTag, OTRError> {
        log::trace!("decode instance tag");
        verify(self.read_u32()?).or(Err(OTRError::ProtocolViolation("Illegal instance tag.")))
    }

    /// `read_data` reads variable-length data from buffer.
    pub fn read_data(&mut self) -> Result<Vec<u8>, OTRError> {
        log::trace!("decode DATA");
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
        log::trace!("decode MPI");
        let len = self.read_u32()? as usize;
        if len == 0 {
            // zero-length MPI is `0`, hence no bytes need reading
            return Ok((*utils::biguint::ZERO).clone());
        }
        if self.0.len() < len {
            return Err(OTRError::IncompleteMessage);
        }
        let mpi = BigUint::from_bytes_be(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(mpi)
    }

    /// Read sequence of MPI values as defined by SMP.
    pub fn read_mpi_sequence(&mut self) -> Result<Vec<BigUint>, OTRError> {
        log::trace!("decode sequence of MPIs");
        let len = self.read_u32()? as usize;
        let mut mpis = Vec::new();
        for _ in 0..len {
            mpis.push(self.read_mpi()?);
        }
        Ok(mpis)
    }

    /// `read_ctr` reads CTR value from buffer.
    pub fn read_ctr(&mut self) -> Result<[u8; CTR_LEN], OTRError> {
        log::trace!("decode CTR");
        if self.0.len() < CTR_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        self.read::<CTR_LEN>()
    }

    /// `read_mac` reads a MAC value from buffer.
    pub fn read_mac(&mut self) -> Result<[u8; MAC_LEN], OTRError> {
        log::trace!("decode MAC");
        if self.0.len() < MAC_LEN {
            return Err(OTRError::IncompleteMessage);
        }
        self.read::<20>()
    }

    /// `read_public_key` reads a DSA public key from the buffer.
    pub fn read_public_key(&mut self) -> Result<dsa::PublicKey, OTRError> {
        log::trace!("decode DSA public key");
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

    pub fn read_dsa_signature(&mut self) -> Result<dsa::Signature, OTRError> {
        let r = self.read::<20>()?;
        let s = self.read::<20>()?;
        dsa::Signature::from(BigUint::from_bytes_be(&r), BigUint::from_bytes_be(&s))
            .map_err(OTRError::CryptographicViolation)
    }

    pub fn read_tlvs(&mut self) -> Result<Vec<TLV>, OTRError> {
        log::trace!("decode all TLVs");
        let mut tlvs = Vec::new();
        while !self.0.is_empty() {
            tlvs.push(self.read_tlv()?);
        }
        Ok(tlvs)
    }

    /// `read_tlv` reads a type-length-value record from the content.
    pub fn read_tlv(&mut self) -> Result<TLV, OTRError> {
        log::trace!("decode TLV");
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
        log::trace!("decode until null-terminated or empty");
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
        log::trace!("decode Ed448 signature");
        ed448::Signature::decode(self)
    }

    pub fn read_ed448_point(&mut self) -> Result<ed448::Point, OTRError> {
        log::trace!("decode Ed448 point");
        let point =
            ed448::Point::decode(&self.read()?).map_err(OTRError::CryptographicViolation)?;
        // FIXME debugging maybe remove for excess processing
        ed448::verify(&point).map_err(OTRError::CryptographicViolation)?;
        Ok(point)
    }

    pub fn read_ed448_scalar(&mut self) -> Result<BigInt, OTRError> {
        log::trace!("decode Ed448 scalar");
        Ok(ed448::decode_scalar(&self.read()?))
    }

    pub fn read_mac4(&mut self) -> Result<[u8; MAC4_LEN], OTRError> {
        log::trace!("decode OTRv4 MAC");
        self.read()
    }

    pub fn read_nonce(&mut self) -> Result<[u8; NONCE_LEN], OTRError> {
        log::trace!("decode nonce");
        self.read()
    }

    // TODO the copy made here is often unnecessary, i.e. could read/parse directly from buffer self.0
    pub fn read<const N: usize>(&mut self) -> Result<[u8; N], OTRError> {
        log::trace!("read {N} (fixed) bytes");
        if self.0.len() < N {
            return Err(OTRError::IncompleteMessage);
        }
        let mut buffer = [0u8; N];
        buffer.copy_from_slice(&self.0[..N]);
        self.0 = &self.0[N..];
        Ok(buffer)
    }

    fn transfer(&mut self, n: usize, buffer: &mut Vec<u8>) {
        log::trace!("read {n} (variable) bytes");
        buffer.extend_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
    }

    /// `done` can be used to express the end of decoding. The instance is consumed.
    /// Note: during clean-up we verify if the buffer is fully drained.
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

    pub fn write_u16_le(&mut self, v: u16) -> &mut Self {
        let b = v.to_le_bytes();
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
        let bytes: SSID = v.to_be_bytes();
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
        if *v == *utils::biguint::ZERO {
            return self.write_u32(0);
        }
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

    pub fn write_ctr(&mut self, v: &[u8; CTR_LEN]) -> &mut Self {
        self.buffer.extend_from_slice(v);
        self
    }

    pub fn write_mac(&mut self, v: &[u8; MAC_LEN]) -> &mut Self {
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

    pub fn write_ed448_point(&mut self, point: &ed448::Point) -> &mut Self {
        let encoded = point.encode();
        self.buffer.extend_from_slice(&encoded);
        self
    }

    pub fn write_ed448_scalar(&mut self, scalar: &BigInt) -> &mut Self {
        self.buffer.extend_from_slice(
            &utils::bigint::to_bytes_le_fixed::<{ ed448::ENCODED_LENGTH }>(scalar),
        );
        self
    }

    pub fn write_ed448_fingerprint(&mut self, fingerprint: &[u8; 56]) -> &mut Self {
        self.buffer.extend_from_slice(fingerprint);
        self
    }

    pub fn write_mac4(&mut self, mac: &[u8; MAC4_LEN]) -> &mut Self {
        self.buffer.extend_from_slice(mac);
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

/// CTR type represents the first half of the counter value used for encryption, which is transmitted between communicating parties.
pub const CTR_LEN: usize = 8;
/// MAC type represents the 20-byte MAC value.
pub const MAC_LEN: usize = 20;
pub const FINGERPRINT_LEN: usize = 20;

pub const MAC4_LEN: usize = 64;
pub const NONCE_LEN: usize = 12;

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub struct TLV(pub TLVType, pub Vec<u8>);

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

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

    #[test]
    fn test_decoding_random_data() {
        let mut data = [0u8; 3000];
        for _ in 0..20 {
            utils::random::fill_secure_bytes(&mut data);
            // accept successful or unsuccessful reading, just not panicking
            let mut dec = OTRDecoder::new(&data);
            let _ = dec.read_data();
            let _ = dec.read_mpi();
            let _ = dec.read_mpi_sequence();
        }
    }
}

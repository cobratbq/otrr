// SPDX-License-Identifier: LGPL-3.0-only

use crate::{
    crypto::{dsa, ed448},
    encoding::{OTRDecoder, OTREncodable, OTREncoder},
    instancetag::{self, InstanceTag},
    utils, OTRError, Version,
};

// FIXME tag in client profile is possibly different from tag in AccountDetails
pub struct ClientProfile {
    pub owner_tag: InstanceTag,
    pub identity_key: ed448::Point,
    pub forging_key: ed448::Point,
    pub versions: Vec<Version>,
    pub expiration: i64,
    pub legacy_key: Option<dsa::PublicKey>,
}

// TODO consider method for including and signing with legacy DSA public key for transitional signature.
impl ClientProfile {
    /// Construct a new client profile based on user input.
    ///
    /// # Errors
    /// In case of failure to construct a valid profile.
    pub fn new(
        owner_tag: InstanceTag,
        identity_key: ed448::Point,
        forging_key: ed448::Point,
        versions: Vec<Version>,
        expiration: i64,
        legacy_key: Option<dsa::PublicKey>,
    ) -> Result<Self, OTRError> {
        let profile = Self {
            owner_tag,
            identity_key,
            forging_key,
            versions,
            expiration,
            legacy_key,
        };
        Self::validate(&profile)?;
        Ok(profile)
    }

    fn validate(profile: &Self) -> Result<(), OTRError> {
        instancetag::verify(profile.owner_tag)?;
        ed448::verify(&profile.identity_key).map_err(OTRError::CryptographicViolation)?;
        ed448::verify(&profile.forging_key).map_err(OTRError::CryptographicViolation)?;
        verify_versions(&profile.versions)?;
        if profile.expiration < 0
            || u64::try_from(profile.expiration).unwrap() <= utils::time::unix_seconds_now()
        {
            // FIXME we probably need to handle expiry differently
            return Err(OTRError::ProtocolViolation("Expired client profile."));
        }
        Ok(())
    }

    /// `sign` signs a client profile and produces a signed client profile payload.
    ///
    /// # Panics
    /// In case of inproper arguments, such as if identity keypair does not match with
    /// client profile's identity public key.
    #[must_use]
    pub fn sign(
        &self,
        identity_keypair: &ed448::EdDSAKeyPair,
        legacy_keypair: Option<&dsa::Keypair>,
    ) -> ClientProfilePayload {
        assert_eq!(&self.identity_key, identity_keypair.public());
        assert_eq!(self.legacy_key.is_none(), legacy_keypair.is_none());
        // TODO double-check if all validation is necessary.
        let mut fields = vec![
            Field::OwnerTag(self.owner_tag),
            Field::IdentityKey(IdentityKey(self.identity_key.clone())),
            Field::ForgingKey(ForgingKey(self.forging_key.clone())),
            Field::Versions(self.versions.clone()),
            Field::Expiration(self.expiration),
        ];
        // TODO there is a specific order of fields for legacy-key-signing and identity-signing. Right now we take order as received.
        if let Some(public_key) = &self.legacy_key {
            fields.push(Field::LegacyKey(public_key.clone()));
            let mut encoder = OTREncoder::new();
            for f in &fields {
                encoder.write_encodable(f);
            }
            let trans_sig = legacy_keypair.unwrap().sign(&encoder.to_vec());
            fields.push(Field::TransitionalSignature(trans_sig));
        }
        let mut encoder = OTREncoder::new();
        for f in &fields {
            encoder.write_encodable(f);
        }
        let bytes = encoder.to_vec();
        let signature = identity_keypair.sign(&bytes);
        let payload = ClientProfilePayload { fields, signature };
        debug_assert!(payload.validate().is_ok());
        payload
    }
}

#[derive(Clone)]
pub struct ClientProfilePayload {
    fields: Vec<Field>,
    signature: ed448::Signature,
}

impl OTREncodable for ClientProfilePayload {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        encoder.write_u32(u32::try_from(self.fields.len()).unwrap());
        for f in &self.fields {
            encoder.write_encodable(f);
        }
        encoder.write_encodable(&self.signature);
    }
}

impl ClientProfilePayload {
    /// `decode` decodes a client profile payload from OTR-encoded byte-stream.
    ///
    /// # Errors
    /// In case of failure to properly read and decode payload from bytes, or upon failing
    /// validation.
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        log::trace!("decoding client profile payload…");
        let n = decoder.read_u32()? as usize;
        let mut fields = Vec::with_capacity(n);
        for _ in 0..n {
            fields.push(Field::decode(decoder)?);
        }
        let signature = decoder.read_ed448_signature()?;
        let payload = Self { fields, signature };
        log::trace!("decoding client profile payload… validating…");
        payload.validate()?;
        log::trace!("decoding client profile payload… validating… done.");
        Ok(payload)
    }

    /// `validate` validates a client profile payload and returns the client profile with relevant
    /// fields after successful validation.
    ///
    /// # Errors
    /// In case anything does not check out with the client profile.
    ///
    /// # Panics
    /// In case of internal failure or bug.
    // TODO there is a complexity in validating because we need to produce the encoding with fields in the same order as originally received, so we cannot rely on the fields in the data structure.
    // TODO now assumes fields order is reliable for signatures, which is not guaranteed by OTRv4 spec, as there it lists fields explicitly by name.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<ClientProfile, OTRError> {
        log::trace!("validating client profile: collecting fields…");
        let mut owner_tag: Option<InstanceTag> = Option::None;
        let mut identity_key: Option<ed448::Point> = Option::None;
        let mut forging_key: Option<ed448::Point> = Option::None;
        let mut versions: Vec<Version> = Vec::new();
        let mut expiration: Option<i64> = Option::None;
        let mut legacy_key: Option<dsa::PublicKey> = Option::None;
        let mut transitional_signature: Option<dsa::Signature> = Option::None;
        for f in &self.fields {
            match f {
                Field::OwnerTag(tag) => {
                    if owner_tag.replace(*tag).is_some() {
                        return Err(OTRError::ProtocolViolation("Duplicate field: owner tag"));
                    }
                }
                Field::IdentityKey(IdentityKey(public_key)) => {
                    if identity_key.replace(public_key.clone()).is_some() {
                        return Err(OTRError::ProtocolViolation("Duplicate field: identity key"));
                    }
                }
                Field::ForgingKey(ForgingKey(public_key)) => {
                    if forging_key.replace(public_key.clone()).is_some() {
                        return Err(OTRError::ProtocolViolation("Duplicate field: forging key"));
                    }
                }
                Field::Versions(ver) => {
                    if !versions.is_empty() {
                        return Err(OTRError::ProtocolViolation("Duplicate field: versions"));
                    }
                    versions.extend_from_slice(ver);
                }
                Field::Expiration(timestamp) => {
                    if expiration.replace(*timestamp).is_some() {
                        return Err(OTRError::ProtocolViolation(
                            "Duplicate field: expiration timestamp",
                        ));
                    }
                }
                Field::LegacyKey(public_key) => {
                    if legacy_key.replace(public_key.clone()).is_some() {
                        return Err(OTRError::ProtocolViolation(
                            "Duplicate field: legacy public key",
                        ));
                    }
                }
                Field::TransitionalSignature(sig) => {
                    if transitional_signature.replace(sig.clone()).is_some() {
                        return Err(OTRError::ProtocolViolation(
                            "Duplicate field: transitional signature",
                        ));
                    }
                }
            };
        }
        log::trace!("validating client profile: validating signature…");
        if owner_tag.is_none()
            || identity_key.is_none()
            || forging_key.is_none()
            || versions.is_empty()
            || expiration.is_none()
        {
            return Err(OTRError::ProtocolViolation(
                "Required fields missing in client profile payload.",
            ));
        }
        if legacy_key.is_some() != transitional_signature.is_some() {
            return Err(OTRError::ProtocolViolation(
                "The legacy public key requires that a transitional signature is present.",
            ));
        }
        // 1. Verify all profile fields.
        let mut encoder = OTREncoder::new();
        for f in &self.fields {
            encoder.write_encodable(f);
        }
        ed448::validate(
            identity_key.as_ref().unwrap(),
            &self.signature,
            &encoder.to_vec(),
        )
        .map_err(OTRError::CryptographicViolation)?;
        if let Some(legacy_key) = &legacy_key {
            log::trace!("validating client profile: validating transitional signature…");
            assert!(transitional_signature.is_some());
            let mut encoder = OTREncoder::new();
            for f in &self.fields {
                match f {
                    Field::OwnerTag(_)
                    | Field::IdentityKey(_)
                    | Field::ForgingKey(_)
                    | Field::Versions(_)
                    | Field::Expiration(_)
                    | Field::LegacyKey(_) => {
                        encoder.write_encodable(f);
                    }
                    Field::TransitionalSignature(_) => continue,
                }
            }
            legacy_key
                .validate(transitional_signature.as_ref().unwrap(), &encoder.to_vec())
                .map_err(OTRError::CryptographicViolation)?;
        }
        // TODO double-check: there was some mention about transitional signature being optional even in presence of DSA public key(?) Probably requires changes to the code.
        log::trace!("validating client profile: success.");
        Ok(ClientProfile {
            owner_tag: owner_tag.unwrap(),
            identity_key: identity_key.unwrap(),
            forging_key: forging_key.unwrap(),
            versions,
            expiration: expiration.unwrap(),
            legacy_key,
        })
    }
}

#[derive(Clone, Debug)]
enum Field {
    OwnerTag(InstanceTag),
    IdentityKey(IdentityKey),
    ForgingKey(ForgingKey),
    Versions(Vec<Version>),
    Expiration(i64),
    LegacyKey(dsa::PublicKey),
    TransitionalSignature(dsa::Signature),
}

impl OTREncodable for Field {
    fn encode(&self, encoder: &mut OTREncoder) {
        match self {
            Self::OwnerTag(tag) => {
                encoder.write_u16(TYPE_OWNERINSTANCETAG);
                encoder.write_u32(*tag);
            }
            Self::IdentityKey(identity_key) => {
                encoder.write_u16(TYPE_ED448_PUBLIC_KEY);
                encoder.write_encodable(identity_key);
            }
            Self::ForgingKey(forging_key) => {
                encoder.write_u16(TYPE_ED448_FORGING_KEY);
                encoder.write_encodable(forging_key);
            }
            Self::Versions(versions) => {
                encoder.write_u16(TYPE_VERSIONS);
                encoder.write_data(&encode_versions(versions));
            }
            Self::Expiration(timestamp) => {
                encoder.write_u16(TYPE_EXPIRATION);
                encoder.write_i64(*timestamp);
            }
            Self::LegacyKey(public_key) => {
                encoder.write_u16(TYPE_DSA_PUBLIC_KEY);
                encoder.write_public_key(public_key);
            }
            Self::TransitionalSignature(signature) => {
                encoder.write_u16(TYPE_TRANSITIONAL_SIGNATURE);
                encoder.write_encodable(signature);
            }
        }
    }
}

impl Field {
    fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let typ = decoder.read_u16()?;
        match typ {
            TYPE_OWNERINSTANCETAG => Ok(Self::OwnerTag(decoder.read_instance_tag()?)),
            TYPE_ED448_PUBLIC_KEY => Ok(Self::IdentityKey(IdentityKey::decode(decoder)?)),
            TYPE_ED448_FORGING_KEY => Ok(Self::ForgingKey(ForgingKey::decode(decoder)?)),
            TYPE_VERSIONS => Ok(Self::Versions(parse_versions(&decoder.read_data()?))),
            TYPE_EXPIRATION => Ok(Self::Expiration(decoder.read_i64()?)),
            TYPE_DSA_PUBLIC_KEY => Ok(Self::LegacyKey(decoder.read_public_key()?)),
            TYPE_TRANSITIONAL_SIGNATURE => {
                Ok(Self::TransitionalSignature(decoder.read_dsa_signature()?))
            }
            _ => {
                log::info!("Unsupported field type: {:?}", typ);
                Err(OTRError::ProtocolViolation(
                    "Unsupported field type encountered.",
                ))
            }
        }
    }
}

const TYPE_OWNERINSTANCETAG: u16 = 1;
const TYPE_ED448_PUBLIC_KEY: u16 = 2;
const TYPE_ED448_FORGING_KEY: u16 = 3;
const TYPE_VERSIONS: u16 = 4;
const TYPE_EXPIRATION: u16 = 5;
const TYPE_DSA_PUBLIC_KEY: u16 = 6;
const TYPE_TRANSITIONAL_SIGNATURE: u16 = 7;

#[derive(Clone, Debug)]
struct IdentityKey(ed448::Point);

impl OTREncodable for IdentityKey {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        encoder.write_u16_le(Self::PUBKEY_TYPE_ED448_IDENTITY_KEY);
        encoder.write_ed448_point(&self.0);
    }
}

impl IdentityKey {
    const PUBKEY_TYPE_ED448_IDENTITY_KEY: u16 = 0x10;

    /// `decode` decodes a public key from its OTR-encoding.
    ///
    /// # Errors
    /// In case of bad input data.
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        if decoder.read_u16_le()? != Self::PUBKEY_TYPE_ED448_IDENTITY_KEY {
            return Err(OTRError::ProtocolViolation(
                "Expected public key type: 0x0010",
            ));
        }
        Ok(Self(decoder.read_ed448_point()?))
    }
}

// NOTE: there is also the Ed448 Preshared PreKey (type 0x0011). Not yet implemented.

#[derive(Clone, Debug)]
struct ForgingKey(ed448::Point);

impl OTREncodable for ForgingKey {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        encoder.write_u16_le(Self::PUBKEY_TYPE_ED448_FORGING_KEY);
        encoder.write_ed448_point(&self.0);
    }
}

impl ForgingKey {
    const PUBKEY_TYPE_ED448_FORGING_KEY: u16 = 0x12;

    /// `decode` decodes a public key from its OTR-encoding.
    ///
    /// # Errors
    /// In case of bad input data.
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        if decoder.read_u16_le()? != Self::PUBKEY_TYPE_ED448_FORGING_KEY {
            return Err(OTRError::ProtocolViolation(
                "Expected public key type: 0x0012",
            ));
        }
        Ok(Self(decoder.read_ed448_point()?))
    }
}

fn verify_versions(versions: &[Version]) -> Result<(), OTRError> {
    for v in versions {
        match v {
            Version::V3 | Version::V4 => continue,
            Version::None | Version::Unsupported(_) => {
                return Err(OTRError::ProtocolViolation("Illegal version encountered."))
            }
        }
    }
    Ok(())
}

fn parse_versions(data: &[u8]) -> Vec<Version> {
    let mut versions = Vec::<Version>::new();
    for c in data {
        versions.push(match *c {
            b'3' => Version::V3,
            b'4' => Version::V4,
            _ => continue,
        });
    }
    versions
}

fn encode_versions(versions: &[Version]) -> Vec<u8> {
    let mut data = Vec::<u8>::new();
    for v in versions {
        data.push(match v {
            Version::V3 => b'3',
            Version::V4 => b'4',
            _ => panic!("Illegal version"),
        });
    }
    data
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{self, dsa, ed448},
        encoding::{OTRDecoder, OTREncoder},
        Version,
    };

    use super::{ClientProfile, ClientProfilePayload, Field, ForgingKey, IdentityKey};

    #[test]
    fn test_encode_decode_clientprofile() {
        let identity = ed448::EdDSAKeyPair::generate();
        let forging = ed448::EdDSAKeyPair::generate();
        let profile = ClientProfile::new(
            0x0fff_ffff,
            identity.public().clone(),
            forging.public().clone(),
            vec![Version::V4],
            0x7fff_ffff,
            None,
        )
        .unwrap();
        let payload = profile.sign(&identity, None);
        let encoded = OTREncoder::new().write_encodable(&payload).to_vec();
        let decoded = ClientProfilePayload::decode(&mut OTRDecoder::new(&encoded)).unwrap();
        let verified = decoded.validate().unwrap();
        assert_eq!(profile.owner_tag, verified.owner_tag);
        assert_eq!(profile.identity_key, verified.identity_key);
        assert_eq!(profile.forging_key, verified.forging_key);
        assert_eq!(profile.versions, verified.versions);
        assert_eq!(profile.expiration, verified.expiration);
        assert_eq!(profile.legacy_key, verified.legacy_key);
    }

    #[test]
    fn test_encode_decode_clientprofile_with_legacy() {
        let identity = ed448::EdDSAKeyPair::generate();
        let forging = ed448::EdDSAKeyPair::generate();
        let legacy = dsa::Keypair::generate();
        let profile = ClientProfile::new(
            0x0fff_ffff,
            identity.public().clone(),
            forging.public().clone(),
            vec![Version::V4],
            0x7fff_ffff,
            Some(legacy.public_key()),
        )
        .unwrap();
        let payload = profile.sign(&identity, Some(&legacy));
        let encoded = OTREncoder::new().write_encodable(&payload).to_vec();
        let decoded = ClientProfilePayload::decode(&mut OTRDecoder::new(&encoded)).unwrap();
        let verified = decoded.validate().unwrap();
        assert_eq!(profile.owner_tag, verified.owner_tag);
        assert_eq!(profile.identity_key, verified.identity_key);
        assert_eq!(profile.forging_key, verified.forging_key);
        assert_eq!(profile.versions, verified.versions);
        assert_eq!(profile.expiration, verified.expiration);
        assert_eq!(profile.legacy_key, verified.legacy_key);
    }

    #[test]
    fn test_read_profile_from_otr4j_tests() {
        let encoded_signed: Vec<i8> = vec![
            0, 0, 0, 7, 0, 1, -109, 97, 79, -64, 0, 2, 16, 0, -34, -104, -16, -124, 35, -103, 75,
            116, -80, -57, -19, 11, 97, 86, -64, 37, 12, -123, 107, -100, 115, -78, -15, 58, -91,
            95, 22, 34, 127, -26, 47, -64, 37, 39, -90, 59, 75, 44, 90, 112, -122, 103, 115, 77,
            -124, -62, -98, 126, -43, 8, 42, -18, 68, -120, 75, 90, 0, 0, 3, 18, 0, 76, 0, 55, -45,
            -49, -94, 8, -113, 40, 122, -56, 43, -62, 101, 63, 70, -29, -100, -11, 111, 11, -46,
            -16, 11, -82, 77, -39, 95, -9, -100, 7, -14, 14, -120, 14, 72, -34, 57, -86, -51, -37,
            109, 94, -69, -53, -12, 120, 22, -39, 37, 18, -80, 73, -10, -126, -16, -128, 0, 4, 0,
            0, 0, 1, 52, 0, 5, 0, 0, 0, 0, 119, -90, 101, 88, 0, 6, 0, 0, 0, 0, 0, -128, -3, 127,
            83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60,
            -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115,
            88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52,
            111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62,
            79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5,
            -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43,
            97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57, 0, 0, 0, 20, -105, 96, 80,
            -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11, 0,
            0, 0, -128, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87,
            -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89,
            87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76,
            40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40,
            -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5,
            98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90,
            -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42,
            0, 0, 0, -128, -126, -68, 65, 55, 123, -95, -49, 115, -8, 100, -53, 12, -99, 20, 0, 69,
            83, 114, -92, 66, 20, 5, -124, 124, 44, -40, -71, 96, 9, -7, 79, 55, 78, 103, -125, 64,
            20, -97, -23, -45, -1, 97, 73, -70, 37, 89, -43, 126, -25, 74, 67, 14, 63, -116, -32,
            -119, 11, 98, 14, 109, 37, -68, -82, -41, 71, -24, 111, -25, -81, 60, 30, 40, 40, 59,
            23, -122, -47, -58, -115, 43, -55, 24, 0, -99, 79, 30, 62, -108, 54, -27, -107, 93, 37,
            -26, 64, -112, 37, -37, 39, 104, -122, -73, -48, -36, -91, -36, -98, 23, 31, -76, 126,
            -28, -8, 50, -75, 3, -95, 104, 46, -22, 117, 41, -43, 106, 113, 124, -73, 80, 0, 7, 0,
            0, 0, 20, 103, 22, 91, 59, 104, 54, -97, -5, -101, 54, 13, 110, -94, -75, -97, -87, 60,
            -63, -56, 113, 0, 0, 0, 20, 46, 54, 75, 105, -39, -111, 56, -30, 84, -41, 105, -4, 83,
            58, -99, 5, 67, -104, -80, -99, 40, -83, 48, -110, 68, 96, 18, -103, 36, -23, 37, -106,
            110, 2, -80, -43, 50, 118, 65, -98, -119, 76, -104, 70, 85, -67, -120, -118, -26, 32,
            105, -56, 103, 65, -58, -32, -58, -117, 121, 76, 94, -57, 98, -53, -22, 9, 10, 44, -16,
            73, -7, -89, 24, 99, -13, -119, -128, -13, -114, -40, -77, -37, -5, -15, 66, 86, -53,
            -79, -14, 122, -43, -97, 107, -111, -1, -66, -107, 51, -81, 14, -118, 92, -117, -108,
            -16, 124, -104, -126, -26, 125, 18, -4, 85, -76, 39, 72, -115, 30, 69, -55, 37, 36, 38,
            83, -56, -72, -3, 24, 81, 51, -78, -52, 48, 0,
        ];
        let encoded: Vec<u8> = encoded_signed
            .into_iter()
            .map(|v| u8::from_be_bytes(v.to_be_bytes()))
            .collect();
        let mut dec = OTRDecoder::new(&encoded);
        let payload = ClientProfilePayload::decode(&mut dec).unwrap();
        let _ = payload.validate().unwrap();
    }
}

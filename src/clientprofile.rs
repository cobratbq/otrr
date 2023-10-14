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
        // FIXME ECDHKeyPair -> Ed448KeyPair (long-term identity)
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
        // FIXME there is a specific order of fields for legacy-key-signing and identity-signing. Right now we take order as received.
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
        // TODO temporary validation? (just for soundness check during development?)
        payload
            .validate()
            .expect("BUG: validation of constructed client profile payload should never fail.");
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
        let n = decoder.read_u32()? as usize;
        let mut fields = Vec::with_capacity(n);
        for _ in 0..n {
            match decoder.read_u16()? {
                TYPE_OWNERINSTANCETAG => fields.push(Field::OwnerTag(decoder.read_u32()?)),
                TYPE_ED448_PUBLIC_KEY => {
                    fields.push(Field::IdentityKey(IdentityKey::decode(decoder)?));
                }
                TYPE_ED448_FORGING_KEY => {
                    fields.push(Field::ForgingKey(ForgingKey::decode(decoder)?));
                }
                TYPE_VERSIONS => {
                    fields.push(Field::Versions(parse_versions(&decoder.read_data()?)));
                }
                TYPE_EXPIRATION => {
                    fields.push(Field::Expiration(decoder.read_i64()?));
                }
                TYPE_DSA_PUBLIC_KEY => fields.push(Field::LegacyKey(decoder.read_public_key()?)),
                TYPE_TRANSITIONAL_SIGNATURE => fields.push(Field::TransitionalSignature(
                    dsa::Signature::decode(decoder)?,
                )),
                _ => {
                    return Err(OTRError::ProtocolViolation(
                        "Unknown client profile field-type",
                    ))
                }
            }
        }
        let signature = decoder.read_ed448_signature()?;
        let payload = Self { fields, signature };
        payload.validate()?;
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
        let mut owner_tag: Option<InstanceTag> = Option::None;
        let mut identity_key: Option<ed448::Point> = Option::None;
        let mut forging_key: Option<ed448::Point> = Option::None;
        let mut versions: Vec<Version> = Vec::new();
        let mut expiration: Option<i64> = Option::None;
        let mut legacy_key: Option<dsa::PublicKey> = Option::None;
        let mut transitional_signature: Option<dsa::Signature> = Option::None;
        // FIXME validate transitional signature
        // FIXME validate signature
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
            assert!(transitional_signature.is_some());
            let mut encoder = OTREncoder::new();
            self.fields
                .iter()
                .filter(|f| {
                    matches!(
                        f,
                        Field::OwnerTag(_)
                            | Field::IdentityKey(_)
                            | Field::ForgingKey(_)
                            | Field::Versions(_)
                            | Field::Expiration(_)
                            | Field::LegacyKey(_)
                    )
                })
                .for_each(|f| {
                    encoder.write_encodable(f);
                });
            legacy_key
                .validate(transitional_signature.as_ref().unwrap(), &encoder.to_vec())
                .map_err(OTRError::CryptographicViolation)?;
        }
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

#[derive(Clone)]
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
            TYPE_TRANSITIONAL_SIGNATURE => Ok(Self::TransitionalSignature(dsa::Signature::decode(decoder)?)),
            _ => {
                log::info!("Unsupported field type: {:?}", typ);
                Err(OTRError::ProtocolViolation("Unsupported field type encountered."))
            },
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

#[derive(Clone)]
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

#[derive(Clone)]
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
    // FIXME version 1 is deprecated, version 2 is not advisable mainly due to lack of support for multiple instances.
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

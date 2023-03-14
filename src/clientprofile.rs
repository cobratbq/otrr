use crate::{
    crypto::{ed448, dsa},
    encoding::{OTRDecoder, OTREncodable},
    instancetag::InstanceTag,
    OTRError, Version,
};

pub struct ClientProfile {
    // FIXME how to implement client profile with useable fields? Follow otr4j pattern?
    owner: InstanceTag,
    publicKey: ed448::PublicKey,
    forgingKey: ed448::PublicKey,
    versions: Vec<Version>,
    expiration: i64,
    legacyPublicKey: Option<dsa::PublicKey>,
}

impl ClientProfile {
    fn from(payload: ClientProfilePayload) -> Result<ClientProfile, OTRError> {
        let ClientProfilePayload {
            owner: Some(owner),
            publicKey: Some(publicKey),
            forgingKey: Some(forgingKey),
            versions,
            expiration: Some(expiration),
            legacyPublicKey,
            transitionalSig: _,
        } = payload else {
            return Err(OTRError::ProtocolViolation("Some components from the client profile are missing"))
        };
        Ok(Self {
            owner,
            publicKey,
            forgingKey,
            versions,
            expiration,
            legacyPublicKey,
        })
    }
}

pub struct ClientProfilePayload {
    owner: Option<InstanceTag>,
    publicKey: Option<ed448::PublicKey>,
    forgingKey: Option<ed448::PublicKey>,
    versions: Vec<Version>,
    expiration: Option<i64>,
    legacyPublicKey: Option<dsa::PublicKey>,
    transitionalSig: Option<dsa::Signature>,
}

impl ClientProfilePayload {
    fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let n = decoder.read_int()? as usize;
        let mut payload = Self {
            owner: Option::None,
            publicKey: Option::None,
            forgingKey: Option::None,
            versions: Vec::new(),
            expiration: Option::None,
            legacyPublicKey: Option::None,
            transitionalSig: Option::None,
        };
        for _ in 0..n {
            match ClientProfileField::decode(decoder)? {
                ClientProfileField::OwnerInstanceTag(tag) => payload.owner = Option::Some(tag),
                ClientProfileField::Ed448PublicKey(pk) => payload.publicKey = Option::Some(pk),
                ClientProfileField::Ed448ForgingKey(pk) => payload.forgingKey = Option::Some(pk),
                ClientProfileField::Versions(data) => payload.versions = parse_versions(&data),
                ClientProfileField::ProfileExpiration(timestamp) => {
                    payload.expiration = Option::Some(timestamp)
                }
                ClientProfileField::DSAPublicKey(pk) => payload.legacyPublicKey = Option::Some(pk),
                ClientProfileField::TransitionalSignature(sig) => {
                    payload.transitionalSig = Option::Some(sig)
                }
            }
        }
        let signature = decoder.read_ed448_signature()?;
        // FIXME need to verify signature before reading payload?
        Ok(Self::validate(payload, signature)?)
    }

    fn validate(
        payload: ClientProfilePayload,
        signature: ed448::Signature,
    ) -> Result<Self, OTRError> {
        // FIXME perform verification of payload and validation against signature
        todo!("perform field validation of payload");
        Ok(payload)
    }
}

fn parse_versions(data: &[u8]) -> Vec<Version> {
    let mut versions = Vec::<Version>::new();
    for c in data {
        versions.push(match *c {
            b'3' => Version::V3,
            b'4' => Version::V4,
            _ => continue,
        })
    }
    versions
}

pub enum ClientProfileField {
    OwnerInstanceTag(InstanceTag),
    Ed448PublicKey(ed448::PublicKey),
    Ed448ForgingKey(ed448::PublicKey),
    Versions(Vec<u8>),
    ProfileExpiration(i64),
    DSAPublicKey(dsa::PublicKey),
    TransitionalSignature(dsa::Signature),
}

const DEFAULT_EXPIRATION: i64 = 7*24*3600;

impl OTREncodable for ClientProfileField {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        match self {
            Self::OwnerInstanceTag(tag) => {
                encoder.write_short(TYPE_OWNERINSTANCETAG);
                // TODO change API to accept reference?
                encoder.write_int(*tag);
            }
            Self::Ed448PublicKey(pk) => {
                encoder.write_short(TYPE_ED448_PUBLIC_KEY);
                encoder.write_ed448_public_key(pk);
            }
            Self::Ed448ForgingKey(pk) => {
                encoder.write_short(TYPE_ED448_FORGING_KEY);
                encoder.write_ed448_public_key(pk);
            }
            Self::Versions(versions) => {
                encoder.write_short(TYPE_VERSIONS);
                encoder.write_data(versions);
            }
            Self::ProfileExpiration(timestamp) => {
                encoder.write_short(TYPE_CLIENTPROFILE_EXPIRATION);
                // FIXME implement Client Profile expiration encoding
                todo!("implement encoding of Client Profile expiration")
            }
            Self::DSAPublicKey(pk) => {
                encoder.write_short(TYPE_DSA_PUBLIC_KEY);
                encoder.write_public_key(pk);
            }
            Self::TransitionalSignature(sig) => {
                encoder.write_short(TYPE_TRANSITIONAL_SIGNATURE);
                encoder.write_signature(sig);
            }
        }
    }
}

impl ClientProfileField {
    fn decode(decoder: &mut OTRDecoder) -> Result<ClientProfileField, OTRError> {
        let fieldtype = decoder.read_short()?;
        match fieldtype {
            TYPE_OWNERINSTANCETAG => Ok(ClientProfileField::OwnerInstanceTag(decoder.read_int()?)),
            TYPE_ED448_PUBLIC_KEY => Ok(ClientProfileField::Ed448PublicKey(
                decoder.read_ed448_public_key()?,
            )),
            TYPE_ED448_FORGING_KEY => Ok(ClientProfileField::Ed448ForgingKey(
                decoder.read_ed448_public_key()?,
            )),
            TYPE_VERSIONS => Ok(ClientProfileField::Versions(decoder.read_data()?)),
            // FIXME implement Client Profile expiration timestamp
            TYPE_CLIENTPROFILE_EXPIRATION => {
                todo!("Implement decoding of Client Profile expiration")
            }
            TYPE_DSA_PUBLIC_KEY => Ok(ClientProfileField::DSAPublicKey(decoder.read_public_key()?)),
            TYPE_TRANSITIONAL_SIGNATURE => Ok(ClientProfileField::TransitionalSignature(
                decoder.read_dsa_signature()?,
            )),
            _ => Err(OTRError::ProtocolViolation(
                "Unknown client profile field-type",
            )),
        }
    }
}

const TYPE_OWNERINSTANCETAG: u16 = 1;
const TYPE_ED448_PUBLIC_KEY: u16 = 2;
const TYPE_ED448_FORGING_KEY: u16 = 3;
const TYPE_VERSIONS: u16 = 4;
const TYPE_CLIENTPROFILE_EXPIRATION: u16 = 5;
const TYPE_DSA_PUBLIC_KEY: u16 = 6;
const TYPE_TRANSITIONAL_SIGNATURE: u16 = 7;

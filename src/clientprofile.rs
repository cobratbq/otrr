use crate::{
    crypto::{dsa, ed448},
    encoding::{OTRDecoder, OTREncodable},
    instancetag::InstanceTag,
    OTRError, Version,
};

pub struct ClientProfile {
    // FIXME how to implement client profile with useable fields? Follow otr4j pattern?
    owner: InstanceTag,
    public_key: ed448::PublicKey,
    forging_key: ed448::PublicKey,
    versions: Vec<Version>,
    expiration: i64,
    legacy_public_key: Option<dsa::PublicKey>,
}

impl ClientProfile {
    fn from(payload: ClientProfilePayload) -> Result<ClientProfile, OTRError> {
        let ClientProfilePayload {
            owner: Some(owner),
            public_key: Some(public_key),
            forging_key: Some(forging_key),
            versions,
            expiration: Some(expiration),
            legacy_public_key,
            transitional_sig: _,
        } = payload else {
            return Err(OTRError::ProtocolViolation("Some components from the client profile are missing"))
        };
        Ok(Self {
            owner,
            public_key,
            forging_key,
            versions,
            expiration,
            legacy_public_key,
        })
    }
}

pub struct ClientProfilePayload {
    owner: Option<InstanceTag>,
    public_key: Option<ed448::PublicKey>,
    forging_key: Option<ed448::PublicKey>,
    versions: Vec<Version>,
    expiration: Option<i64>,
    legacy_public_key: Option<dsa::PublicKey>,
    transitional_sig: Option<dsa::Signature>,
}

impl OTREncodable for ClientProfilePayload {
    fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
        // TODO assumes payload is valid, i.e. unwrap will produce panics
        encoder.write_u32(self.count_fields() as u32);
        {
            let tag = self.owner.unwrap();
            encoder.write_u16(TYPE_OWNERINSTANCETAG);
            encoder.write_u32(tag);
        }
        {
            let pk = self.public_key.unwrap();
            encoder.write_u16(TYPE_ED448_PUBLIC_KEY);
            encoder.write_ed448_public_key(&pk);
        }
        {
            let pk = self.forging_key.unwrap();
            encoder.write_u16(TYPE_ED448_FORGING_KEY);
            encoder.write_ed448_public_key(&pk);
        }
        {
            encoder.write_u16(TYPE_VERSIONS);
            encoder.write_data(&encode_versions(&self.versions));
        }
        {
            let timestamp = self.expiration.unwrap();
            encoder.write_u16(TYPE_CLIENTPROFILE_EXPIRATION);
            encoder.write_i64(timestamp);
        }
        if let Some(pk) = &self.legacy_public_key {
            encoder.write_u16(TYPE_DSA_PUBLIC_KEY);
            encoder.write_public_key(pk);
        }
        if let Some(sig) = &self.transitional_sig {
            encoder.write_u16(TYPE_TRANSITIONAL_SIGNATURE);
            encoder.write_signature(sig);
        }
    }
}

impl ClientProfilePayload {
    fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let n = decoder.read_u32()? as usize;
        let mut payload = Self {
            owner: Option::None,
            public_key: Option::None,
            forging_key: Option::None,
            versions: Vec::new(),
            expiration: Option::None,
            legacy_public_key: Option::None,
            transitional_sig: Option::None,
        };
        for _ in 0..n {
            match ClientProfileField::decode(decoder)? {
                ClientProfileField::OwnerInstanceTag(tag) => payload.owner = Option::Some(tag),
                ClientProfileField::Ed448PublicKey(pk) => payload.public_key = Option::Some(pk),
                ClientProfileField::Ed448ForgingKey(pk) => payload.forging_key = Option::Some(pk),
                ClientProfileField::Versions(data) => payload.versions = parse_versions(&data),
                ClientProfileField::ProfileExpiration(timestamp) => {
                    payload.expiration = Option::Some(timestamp);
                }
                ClientProfileField::DSAPublicKey(pk) => payload.legacy_public_key = Option::Some(pk),
                ClientProfileField::TransitionalSignature(sig) => {
                    payload.transitional_sig = Option::Some(sig);
                }
            }
        }
        let signature = decoder.read_ed448_signature()?;
        // FIXME need to verify signature before reading payload?
        Self::validate(payload, signature)
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

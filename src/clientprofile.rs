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

// TODO consider method for including and signing with legacy DSA public key for transitional signature.
impl ClientProfile {

    fn new(tag: InstanceTag, public_key: ed448::PublicKey, forging_key: ed448::PublicKey, versions: Vec<Version>, expiration: i64) -> Result<Self,OTRError> {
        let profile = Self{
            owner: tag,
            public_key,
            forging_key,
            versions,
            expiration,
            legacy_public_key: None,
        };
        Self::validate(profile)
    }

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

    fn validate(profile: Self) -> Result<Self,OTRError> {
        // FIXME continue here
        Ok(profile)
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
            let pk = self.public_key.as_ref().unwrap();
            encoder.write_u16(TYPE_ED448_PUBLIC_KEY);
            encoder.write_ed448_public_key(pk);
        }
        {
            let pk = self.forging_key.as_ref().unwrap();
            encoder.write_u16(TYPE_ED448_FORGING_KEY);
            encoder.write_ed448_public_key(pk);
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
            match decoder.read_u16()? {
                TYPE_OWNERINSTANCETAG => payload.owner = Some(decoder.read_u32()?),
                TYPE_ED448_PUBLIC_KEY => {
                    payload.public_key = Some(decoder.read_ed448_public_key()?)
                }
                TYPE_ED448_FORGING_KEY => {
                    payload.forging_key = Some(decoder.read_ed448_public_key()?)
                }
                TYPE_VERSIONS => {
                    payload
                        .versions
                        .extend(parse_versions(&decoder.read_data()?));
                }
                TYPE_CLIENTPROFILE_EXPIRATION => payload.expiration = Some(decoder.read_i64()?),
                TYPE_DSA_PUBLIC_KEY => payload.legacy_public_key = Some(decoder.read_public_key()?),
                TYPE_TRANSITIONAL_SIGNATURE => {
                    payload.transitional_sig = Some(decoder.read_dsa_signature()?)
                }
                _ => {
                    return Err(OTRError::ProtocolViolation(
                        "Unknown client profile field-type",
                    ))
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

    fn count_fields(&self) -> u8 {
        let mut count = 5u8;
        if self.legacy_public_key.is_some() {
            count += 1;
        }
        if self.transitional_sig.is_some() {
            count += 1;
        }
        count
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

fn encode_versions(versions: &[Version]) -> Vec<u8> {
    let mut data = Vec::<u8>::new();
    for v in versions {
        data.push(match v {
            Version::V3 => b'3',
            Version::V4 => b'4',
            _ => panic!("Illegal version"),
        })
    }
    data
}

const DEFAULT_EXPIRATION: i64 = 7 * 24 * 3600;

const TYPE_OWNERINSTANCETAG: u16 = 1;
const TYPE_ED448_PUBLIC_KEY: u16 = 2;
const TYPE_ED448_FORGING_KEY: u16 = 3;
const TYPE_VERSIONS: u16 = 4;
const TYPE_CLIENTPROFILE_EXPIRATION: u16 = 5;
const TYPE_DSA_PUBLIC_KEY: u16 = 6;
const TYPE_TRANSITIONAL_SIGNATURE: u16 = 7;

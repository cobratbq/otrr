// SPDX-License-Identifier: LGPL-3.0-only

use num_bigint::BigUint;

use crate::{
    clientprofile::{self, ClientProfilePayload},
    crypto::{self, ed448::RingSignature},
    encoding::{OTRDecoder, OTREncodable, OTREncoder},
    OTRError,
};

pub struct DAKEContext {}

enum State {
    Initial,
    AwaitingAuthR,
    AwaitingAuthI,
}

pub struct IdentityMessage {
    pub profile: clientprofile::ClientProfilePayload,
    pub y: crypto::ed448::Point,
    pub b: BigUint,
    pub ecdh0: crypto::ed448::Point,
    pub dh0: BigUint,
}

impl OTREncodable for IdentityMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        // FIXME check if complete/working.
        encoder
            .write_encodable(&self.profile)
            .write_ed448_point(&self.y)
            .write_ed448_scalar(&self.b)
            .write_ed448_point(&self.ecdh0)
            .write_ed448_scalar(&self.dh0);
    }
}

impl IdentityMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let profile = ClientProfilePayload::decode(decoder)?;
        let y = decoder.read_ed448_point()?;
        let b = decoder.read_ed448_scalar()?;
        let ecdh0 = decoder.read_ed448_point()?;
        let dh0 = decoder.read_ed448_scalar()?;
        Ok(Self {
            profile,
            y,
            b,
            ecdh0,
            dh0,
        })
    }
}

pub struct AuthRMessage {
    // FIXME define auth-r message
    pub profile: clientprofile::ClientProfilePayload,
    pub x: crypto::ed448::Point,
    pub a: BigUint,
    pub sigma: crypto::ed448::RingSignature,
    pub ecdh0: crypto::ed448::Point,
    pub dh0: BigUint,
}

impl OTREncodable for AuthRMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_encodable(&self.profile)
            .write_ed448_point(&self.x)
            .write_ed448_scalar(&self.a)
            .write_encodable(&self.sigma)
            .write_ed448_point(&self.ecdh0)
            .write_ed448_scalar(&self.dh0);
    }
}

impl AuthRMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let profile = ClientProfilePayload::decode(decoder)?;
        let x = decoder.read_ed448_point()?;
        let a = decoder.read_ed448_scalar()?;
        let sigma = RingSignature::decode(decoder)?;
        let ecdh0 = decoder.read_ed448_point()?;
        let dh0 = decoder.read_ed448_scalar()?;
        Ok(Self {
            profile,
            x,
            a,
            sigma,
            ecdh0,
            dh0,
        })
    }
}

pub struct AuthIMessage {
    pub sigma: crypto::ed448::RingSignature,
}

impl OTREncodable for AuthIMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder.write_encodable(&self.sigma);
    }
}

impl AuthIMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let sigma = RingSignature::decode(decoder)?;
        Ok(Self { sigma })
    }
}

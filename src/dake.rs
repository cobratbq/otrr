// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    clientprofile::{self, ClientProfilePayload},
    crypto::{
        self,
        otr4::{
            USAGE_AUTH_I_ALICE_CLIENT_PROFILE, USAGE_AUTH_I_BOB_CLIENT_PROFILE, USAGE_AUTH_I_PHI,
            USAGE_AUTH_R_ALICE_CLIENT_PROFILE, USAGE_AUTH_R_BOB_CLIENT_PROFILE, USAGE_AUTH_R_PHI,
            USAGE_SHARED_SECRET, USAGE_SSID, USAGE_THIRD_BRACE_KEY,
        },
    },
    encoding::{OTRDecoder, OTREncodable, OTREncoder},
    Host, OTRError,
};

pub struct DAKEContext {
    host: Rc<dyn Host>,
    state: State,
}

impl DAKEContext {
    pub fn initiate(&mut self) -> Result<IdentityMessage, OTRError> {
        let profile_bytes = self.host.client_profile();
        let mut decoder = OTRDecoder::new(&profile_bytes);
        let profile = ClientProfilePayload::decode(&mut decoder)?;
        decoder.done()?;
        let y = crypto::ed448::KeyPair::generate();
        let b = crypto::dh2::KeyPair::generate();
        let ecdh0 = crypto::ed448::KeyPair::generate();
        let dh0 = crypto::dh2::KeyPair::generate();
        let initial = IdentityMessage {
            profile: profile.clone(),
            y: y.public().clone(),
            b: b.public().clone(),
            ecdh0: ecdh0.public().clone(),
            dh0: dh0.public().clone(),
        };
        self.state = State::AwaitingAuthR {
            y,
            b,
            payload: profile,
        };
        Ok(initial)
    }

    pub fn handle_identity(&mut self, message: &IdentityMessage) -> Result<AuthRMessage, OTRError> {
        if let State::Initial = self.state {
            // No need to extract any data from state.
        } else {
            return Err(OTRError::ProtocolViolation(
                "Unexpected message received. Ignoring.",
            ));
        }
        let profile_bob = message.profile.validate()?;
        crypto::ed448::verify(&message.y).map_err(OTRError::CryptographicViolation)?;
        crypto::dh2::verify(&message.b).map_err(OTRError::CryptographicViolation)?;
        crypto::ed448::verify(&message.ecdh0).map_err(OTRError::CryptographicViolation)?;
        crypto::dh2::verify(&message.dh0).map_err(OTRError::CryptographicViolation)?;
        // Generate own key material and construct Auth-R Message.
        let profile_bytes = self.host.client_profile();
        let mut profile_decoder = OTRDecoder::new(&profile_bytes);
        let profile = ClientProfilePayload::decode(&mut profile_decoder)?;
        profile_decoder.done()?;
        let x = crypto::ed448::KeyPair::generate();
        let a = crypto::dh2::KeyPair::generate();
        let ecdh0 = crypto::ed448::KeyPair::generate();
        let dh0 = crypto::dh2::KeyPair::generate();
        let K_ecdh = ecdh0.generate_shared_secret(&message.ecdh0);
        // FIXME securely delete ecdh0.private
        let K_dh = dh0.generate_shared_secret(&message.dh0);
        // FIXME securely delete dh0.private
        // FIXME double check minimal size big-endian encoding.
        let brace_key = crypto::otr4::kdf::<32>(USAGE_THIRD_BRACE_KEY, &K_dh.to_bytes_be());
        let K = crypto::otr4::kdf_2::<64>(USAGE_SHARED_SECRET, &K_ecdh.encode(), &brace_key);
        let ssid = crypto::otr4::hwc::<8>(USAGE_SSID, &K);
        let mut tbytes = Vec::new();
        tbytes.push(0x00);
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_R_BOB_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(&message.profile).to_vec(),
        ));
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_R_ALICE_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(&profile).to_vec(),
        ));
        tbytes.extend_from_slice(&message.y.encode());
        tbytes.extend_from_slice(&x.public().encode());
        tbytes.extend_from_slice(&message.b.to_bytes_be());
        tbytes.extend_from_slice(&a.public().to_bytes_be());
        let phi = self.generate_phi();
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(USAGE_AUTH_R_PHI, &phi));
        let identity_keypair = self.host.keypair_identity();
        let sigma = crypto::ed448::RingSignature::sign(
            identity_keypair,
            profile_bob.forging_key.point(),
            identity_keypair.public(),
            &message.y,
            &tbytes,
        )
        .map_err(OTRError::CryptographicViolation)?;
        let response = AuthRMessage {
            profile_payload: profile.clone(),
            x: x.public().clone(),
            a: a.public().clone(),
            sigma,
            ecdh0: ecdh0.public().clone(),
            dh0: dh0.public().clone(),
        };
        self.state = State::AwaitingAuthI {
            profile_alice: profile,
            profile_bob: message.profile.clone(),
            x,
            y: message.y.clone(),
            a,
            b: message.b.clone(),
            ecdh0,
            dh0,
        };
        Ok(response)
    }

    pub fn handle_auth_r(&mut self, message: &AuthRMessage) -> Result<AuthIMessage, OTRError> {
        let y: &crypto::ed448::KeyPair;
        let b: &crypto::dh2::KeyPair;
        let payload_bob: &ClientProfilePayload;
        if let State::AwaitingAuthR {
            y: y_,
            b: b_,
            payload: payload_,
        } = &self.state
        {
            y = y_;
            b = b_;
            payload_bob = payload_;
        } else {
            return Err(OTRError::ProtocolViolation(
                "Unexpected message received. Ignoring.",
            ));
        };
        let profile_alice = message.profile_payload.validate()?;
        crypto::ed448::verify(&message.x).map_err(OTRError::CryptographicViolation)?;
        crypto::dh2::verify(&message.a).map_err(OTRError::CryptographicViolation)?;
        crypto::ed448::verify(&message.ecdh0).map_err(OTRError::CryptographicViolation)?;
        crypto::dh2::verify(&message.dh0).map_err(OTRError::CryptographicViolation)?;
        let mut tbytes: Vec<u8> = Vec::new();
        tbytes.push(0);
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            crypto::otr4::USAGE_AUTH_R_BOB_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(payload_bob).to_vec(),
        ));
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            crypto::otr4::USAGE_AUTH_R_ALICE_CLIENT_PROFILE,
            &OTREncoder::new()
                .write_encodable(&message.profile_payload)
                .to_vec(),
        ));
        tbytes.extend_from_slice(&y.public().encode());
        tbytes.extend_from_slice(&message.x.encode());
        tbytes.extend_from_slice(&OTREncoder::new().write_mpi(b.public()).to_vec());
        tbytes.extend_from_slice(&OTREncoder::new().write_mpi(&message.a).to_vec());
        let phi = self.generate_phi();
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            crypto::otr4::USAGE_AUTH_R_PHI,
            &phi,
        ));
        let profile_bob = payload_bob.validate()?;
        message
            .sigma
            .verify(
                profile_bob.forging_key.point(),
                profile_alice.public_key.point(),
                y.public(),
                &tbytes.to_vec(),
            )
            .map_err(OTRError::CryptographicViolation)?;
        // Generate response Auth-I Message.
        let mut tbytes = Vec::new();
        tbytes.push(0x01);
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_I_BOB_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(payload_bob).to_vec(),
        ));
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
            &OTREncoder::new()
                .write_encodable(&message.profile_payload)
                .to_vec(),
        ));
        tbytes.extend_from_slice(&y.public().encode());
        tbytes.extend_from_slice(&message.x.encode());
        // FIXME double-check if it is big-endian byte-order
        tbytes.extend_from_slice(&b.public().to_bytes_be());
        tbytes.extend_from_slice(&message.a.to_bytes_be());
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(USAGE_AUTH_I_PHI, &phi));
        let keypair_identity = self.host.keypair_identity();
        let sigma = crypto::ed448::RingSignature::sign(
            &keypair_identity,
            keypair_identity.public(),
            profile_alice.forging_key.point(),
            &message.x,
            &tbytes,
        )
        .map_err(OTRError::CryptographicViolation)?;
        let response = AuthIMessage { sigma };
        let mut tbytes = Vec::new();
        tbytes.push(0x01);
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_I_BOB_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(payload_bob).to_vec(),
        ));
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
            &OTREncoder::new()
                .write_encodable(&message.profile_payload)
                .to_vec(),
        ));
        self.state = State::Initial;
        // FIXME construct and reply with AUTH-I message.
        // FIXME transition to `ENCRYPTED_MESSAGES` state with gathered key material.
        Ok(response)
    }

    pub fn handle_auth_i(&mut self, message: &AuthIMessage) -> Result<(), OTRError> {
        let payload_alice: &ClientProfilePayload;
        let payload_bob: &ClientProfilePayload;
        let x: &crypto::ed448::KeyPair;
        let y: &crypto::ed448::Point;
        let a: &crypto::dh2::KeyPair;
        let b: &BigUint;
        let ecdh0: &crypto::ed448::KeyPair;
        let dh0: &crypto::dh2::KeyPair;
        if let State::AwaitingAuthI {
            profile_alice: payload_alice_,
            profile_bob: payload_bob_,
            x: x_,
            y: y_,
            a: a_,
            b: b_,
            ecdh0: ecdh0_,
            dh0: dh0_,
        } = &self.state
        {
            payload_alice = payload_alice_;
            payload_bob = payload_bob_;
            x = x_;
            y = y_;
            a = a_;
            b = b_;
            ecdh0 = ecdh0_;
            dh0 = dh0_;
        } else {
            return Err(OTRError::ProtocolViolation(
                "Unexpected message received. Ignoring.",
            ));
        }
        let profile_alice = payload_alice.validate()?;
        let keypair = self.host.keypair_identity();
        let mut tbytes = Vec::new();
        tbytes.push(0x01);
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_I_BOB_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(payload_bob).to_vec(),
        ));
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(
            USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(payload_alice).to_vec(),
        ));
        tbytes.extend_from_slice(&y.encode());
        tbytes.extend_from_slice(&x.public().encode());
        tbytes.extend_from_slice(&b.to_bytes_be());
        tbytes.extend_from_slice(&a.public().to_bytes_be());
        let phi = self.generate_phi();
        tbytes.extend_from_slice(&crypto::otr4::hwc::<64>(USAGE_AUTH_I_PHI, &phi));
        message
            .sigma
            .verify(
                keypair.public(),
                profile_alice.public_key.point(),
                x.public(),
                &tbytes,
            )
            .map_err(OTRError::CryptographicViolation)?;
        // FIXME implement: handle_auth_i
        todo!("implement: handle_auth_i")
    }

    fn generate_phi(&self) -> Vec<u8> {
        // FIXME implement: generating phi value
        todo!("implement: generating phi value")
    }
}

/// Interactive DAKE states.
enum State {
    /// `Initial` is the state where Bob initiates the Interactive DAKE or Alice receives Bob's
    /// `IdentityMessage`.
    Initial,
    /// `AwaitingAuthR` is the state for Alice as she awaits Bob's `AuthRMessage`.
    AwaitingAuthR {
        y: crypto::ed448::KeyPair,
        b: crypto::dh2::KeyPair,
        payload: ClientProfilePayload,
    },
    /// `AwaitingAuthI` is the state for Bob as he awaits Alice's `AuthIMessage`.
    // FIXME easier to have `expected_sigma` as bytes?
    AwaitingAuthI {
        profile_alice: clientprofile::ClientProfilePayload,
        profile_bob: clientprofile::ClientProfilePayload,
        x: crypto::ed448::KeyPair,
        y: crypto::ed448::Point,
        a: crypto::dh2::KeyPair,
        b: BigUint,
        ecdh0: crypto::ed448::KeyPair,
        dh0: crypto::dh2::KeyPair,
    },
}

pub struct IdentityMessage {
    pub profile: ClientProfilePayload,
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
    pub profile_payload: clientprofile::ClientProfilePayload,
    pub x: crypto::ed448::Point,
    pub a: BigUint,
    pub sigma: crypto::ed448::RingSignature,
    pub ecdh0: crypto::ed448::Point,
    pub dh0: BigUint,
}

impl OTREncodable for AuthRMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder
            .write_encodable(&self.profile_payload)
            .write_ed448_point(&self.x)
            .write_ed448_scalar(&self.a)
            .write_encodable(&self.sigma)
            .write_ed448_point(&self.ecdh0)
            .write_ed448_scalar(&self.dh0);
    }
}

impl AuthRMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let profile_payload = ClientProfilePayload::decode(decoder)?;
        let x = decoder.read_ed448_point()?;
        let a = decoder.read_ed448_scalar()?;
        let sigma = crypto::ed448::RingSignature::decode(decoder)?;
        let ecdh0 = decoder.read_ed448_point()?;
        let dh0 = decoder.read_ed448_scalar()?;
        Ok(Self {
            profile_payload,
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
        let sigma = crypto::ed448::RingSignature::decode(decoder)?;
        Ok(Self { sigma })
    }
}

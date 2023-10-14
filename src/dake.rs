// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    clientprofile::{self, ClientProfile, ClientProfilePayload},
    crypto::{dh3072, ed448, otr4},
    encoding::{OTRDecoder, OTREncodable, OTREncoder},
    messages::EncodedMessageType,
    Host, OTRError, Version, SSID,
};

/// `DAKEContext` is the struct maintaining the state.
// TODO in general, review the DAKE error handling and whether to propagate all errors.
// TODO add more (trace/debug) logging to provide better insight into the process in case of bugs.
pub struct DAKEContext {
    host: Rc<dyn Host>,
    state: State,
}

impl DAKEContext {
    pub fn new(host: Rc<dyn Host>) -> Self {
        Self {
            host,
            state: State::Initial,
        }
    }

    #[allow(clippy::unused_self)]
    pub fn version(&self) -> Version {
        Version::V4
    }

    /// `initiate` initiates a new DAKE.
    ///
    /// # Errors
    /// In case of protocol violation or cryptographic failure.
    pub fn initiate(&mut self) -> Result<EncodedMessageType, OTRError> {
        log::info!("Initiating DAKE.");
        if !matches!(self.state, State::Initial) {
            return Err(OTRError::IncorrectState(
                "Authenticated key exchange in progress.",
            ));
        }
        log::trace!("DAKE: reading client profile payload from host…");
        let payload = self.host.client_profile();
        let mut decoder = OTRDecoder::new(&payload);
        let payload = ClientProfilePayload::decode(&mut decoder)?;
        decoder.done()?;
        log::trace!("DAKE: generating new ephemeral keypairs.");
        let y = ed448::ECDHKeyPair::generate();
        let b = dh3072::KeyPair::generate();
        let ecdh0 = ed448::ECDHKeyPair::generate();
        let dh0 = dh3072::KeyPair::generate();
        let identity_message = IdentityMessage {
            profile: payload.clone(),
            y: y.public().clone(),
            b: b.public().clone(),
            ecdh0: ecdh0.public().clone(),
            dh0: dh0.public().clone(),
        };
        log::trace!("DAKE: message constructed; transitioning to AWAITING_AUTH_R and returning Identity-message for sending.");
        self.state = State::AwaitingAuthR {
            y,
            b,
            payload,
            ecdh0,
            dh0,
            identity_message: identity_message.clone(),
        };
        Ok(EncodedMessageType::Identity(identity_message))
    }

    pub fn abort(&mut self) {
        self.state = State::Initial;
        // FIXME need to send response when we abort?
    }

    /// `handle_identity` handles identity messages.
    ///
    /// # Errors
    /// In case of failure to validate message or failed to process due to protocol violation, e.g.
    /// incorrect state.
    // TODO Identity Message also needs to be handled in ENCRYPTED_MESSAGES and FINISHED states.
    #[allow(clippy::too_many_lines)]
    pub fn handle_identity(
        &mut self,
        message: IdentityMessage,
    ) -> Result<EncodedMessageType, OTRError> {
        let profile_bob: ClientProfile;
        match &self.state {
            State::Initial
            | State::AwaitingAuthI {
                profile_alice: _,
                profile_bob: _,
                x: _,
                y: _,
                a: _,
                b: _,
                k: _,
                ecdh0: _,
                dh0: _,
                ecdh0_other: _,
                dh0_other: _,
            } => {
                profile_bob = message.validate()?;
            }
            State::AwaitingAuthR {
                y: _,
                b: _,
                payload: _,
                ecdh0: _,
                dh0: _,
                identity_message,
            } => {
                profile_bob = message.validate()?;
                // FIXME we need to compare the proper values (hashes of `B`)
                if identity_message.b > message.b {
                    return Ok(EncodedMessageType::Identity(identity_message.clone()));
                }
            }
        }
        // Generate own key material and construct Auth-R Message.
        let profile_payload = self.host.client_profile();
        let mut profile_decoder = OTRDecoder::new(&profile_payload);
        let profile = ClientProfilePayload::decode(&mut profile_decoder)?;
        profile_decoder.done()?;
        let x = ed448::ECDHKeyPair::generate();
        let a = dh3072::KeyPair::generate();
        // FIXME double check minimal size big-endian encoding.
        let mut tbytes = Vec::new();
        tbytes.push(0x00);
        tbytes.extend_from_slice(&otr4::hwc::<64>(
            otr4::USAGE_AUTH_R_BOB_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(&message.profile).to_vec(),
        ));
        tbytes.extend_from_slice(&otr4::hwc::<64>(
            otr4::USAGE_AUTH_R_ALICE_CLIENT_PROFILE,
            &OTREncoder::new().write_encodable(&profile).to_vec(),
        ));
        tbytes.extend_from_slice(&message.y.encode());
        tbytes.extend_from_slice(&x.public().encode());
        // FIXME need big-endian or little-endian?
        tbytes.extend_from_slice(&message.b.to_bytes_be());
        tbytes.extend_from_slice(&a.public().to_bytes_be());
        let phi = self.generate_phi();
        tbytes.extend_from_slice(&otr4::hwc::<64>(otr4::USAGE_AUTH_R_PHI, &phi));
        let identity_keypair = self.host.keypair_identity();
        let sigma = ed448::RingSignature::sign(
            identity_keypair,
            &profile_bob.forging_key,
            identity_keypair.public(),
            &message.y,
            &tbytes,
        )
        .map_err(OTRError::CryptographicViolation)?;
        let ecdh0 = ed448::ECDHKeyPair::generate();
        let dh0 = dh3072::KeyPair::generate();
        let response = AuthRMessage {
            profile_payload: profile.clone(),
            x: x.public().clone(),
            a: a.public().clone(),
            sigma,
            ecdh0: ecdh0.public().clone(),
            dh0: dh0.public().clone(),
        };
        let x_public = x.public().clone();
        let a_public = a.public().clone();
        let y_message = message.y.clone();
        let b_message = message.b.clone();
        let shared_secret = otr4::MixedSharedSecret::new(x, a, message.y, message.b)
            .map_err(OTRError::CryptographicViolation)?;
        // FIXME clean up used key material (a, x, b, y)
        let k = shared_secret.k();
        self.state = State::AwaitingAuthI {
            profile_alice: profile,
            profile_bob: message.profile.clone(),
            x: x_public,
            y: y_message,
            a: a_public,
            b: b_message,
            k,
            ecdh0,
            dh0,
            ecdh0_other: message.ecdh0,
            dh0_other: message.dh0,
        };
        Ok(EncodedMessageType::AuthR(response))
    }

    /// `handle_auth_r` handles incoming Auth-R messages.
    ///
    /// # Errors
    /// In case of violation of protocol or cryptographic failures.
    #[allow(clippy::too_many_lines)]
    pub fn handle_auth_r(
        &mut self,
        message: AuthRMessage,
    ) -> Result<(MixedKeyMaterial, EncodedMessageType), OTRError> {
        if let State::AwaitingAuthR {
            y,
            b,
            payload: payload_bob,
            ecdh0,
            dh0,
            identity_message: _,
        } = &self.state
        {
            let profile_alice = message.validate()?;
            let mut tbytes: Vec<u8> = Vec::new();
            tbytes.push(0);
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_R_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_bob).to_vec(),
            ));
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_R_ALICE_CLIENT_PROFILE,
                &OTREncoder::new()
                    .write_encodable(&message.profile_payload)
                    .to_vec(),
            ));
            tbytes.extend_from_slice(&y.public().encode());
            tbytes.extend_from_slice(&message.x.encode());
            tbytes.extend_from_slice(&OTREncoder::new().write_mpi(b.public()).to_vec());
            tbytes.extend_from_slice(&OTREncoder::new().write_mpi(&message.a).to_vec());
            let phi = self.generate_phi();
            tbytes.extend_from_slice(&otr4::hwc::<64>(otr4::USAGE_AUTH_R_PHI, &phi));
            let profile_bob = payload_bob.validate()?;
            message
                .sigma
                .verify(
                    &profile_bob.forging_key,
                    &profile_alice.identity_key,
                    y.public(),
                    &tbytes,
                )
                .map_err(OTRError::CryptographicViolation)?;
            // Generate response Auth-I Message.
            let mut tbytes = Vec::new();
            tbytes.push(0x01);
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_bob).to_vec(),
            ));
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
                &OTREncoder::new()
                    .write_encodable(&message.profile_payload)
                    .to_vec(),
            ));
            tbytes.extend_from_slice(&y.public().encode());
            tbytes.extend_from_slice(&message.x.encode());
            // FIXME double-check if it is big-endian byte-order, fixed-size byte-array.
            tbytes.extend_from_slice(&b.public().to_bytes_be());
            tbytes.extend_from_slice(&message.a.to_bytes_be());
            tbytes.extend_from_slice(&otr4::hwc::<64>(otr4::USAGE_AUTH_I_PHI, &phi));
            let keypair_identity = self.host.keypair_identity();
            let sigma = ed448::RingSignature::sign(
                keypair_identity,
                keypair_identity.public(),
                &profile_alice.forging_key,
                &message.x,
                &tbytes,
            )
            .map_err(OTRError::CryptographicViolation)?;
            // Calculate cryptographic material.
            let shared_secret =
                otr4::MixedSharedSecret::new(y.clone(), b.clone(), message.x, message.a)
                    .map_err(OTRError::CryptographicViolation)?;
            let k = shared_secret.k();
            let ssid = otr4::hwc::<8>(otr4::USAGE_SSID, &k);
            let prev_root_key =
                otr4::kdf::<{ otr4::ROOT_KEY_LENGTH }>(otr4::USAGE_FIRST_ROOT_KEY, &k);
            let shared_secret = otr4::MixedSharedSecret::new(
                ecdh0.clone(),
                dh0.clone(),
                message.ecdh0,
                message.dh0,
            )
            .map_err(OTRError::CryptographicViolation)?;
            let double_ratchet = otr4::DoubleRatchet::initialize(
                &otr4::Selector::RECEIVER,
                shared_secret,
                prev_root_key,
            );

            // FIXME should generate sending keys here (as part of Double Ratchet), but this can probably be delayed until use. Check otr4j implementation.
            self.state = State::Initial;
            Ok((
                MixedKeyMaterial {
                    ssid,
                    double_ratchet,
                    us: otr4::fingerprint(&profile_bob.identity_key, &profile_bob.forging_key),
                    them: otr4::fingerprint(
                        &profile_alice.identity_key,
                        &profile_alice.forging_key,
                    ),
                },
                EncodedMessageType::AuthI(AuthIMessage { sigma }),
            ))
        } else {
            // FIXME double-check if we can use IncorrectState, as it seems to be tied closely to FINISHED state.
            Err(OTRError::IncorrectState(
                "Unexpected message received. Ignoring.",
            ))
        }
    }

    /// `handle_auth_i` processes a received Auth-I message and returns, if user secret matches,
    /// the key material needed for the encrypted session, or if the secret does not match, nothing
    /// useful.
    ///
    /// # Errors
    /// In case of protocol violations or cryptographic failures.
    pub fn handle_auth_i(&mut self, message: AuthIMessage) -> Result<MixedKeyMaterial, OTRError> {
        if let State::AwaitingAuthI {
            profile_alice: payload_alice,
            profile_bob: payload_bob,
            x,
            y,
            a,
            b,
            k,
            ecdh0,
            dh0,
            ecdh0_other,
            dh0_other,
        } = &self.state
        {
            let profile_alice = payload_alice.validate()?;
            let keypair = self.host.keypair_identity();
            let mut tbytes = Vec::new();
            tbytes.push(0x01);
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_bob).to_vec(),
            ));
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_alice).to_vec(),
            ));
            tbytes.extend_from_slice(&y.encode());
            tbytes.extend_from_slice(&x.encode());
            tbytes.extend_from_slice(&b.to_bytes_be());
            tbytes.extend_from_slice(&a.to_bytes_be());
            tbytes.extend_from_slice(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_PHI,
                &self.generate_phi(),
            ));
            // TODO consider precomputing this and storing the bytes for the ring signature verification, instead of individual components.
            message
                .sigma
                .verify(keypair.public(), &profile_alice.forging_key, x, &tbytes)
                .map_err(OTRError::CryptographicViolation)?;
            // FIXME initialize double ratchet, check otr4j for initial initialization steps to avoid having to reinvent the most practical way of starting this process.
            let ssid = otr4::hwc::<8>(otr4::USAGE_SSID, k);
            let prev_root_key =
                otr4::kdf::<{ otr4::ROOT_KEY_LENGTH }>(otr4::USAGE_FIRST_ROOT_KEY, k);
            let shared_secret = otr4::MixedSharedSecret::new(
                ecdh0.clone(),
                dh0.clone(),
                ecdh0_other.clone(),
                dh0_other.clone(),
            )
            .map_err(OTRError::CryptographicViolation)?;
            let double_ratchet = otr4::DoubleRatchet::initialize(
                &otr4::Selector::SENDER,
                shared_secret,
                prev_root_key,
            );
            // TODO validating the profile again just to acquire the correct data-type is a bit annoying, as we previously accepted the profile, but now we could potentially run into validation issues if near the expiration threshold.
            let profile_bob = payload_bob.validate()?;
            Ok(MixedKeyMaterial {
                ssid,
                double_ratchet,
                us: otr4::fingerprint(&profile_alice.identity_key, &profile_alice.forging_key),
                them: otr4::fingerprint(&profile_bob.identity_key, &profile_bob.forging_key),
            })
        } else {
            Err(OTRError::IncorrectState(
                "Unexpected message received. Ignoring.",
            ))
        }
    }

    fn generate_phi(&self) -> Vec<u8> {
        // FIXME implement: generating phi value
        todo!("implement: generating phi value")
    }
}

/// `MixedKeyMaterial` represents the result of the OTRv4 DAKE that includes the mixed shared
/// secret and initialized double ratchet.
pub struct MixedKeyMaterial {
    pub ssid: SSID,
    pub double_ratchet: otr4::DoubleRatchet,
    pub us: otr4::Fingerprint,
    pub them: otr4::Fingerprint,
}

/// Interactive DAKE states.
#[allow(clippy::large_enum_variant)]
enum State {
    /// `Initial` is the state where Bob initiates the Interactive DAKE or Alice receives Bob's
    /// `IdentityMessage`.
    Initial,
    /// `AwaitingAuthR` is the state for Alice as she awaits Bob's `AuthRMessage`.
    AwaitingAuthR {
        y: ed448::ECDHKeyPair,
        b: dh3072::KeyPair,
        payload: ClientProfilePayload,
        ecdh0: ed448::ECDHKeyPair,
        dh0: dh3072::KeyPair,
        identity_message: IdentityMessage,
    },
    /// `AwaitingAuthI` is the state for Bob as he awaits Alice's `AuthIMessage`.
    AwaitingAuthI {
        profile_alice: clientprofile::ClientProfilePayload,
        profile_bob: clientprofile::ClientProfilePayload,
        x: ed448::Point,
        y: ed448::Point,
        a: BigUint,
        b: BigUint,
        k: [u8; otr4::K_LENGTH],
        ecdh0: ed448::ECDHKeyPair,
        dh0: dh3072::KeyPair,
        ecdh0_other: ed448::Point,
        dh0_other: BigUint,
    },
}

#[derive(Clone)]
pub struct IdentityMessage {
    pub profile: ClientProfilePayload,
    pub y: ed448::Point,
    pub b: BigUint,
    pub ecdh0: ed448::Point,
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

    fn validate(&self) -> Result<ClientProfile, OTRError> {
        // FIXME client profile's instance tag needs to be validated against instance tag in session to make sure message is properly constructed belonging to the instance tag of the message.
        let profile_bob = self.profile.validate()?;
        ed448::verify(&self.y).map_err(OTRError::CryptographicViolation)?;
        dh3072::verify(&self.b).map_err(OTRError::CryptographicViolation)?;
        ed448::verify(&self.ecdh0).map_err(OTRError::CryptographicViolation)?;
        dh3072::verify(&self.dh0).map_err(OTRError::CryptographicViolation)?;
        Ok(profile_bob)
    }
}

#[derive(Clone)]
pub struct AuthRMessage {
    // FIXME define auth-r message
    pub profile_payload: clientprofile::ClientProfilePayload,
    pub x: ed448::Point,
    pub a: BigUint,
    pub sigma: ed448::RingSignature,
    pub ecdh0: ed448::Point,
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
        let sigma = ed448::RingSignature::decode(decoder)?;
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

    fn validate(&self) -> Result<ClientProfile, OTRError> {
        // FIXME client profile's instance tag needs to be validated against instance tag in session to make sure message is properly constructed belonging to the instance tag of the message.
        let profile_alice = self.profile_payload.validate()?;
        ed448::verify(&self.x).map_err(OTRError::CryptographicViolation)?;
        dh3072::verify(&self.a).map_err(OTRError::CryptographicViolation)?;
        ed448::verify(&self.ecdh0).map_err(OTRError::CryptographicViolation)?;
        dh3072::verify(&self.dh0).map_err(OTRError::CryptographicViolation)?;
        Ok(profile_alice)
    }
}

#[derive(Clone)]
pub struct AuthIMessage {
    pub sigma: ed448::RingSignature,
}

impl OTREncodable for AuthIMessage {
    fn encode(&self, encoder: &mut OTREncoder) {
        encoder.write_encodable(&self.sigma);
    }
}

impl AuthIMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        let sigma = ed448::RingSignature::decode(decoder)?;
        Ok(Self { sigma })
    }
}

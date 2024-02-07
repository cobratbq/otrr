// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    clientprofile::{self, ClientProfile, ClientProfilePayload},
    crypto::{self, dh3072, ed448, otr4},
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
        log::trace!("reading client profile payload from host…");
        let payload = self.host.client_profile();
        let mut decoder = OTRDecoder::new(&payload);
        let payload = ClientProfilePayload::decode(&mut decoder)?;
        decoder.done()?;
        log::trace!("generating new ephemeral keypairs.");
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
        log::trace!("message constructed; transitioning to AWAITING_AUTH_R and returning Identity-message for sending.");
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

    /// `transfer` provides DAKEContext --if and only if in the proper state-- for transfer to
    /// another instance.
    pub fn transfer(&self) -> Result<DAKEContext, OTRError> {
        log::trace!("Attempting state transfer…");
        match self.state {
            State::AwaitingAuthR {
                y: _,
                b: _,
                payload: _,
                ecdh0: _,
                dh0: _,
                identity_message: _,
            } => Ok(Self {
                host: Rc::clone(&self.host),
                state: self.state.clone(),
            }),
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
            } => Err(OTRError::IncorrectState(
                "State transfers are only legal in case of state AwaitingAuthR.",
            )),
        }
    }

    /// `handle_identity` handles identity messages.
    /// - `account_id` is the identifier of the local account.
    /// - `contact_id` is the identifier of the remote contact.
    ///
    /// NOTE: Alice receives the Identity message, sends Auth-R.
    ///
    /// # Errors
    /// In case of failure to validate message or failed to process due to protocol violation, e.g.
    /// incorrect state.
    // TODO Identity Message also needs to be handled in ENCRYPTED_MESSAGES and FINISHED states.
    // FIXME we need to pass in transport-level attributes, e.g. account ID of local user and contact ID of remote user, to include in `phi`.
    #[allow(clippy::too_many_lines)]
    pub fn handle_identity(
        &mut self,
        message: IdentityMessage,
        account: &[u8],
        contact: &[u8],
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
                // Note that, in case of `Awaiting Auth-I` we follow path of new identity message,
                // as opposed to OTRv4 spec's incorrect instructions of creating an Auth-R Message
                // with new values from the received Identity Message only, i.e. reusing our
                // existing but already cleared ECDH/DH keypairs.
                // There is no risk in generating new key material.
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
                let our_hashed_b = BigUint::from_bytes_be(&crypto::shake256::digest::<32>(
                    &OTREncoder::new().write_mpi(&identity_message.b).to_vec(),
                ));
                let their_hashed_b = BigUint::from_bytes_be(&crypto::shake256::digest::<32>(
                    &OTREncoder::new().write_mpi(&message.b).to_vec(),
                ));
                if our_hashed_b > their_hashed_b {
                    return Ok(EncodedMessageType::Identity(identity_message.clone()));
                }
            }
        }
        // Generate own key material and construct Auth-R Message.
        let profile_payload_bytes = self.host.client_profile();
        let mut profile_decoder = OTRDecoder::new(&profile_payload_bytes);
        let profile_payload = ClientProfilePayload::decode(&mut profile_decoder)?;
        profile_decoder.done()?;
        let x = ed448::ECDHKeyPair::generate();
        let a = dh3072::KeyPair::generate();
        let mut tbytes_enc = OTREncoder::new();
        tbytes_enc
            .write_u8(0x00)
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_R_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(&message.profile).to_vec(),
            ))
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_R_ALICE_CLIENT_PROFILE,
                &profile_payload_bytes,
            ))
            .write_ed448_point(&message.y)
            .write_ed448_point(x.public())
            .write_mpi(&message.b)
            .write_mpi(a.public());
        let profile = profile_payload.validate()?;
        let ecdh0 = ed448::ECDHKeyPair::generate();
        let dh0 = dh3072::KeyPair::generate();
        tbytes_enc.write(&otr4::hwc::<64>(
            otr4::USAGE_AUTH_R_PHI,
            &OTREncoder::new()
                .write_u32(profile.owner_tag)
                .write_u32(profile_bob.owner_tag)
                .write_ed448_point(ecdh0.public())
                .write_mpi(dh0.public())
                .write_ed448_point(&message.ecdh0)
                .write_mpi(&message.dh0)
                .write_data(account)
                .write_data(contact)
                .to_vec(),
        ));
        let identity_keypair = self.host.keypair_identity();
        let sigma = ed448::RingSignature::sign(
            identity_keypair,
            &profile_bob.forging_key,
            identity_keypair.public(),
            &message.y,
            &tbytes_enc.to_vec(),
        )
        .map_err(OTRError::CryptographicViolation)?;
        let response = AuthRMessage {
            profile_payload: profile_payload.clone(),
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
        let k = shared_secret.k();
        self.state = State::AwaitingAuthI {
            profile_alice: profile_payload,
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
    /// - `account_id` is the identifier of the local account.
    /// - `contact_id` is the identifier of the remote contact.
    ///
    /// NOTE: Bob receives the Auth-R message, sends Auth-I.
    ///
    /// # Errors
    /// In case of violation of protocol or cryptographic failures.
    #[allow(clippy::too_many_lines)]
    pub fn handle_auth_r(
        &mut self,
        message: AuthRMessage,
        account: &[u8],
        contact: &[u8],
    ) -> Result<(MixedKeyMaterial, EncodedMessageType), OTRError> {
        let State::AwaitingAuthR {
            y,
            b,
            payload: payload_bob,
            ecdh0,
            dh0,
            identity_message: _,
        } = &self.state
        else {
            return Err(OTRError::IncorrectState(
                "Unexpected message received. Ignoring.",
            ));
        };
        log::trace!("Handling Auth-R message…");
        let profile_alice = message.validate()?;
        let mut tbytes_enc = OTREncoder::new();
        tbytes_enc
            .write_u8(0x00)
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_R_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_bob).to_vec(),
            ))
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_R_ALICE_CLIENT_PROFILE,
                &OTREncoder::new()
                    .write_encodable(&message.profile_payload)
                    .to_vec(),
            ))
            .write_ed448_point(y.public())
            .write_ed448_point(&message.x)
            .write_mpi(b.public())
            .write_mpi(&message.a);
        let profile_bob = payload_bob.validate()?;
        tbytes_enc.write(&otr4::hwc::<64>(
            otr4::USAGE_AUTH_R_PHI,
            &OTREncoder::new()
                .write_u32(profile_alice.owner_tag)
                .write_u32(profile_bob.owner_tag)
                .write_ed448_point(&message.ecdh0)
                .write_mpi(&message.dh0)
                .write_ed448_point(ecdh0.public())
                .write_mpi(dh0.public())
                .write_data(contact)
                .write_data(account)
                .to_vec(),
        ));
        log::trace!("Validating Auth-R sigma…");
        message
            .sigma
            .validate(
                &profile_bob.forging_key,
                &profile_alice.identity_key,
                y.public(),
                &tbytes_enc.to_vec(),
            )
            .map_err(OTRError::CryptographicViolation)?;
        log::trace!("Auth-R sigma validated.");
        // Generate response Auth-I Message.
        let mut tbytes_enc = OTREncoder::new();
        tbytes_enc
            .write_u8(0x01)
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_bob).to_vec(),
            ))
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
                &OTREncoder::new()
                    .write_encodable(&message.profile_payload)
                    .to_vec(),
            ))
            .write_ed448_point(y.public())
            .write_ed448_point(&message.x)
            .write_mpi(b.public())
            .write_mpi(&message.a)
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_PHI,
                &OTREncoder::new()
                    .write_u32(profile_bob.owner_tag)
                    .write_u32(profile_alice.owner_tag)
                    .write_ed448_point(ecdh0.public())
                    .write_mpi(dh0.public())
                    .write_ed448_point(&message.ecdh0)
                    .write_mpi(&message.dh0)
                    .write_data(account)
                    .write_data(contact)
                    .to_vec(),
            ));
        let keypair_identity = self.host.keypair_identity();
        let sigma = ed448::RingSignature::sign(
            keypair_identity,
            keypair_identity.public(),
            &profile_alice.forging_key,
            &message.x,
            &tbytes_enc.to_vec(),
        )
        .map_err(OTRError::CryptographicViolation)?;
        // Calculate cryptographic material.
        let shared_secret =
            otr4::MixedSharedSecret::new(y.clone(), b.clone(), message.x, message.a)
                .map_err(OTRError::CryptographicViolation)?;
        let k = shared_secret.k();
        let ssid = otr4::hwc::<8>(otr4::USAGE_SSID, &k);
        let prev_root_key = otr4::kdf::<{ otr4::ROOT_KEY_LENGTH }>(otr4::USAGE_FIRST_ROOT_KEY, &k);
        let shared_secret =
            otr4::MixedSharedSecret::new(ecdh0.clone(), dh0.clone(), message.ecdh0, message.dh0)
                .map_err(OTRError::CryptographicViolation)?;
        let double_ratchet = otr4::DoubleRatchet::initialize(
            &otr4::Selector::RECEIVER,
            shared_secret,
            prev_root_key,
        );
        let double_ratchet = double_ratchet.rotate_sender();
        self.state = State::Initial;
        Ok((
            MixedKeyMaterial {
                ssid,
                double_ratchet,
                us: otr4::fingerprint(&profile_bob.identity_key, &profile_bob.forging_key),
                them: otr4::fingerprint(&profile_alice.identity_key, &profile_alice.forging_key),
            },
            EncodedMessageType::AuthI(AuthIMessage { sigma }),
        ))
    }

    /// `handle_auth_i` processes a received Auth-I message and returns, if user secret matches,
    /// the key material needed for the encrypted session, or if the secret does not match, nothing
    /// useful.
    /// - `account_id` is the identifier of the local account.
    /// - `contact_id` is the identifier of the remote contact.
    ///
    /// NOTE: Alice receives the Auth-I message.
    ///
    /// # Errors
    /// In case of protocol violations or cryptographic failures.
    pub fn handle_auth_i(
        &mut self,
        message: AuthIMessage,
        account: &[u8],
        contact: &[u8],
    ) -> Result<MixedKeyMaterial, OTRError> {
        let State::AwaitingAuthI {
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
        else {
            return Err(OTRError::IncorrectState(
                "Unexpected message received. Ignoring.",
            ));
        };
        let profile_alice = payload_alice.validate()?;
        let mut tbytes_enc = OTREncoder::new();
        tbytes_enc
            .write_u8(0x01)
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_BOB_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_bob).to_vec(),
            ))
            .write(&otr4::hwc::<64>(
                otr4::USAGE_AUTH_I_ALICE_CLIENT_PROFILE,
                &OTREncoder::new().write_encodable(payload_alice).to_vec(),
            ))
            .write_ed448_point(y)
            .write_ed448_point(x)
            .write_mpi(b)
            .write_mpi(a);
        let profile_bob = payload_bob.validate()?;
        tbytes_enc.write(&otr4::hwc::<64>(
            otr4::USAGE_AUTH_I_PHI,
            &OTREncoder::new()
                .write_u32(profile_bob.owner_tag)
                .write_u32(profile_alice.owner_tag)
                .write_ed448_point(ecdh0_other)
                .write_mpi(dh0_other)
                .write_ed448_point(ecdh0.public())
                .write_mpi(dh0.public())
                .write_data(contact)
                .write_data(account)
                .to_vec(),
        ));
        // TODO consider precomputing this and storing the bytes for the ring signature verification, instead of individual components.
        log::trace!("Validating Auth-I sigma…");
        let AuthIMessage { sigma } = message;
        sigma
            .validate(
                &profile_bob.identity_key,
                &profile_alice.forging_key,
                x,
                &tbytes_enc.to_vec(),
            )
            .map_err(OTRError::CryptographicViolation)?;
        log::trace!("Auth-I sigma validated.");
        let ssid = otr4::hwc::<8>(otr4::USAGE_SSID, k);
        let prev_root_key = otr4::kdf::<{ otr4::ROOT_KEY_LENGTH }>(otr4::USAGE_FIRST_ROOT_KEY, k);
        let shared_secret = otr4::MixedSharedSecret::new(
            ecdh0.clone(),
            dh0.clone(),
            ecdh0_other.clone(),
            dh0_other.clone(),
        )
        .map_err(OTRError::CryptographicViolation)?;
        let double_ratchet =
            otr4::DoubleRatchet::initialize(&otr4::Selector::SENDER, shared_secret, prev_root_key);
        // TODO validating the profile again just to acquire the correct data-type is a bit annoying, as we previously accepted the profile, but now we could potentially run into validation issues if near the expiration threshold.
        let profile_bob = payload_bob.validate()?;
        Ok(MixedKeyMaterial {
            ssid,
            double_ratchet,
            us: otr4::fingerprint(&profile_alice.identity_key, &profile_alice.forging_key),
            them: otr4::fingerprint(&profile_bob.identity_key, &profile_bob.forging_key),
        })
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
// FIXME consider defining an `ERROR` state that can be swapped in when taking the current state as we process the next DAKE message.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum State {
    /// `Initial` is the state where Bob initiates the Interactive DAKE or Alice receives Bob's
    /// `IdentityMessage`.
    Initial,
    /// `AwaitingAuthR` is the state for Bob as she awaits Alice's `AuthRMessage`.
    AwaitingAuthR {
        y: ed448::ECDHKeyPair,
        b: dh3072::KeyPair,
        payload: ClientProfilePayload,
        ecdh0: ed448::ECDHKeyPair,
        dh0: dh3072::KeyPair,
        identity_message: IdentityMessage,
    },
    /// `AwaitingAuthI` is the state for Alice as he awaits Bob's `AuthIMessage`.
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
        encoder
            .write_encodable(&self.profile)
            .write_ed448_point(&self.y)
            .write_mpi(&self.b)
            .write_ed448_point(&self.ecdh0)
            .write_mpi(&self.dh0);
    }
}

impl IdentityMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        log::trace!("decoding OTRv4 Identity message…");
        let profile = ClientProfilePayload::decode(decoder)?;
        let y = decoder.read_ed448_point()?;
        let b = decoder.read_mpi()?;
        let ecdh0 = decoder.read_ed448_point()?;
        let dh0 = decoder.read_mpi()?;
        log::trace!("decoding OTRv4 Identity message… done.");
        Ok(Self {
            profile,
            y,
            b,
            ecdh0,
            dh0,
        })
    }

    fn validate(&self) -> Result<ClientProfile, OTRError> {
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
            .write_mpi(&self.a)
            .write_encodable(&self.sigma)
            .write_ed448_point(&self.ecdh0)
            .write_mpi(&self.dh0);
    }
}

impl AuthRMessage {
    pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
        log::trace!("decoding OTRv4 Auth-R message…");
        let profile_payload = ClientProfilePayload::decode(decoder)?;
        let x = decoder.read_ed448_point()?;
        let a = decoder.read_mpi()?;
        let sigma = ed448::RingSignature::decode(decoder)?;
        let ecdh0 = decoder.read_ed448_point()?;
        let dh0 = decoder.read_mpi()?;
        log::trace!("decoding OTRv4 Auth-R message… done.");
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
        log::trace!("decoding OTRv4 Auth-I message…");
        let sigma = ed448::RingSignature::decode(decoder)?;
        log::trace!("decoding OTRv4 Auth-I message… done.");
        Ok(Self { sigma })
    }
}

// SPDX-License-Identifier: LGPL-3.0-only

use std::{collections, rc::Rc};

use crate::{
    ake::{AKEContext, CryptographicMaterial},
    clientprofile::{ClientProfile, ClientProfilePayload},
    dake::{DAKEContext, MixedKeyMaterial},
    encoding::{MessageFlags, OTRDecoder, OTREncoder},
    fragment::{self, FragmentError},
    instancetag::{self, InstanceTag, INSTANCE_ZERO},
    messages::{
        self, encode_message, serialize_message, EncodedMessage, EncodedMessageType, MessageType,
    },
    protocol::{self, Message, ProtocolMaterial},
    smp::{self, SMPStatus},
    smp4::{self, SMP4Status},
    utils, Host, OTRError, Policy, ProtocolStatus, UserMessage, Version, SSID, SUPPORTED_VERSIONS,
};

pub struct Account {
    host: Rc<dyn Host>,
    details: Rc<AccountDetails>,
    profile: ClientProfile,
    sessions: collections::HashMap<Vec<u8>, Session>,
}

// TODO set up a heartbeat timer that checks up on sessions and sends heartbeat messages if necessary.
impl Account {
    /// `new` creates a new Account instance.
    ///
    /// # Errors
    /// In case of failure to reconstruct client profile.
    pub fn new(account: Vec<u8>, policy: Policy, host: Rc<dyn Host>) -> Result<Self, OTRError> {
        let sessions = collections::HashMap::new();
        let profile = if let Ok(restored) = Self::restore_clientprofile(host.as_ref()) {
            log::trace!("Account: attempting to restore client-profile from host.");
            restored
        } else {
            log::trace!("Account: host provided zero bytes, incorrect or expired profile. Constructing new client profile.");
            Self::generate_clientprofile(host.as_ref())
        };
        let details = Rc::new(AccountDetails {
            policy,
            tag: profile.owner_tag,
            account,
        });
        Ok(Self {
            host,
            details,
            profile,
            sessions,
        })
    }

    // TODO how to approach client profile renewals?
    fn restore_clientprofile(host: &dyn Host) -> Result<ClientProfile, OTRError> {
        log::trace!("Account: restoring existing client profile.");
        let encoded_profile = host.client_profile();
        let mut decoder = OTRDecoder::new(&encoded_profile);
        let payload = ClientProfilePayload::decode(&mut decoder)?;
        decoder.done()?;
        payload.validate()
    }

    fn generate_clientprofile(host: &dyn Host) -> ClientProfile {
        const DEFAULT_EXPIRATION: u64 = 7 * 24 * 3600;
        let tag = instancetag::random_tag();
        let identity_keypair = host.keypair_identity();
        let identity_public = identity_keypair.public().clone();
        let forging_public = host.keypair_forging().public().clone();
        let mut versions = vec![Version::V4];
        let legacy_keypair = host.keypair();
        if legacy_keypair.is_some() {
            versions.push(Version::V3);
        }
        let expiration = i64::try_from(
            std::time::SystemTime::now()
                .checked_add(std::time::Duration::new(DEFAULT_EXPIRATION, 0))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .expect("BUG: working under the assumption that the duration calculation fits in an i64.");
        let profile = ClientProfile::new(
            tag,
            identity_public,
            forging_public,
            versions,
            expiration,
            legacy_keypair.map(|keypair| keypair.public_key().clone()),
        ).expect("BUG: failed to construct new client-profile for our client. This only happens in case of bad input such as illegal keypairs.");
        let payload = profile.sign(identity_keypair, legacy_keypair);
        host.update_client_profile(OTREncoder::new().write_encodable(&payload).to_vec());
        profile
    }

    #[must_use]
    pub fn instance_tag(&self) -> InstanceTag {
        self.details.tag
    }

    #[must_use]
    pub fn policy(&self) -> Policy {
        self.details.policy
    }

    #[must_use]
    pub fn session(&mut self, address: &[u8]) -> &mut Session {
        return self
            .sessions
            .entry(Vec::from(address))
            .or_insert(Session::new(
                Rc::clone(&self.host),
                Rc::clone(&self.details),
                Vec::from(address),
            ));
    }

    /// expire expires all timed-out (in secs) sessions and their instances of an account.
    ///
    /// This method handles a complete account. (Alternatively, there is `Session::expire`.)
    pub fn expire(&mut self, timeout: u64) {
        // TODO this is currently not thread-safe. Depending on how the heart-beat timer is going to work, this can cause problems.
        for (_, session) in &mut self.sessions {
            session.expire(timeout);
        }
    }
}

pub struct Session {
    host: Rc<dyn Host>,
    details: Rc<AccountDetails>,
    /// address contains the address of the remote party (chat account).
    address: Vec<u8>,
    /// instances contains all individual instances (clients) that have been
    /// encountered. Instance 0 is used for clients that have not yet announced
    /// their instance tag. Typically, before or during initial stages of OTR.
    instances: collections::HashMap<InstanceTag, Instance>,
    /// `whitespace_tagged` indicates whether or not a whitespace-tagged plaintext message was sent
    /// already. This field is shared with the method call that constructs the actual
    /// whitespace-tagged message whenever the opportunity is there. This field is shared such that
    /// sending a whitespace-tagged message (which is not specific to an instance) is common
    /// knowledge among all instances.
    // TODO `whitespace_tagged` is never reset to false. (After reentering MSGSTATE_PLAINTEXT)
    whitespace_tagged: bool,
}

// TODO we need to ensure the (legacy) DSA keypair is available when OTR3 interaction is executed. The logic assumes that the keypair is present.
impl Session {
    fn new(host: Rc<dyn Host>, details: Rc<AccountDetails>, address: Vec<u8>) -> Session {
        let mut instances = collections::HashMap::new();
        instances.insert(
            INSTANCE_ZERO,
            Instance::new(
                Rc::clone(&details),
                Rc::clone(&host),
                address.clone(),
                INSTANCE_ZERO,
            ),
        );
        Self {
            host,
            details,
            address,
            instances,
            whitespace_tagged: false,
        }
    }

    /// `instances` returns a list of known instance tags. The session may be in any
    /// state of the protocol, i.e. `MSGSTATE_PLAINTEXT`, `MSGSTATE_ENCRYPTED`, `MSGSTATE_FINISHED`.
    /// However, the fact that a session (known by instance tag) exists, means that this instance
    /// tag was once revealed.
    #[must_use]
    pub fn instances(&self) -> Vec<InstanceTag> {
        let mut sessions = Vec::<InstanceTag>::new();
        for k in self.instances.keys() {
            if *k == INSTANCE_ZERO {
                continue;
            }
            sessions.push(*k);
        }
        sessions
    }

    /// expire expires all instances of a session if timeout (in secs) is reached.
    ///
    /// This method handles a single session, i.e. multiple instances. (Alternatively, there is
    /// `Account::expire` that call this method.)
    pub fn expire(&mut self, timeout: u64) {
        // TODO this is currently not thread-safe. Depending on how the heart-beat timer is going to work, this can cause problems.
        for (_, instance) in &mut self.instances {
            instance.expire(timeout);
        }
    }

    /// Query status (protocol status) for a particular instance. Returns status if the instance is
    /// known.
    pub fn status(&self, instance: InstanceTag) -> Option<ProtocolStatus> {
        self.instances.get(&instance).map(Instance::status)
    }

    /// `receive` processes a raw-bytes payload for possible OTR content. Receive should be called
    /// for any received messages such that the protocol may transparently handle any OTR protocol
    /// message, as well as warn the client about plaintext message received at unexpected times.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` on any deviating circumstances of the protocol, such as failed AKE
    /// negotiations, failed SMP negotiations, incorrectly formatted messages, protocol violations,
    /// etc. Most errors will contain an instance tag when an established OTR session is involved.
    ///
    /// # Panics
    ///
    /// Will panic on incorrect internal state or uses. It should not panic on any user input, as
    /// these are typically the chat network messages therefore out of the clients control.
    // REMARK fuzzing target
    // TODO double-check if we correctly mitigate if we keep receiving messages with sender id '0' as this is only valid for OTR protocol 2 use-cases, which we don't support.
    // TODO ideally, one active AKE should exclude the other, such that no two processes can be in progress simultaneously.
    #[allow(clippy::too_many_lines)]
    pub fn receive(&mut self, payload: &[u8]) -> Result<UserMessage, OTRError> {
        log::debug!("Processing incoming message ..");
        if !self.details.policy.contains(Policy::ALLOW_V3)
            && !self.details.policy.contains(Policy::ALLOW_V4)
        {
            // OTR: if no version is allowed according to policy, do not do any handling at all.
            return Ok(UserMessage::Plaintext(Vec::from(payload)));
        }
        if fragment::match_fragment(payload) {
            log::debug!("Processing OTR fragment ..");
            let Some(fragment) = fragment::parse(payload) else {
                log::debug!("Not a valid/supported fragment.");
                return Ok(UserMessage::None);
            };
            fragment::verify(&fragment).or(Err(OTRError::ProtocolViolation("Invalid fragment")))?;
            if fragment.receiver != INSTANCE_ZERO && fragment.receiver != self.details.tag {
                // ignore instance tag ZERO as this is only relevant for OTRv2 and we do not
                // support this.
                return Err(OTRError::MessageForOtherInstance);
            }
            let details = Rc::clone(&self.details);
            let instance = self.instances.entry(fragment.sender).or_insert_with(|| {
                Instance::new(
                    details,
                    Rc::clone(&self.host),
                    self.address.clone(),
                    fragment.sender,
                )
            });
            return match instance.assembler.assemble(&fragment) {
                Ok(assembled) => {
                    if fragment::match_fragment(&assembled) {
                        return Err(OTRError::ProtocolViolation("Assembled fragments assemble into a fragment. This is disallowed by the specification."));
                    }
                    self.receive(&assembled)
                }
                Err(FragmentError::IncompleteResult | FragmentError::UnexpectedFragment) => {
                    // We've received a message fragment, but not enough to reassemble a message, so
                    // return early with no actual result and tell the client to wait for more
                    // fragments to arrive. (Or we have received an unexpected fragment, therefore
                    // reset everything and forget what we had up to now.)
                    Ok(UserMessage::None)
                }
                Err(FragmentError::InvalidData) => {
                    // Given that this is (merely) a fragment, just discard it and do not send an
                    // error message, as the error message would wreak havoc on the (still
                    // functional) encrypted session.
                    Err(OTRError::ProtocolViolation(
                        "Fragment contains invalid data.",
                    ))
                }
            };
        }
        // TODO can we handle possible errors produced here to reset whitespace_tagged, respond with OTR Error, etc?
        match messages::parse(payload)? {
            MessageType::Error(error) => {
                log::debug!("Processing OTR Error message ..");
                if self.details.policy.contains(Policy::ERROR_START_AKE) {
                    self.query()?;
                }
                Ok(UserMessage::Error(error))
            }
            MessageType::Plaintext(content) => {
                log::debug!("Processing plaintext message ..");
                if self.has_sessions() || self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::Tagged(versions, content) => {
                log::debug!("Processing whitespace-tagged message ..");
                if self.details.policy.contains(Policy::WHITESPACE_START_AKE) {
                    if let Some(selected) = select_version(&self.details.policy, &versions) {
                        self.initiate(&selected, INSTANCE_ZERO)?;
                    }
                }
                if self.has_sessions() || self.details.policy.contains(Policy::REQUIRE_ENCRYPTION) {
                    Ok(UserMessage::WarningUnencrypted(content))
                } else {
                    Ok(UserMessage::Plaintext(content))
                }
            }
            MessageType::Query(versions) => {
                log::debug!("Processing query message ..");
                log::trace!("Query-message with versions {:?}", versions);
                if let Some(selected) = select_version(&self.details.policy, &versions) {
                    self.initiate(&selected, INSTANCE_ZERO)?;
                }
                Ok(UserMessage::None)
            }
            MessageType::Encoded(EncodedMessage {
                version: _,
                sender: 0,
                receiver: _,
                message: _,
            }) => {
                log::debug!("Encoded message with sender-tag 0. This is illegal in OTR protocol (starting with version 3).");
                Ok(UserMessage::None)
            }
            MessageType::Encoded(
                msg @ EncodedMessage {
                    version: Version::V3,
                    sender: _,
                    receiver: _,
                    message: EncodedMessageType::DHKey(_),
                },
            ) => {
                log::debug!("Processing OTR-encoded D-H Commit message (with possible need to transfer AKEContext)…");
                // When a DH-Commit message was sent with receiver tag ZERO, then we may receive
                // any number of DH-Key messages in response. That is, a DH-Key message for each
                // client of the account that receives the DH-Commit message. (Potentially even
                // after the fact if client OTR plug-in incorrectly responds to history (replay)
                // of chat. Only upon receiving do we obtain the instance tag such that we can
                // redirect processing to a dedicated instance.
                self.verify_encoded_message_header(&msg)?;
                if !self.details.policy.contains(Policy::ALLOW_V3) {
                    return Ok(UserMessage::None);
                }
                // TODO DH-Key (responses) may be received multiple times (multiple instances, multiple repeats). Do we need to take these cases into account when handling? (temporary dh keypair and `r` value are same/reused for all cases, same CTR value used for all cases)
                // Transfer is only supported in `AKEState::AwaitingDHKey`. Therefore, result
                // indicates whether transfer is possible.
                let result_context = self
                    .instances
                    .get(&INSTANCE_ZERO)
                    .expect("BUG: instance 0 should always exist.")
                    .transfer_ake_context();
                let instance = self.instances.entry(msg.sender).or_insert_with(|| {
                    Instance::new(
                        Rc::clone(&self.details),
                        Rc::clone(&self.host),
                        self.address.clone(),
                        msg.sender,
                    )
                });
                if let Ok(context) = result_context {
                    instance.adopt_ake_context(context);
                }
                instance.handle(msg)
            }
            MessageType::Encoded(
                msg @ EncodedMessage {
                    version: Version::V4,
                    sender: _,
                    receiver: _,
                    message: EncodedMessageType::AuthR(_),
                },
            ) => {
                // TODO should we also check protocol version, to see if AuthR message is sent correctly?
                log::debug!("Processing OTR-encoded Auth-R message (with possible need to transfer DAKEContext)…");
                log::trace!("Auth-R message: {msg:?}");
                self.verify_encoded_message_header(&msg)?;
                if !self.details.policy.contains(Policy::ALLOW_V4) {
                    return Ok(UserMessage::None);
                }
                // TODO Auth-R (responses) may be received multiple times (multiple instances, multiple repeats). Do we need to take these cases into account when handling? (temporary dh keypair and `r` value are same/reused for all cases, same CTR value used for all cases)
                // Transfer is only supported in `AKEState::AwaitingDHKey`. Therefore, result
                // indicates whether transfer is possible.
                let result_context = self
                    .instances
                    .get(&INSTANCE_ZERO)
                    .expect("BUG: instance 0 should always exist.")
                    .transfer_dake_context();
                let instance = self.instances.entry(msg.sender).or_insert_with(|| {
                    Instance::new(
                        Rc::clone(&self.details),
                        Rc::clone(&self.host),
                        self.address.clone(),
                        msg.sender,
                    )
                });
                // TODO what if transfer isn't necessary? can we clearly distinguish between the two cases?
                if let Ok(context) = result_context {
                    instance.adopt_dake_context(context);
                }
                instance.handle(msg)
            }
            MessageType::Encoded(msg) => {
                log::debug!("Processing OTR-encoded message…");
                log::trace!("Encoded message: {msg:?}");
                self.verify_encoded_message_header(&msg)?;
                if msg.version == Version::V3 && !self.details.policy.contains(Policy::ALLOW_V3)
                    || msg.version == Version::V4 && !self.details.policy.contains(Policy::ALLOW_V4)
                {
                    return Ok(UserMessage::None);
                }
                self.instances
                    .entry(msg.sender)
                    .or_insert_with(|| {
                        Instance::new(
                            Rc::clone(&self.details),
                            Rc::clone(&self.host),
                            self.address.clone(),
                            msg.sender,
                        )
                    })
                    .handle(msg)
            }
        }
    }

    fn verify_encoded_message_header(&self, msg: &EncodedMessage) -> Result<(), OTRError> {
        match msg.version {
            Version::None => {
                return Err(OTRError::ProtocolViolation(
                    "Encoded message must always have a protocol version.",
                ))
            }
            Version::Unsupported(version) => return Err(OTRError::UnsupportedVersion(version)),
            Version::V3 | Version::V4 => { /* This is acceptable. */ }
        }
        instancetag::verify(msg.sender).or(Err(OTRError::ProtocolViolation(
            "Sender instance tag is illegal value",
        )))?;
        if msg.sender == INSTANCE_ZERO {
            return Err(OTRError::ProtocolViolation("Sender instance tag is zero"));
        }
        instancetag::verify(msg.receiver).or(Err(OTRError::ProtocolViolation(
            "Receiver instance tag is illegal value",
        )))?;
        if msg.receiver == 0
            && !matches!(
                msg.message,
                EncodedMessageType::DHCommit(_) | EncodedMessageType::Identity(_)
            )
        {
            return Err(OTRError::ProtocolViolation(
                "Receiver instance tag is zero.",
            ));
        }
        if msg.receiver > INSTANCE_ZERO && msg.receiver != self.details.tag {
            return Err(OTRError::MessageForOtherInstance);
        }
        Ok(())
    }

    /// `send` processes plaintext message content (user input) through the current state of OTR to
    /// ready them for sending. This involves possibly encrypting the plaintext message, possibly
    /// triggering other protocol interactions, and so forth. Additionally, depending on set
    /// policies, `send` may issue warnings or refuse to operate to ensure that the client operates
    /// according to set policies.
    ///
    /// NOTE: for correctness of the OTR protocol, `0` (`NULL`) values in the user message will be
    /// dropped. If the policy does not allow OTR to operate (all protocol versions disabled) then
    /// user content will not be touched at all.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` on any kind of special-case situations involving the OTR protocol,
    /// such as protocol violations, inproper state, incorrect internal state (data), etc.
    ///
    /// # Panics
    ///
    /// Will panic on inappropriate user-input. Panics are most likely traced back to incorrect use.
    // TODO do we check if message contains null-bytes? (Nulls are not allowed, because it's the separator between message and TLVs.)
    pub fn send(
        &mut self,
        instance: InstanceTag,
        content: &[u8],
    ) -> Result<Vec<Vec<u8>>, OTRError> {
        if !self.details.policy.contains(Policy::ALLOW_V3)
            && !self.details.policy.contains(Policy::ALLOW_V4)
        {
            log::debug!("No protocol versions are allowed. OTR support is disabled.");
            return Ok(vec![Vec::from(content)]);
        }
        let instance = self
            .instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance(instance))?;
        // "If msgstate is MSGSTATE_PLAINTEXT:"
        if self.details.policy.contains(Policy::REQUIRE_ENCRYPTION)
            && instance.status() == ProtocolStatus::Plaintext
        {
            // "   If REQUIRE_ENCRYPTION is set:
            //       Store the plaintext message for possible retransmission, and send a Query
            //       Message."
            self.query()?;
            return Err(OTRError::PolicyRestriction(
                "Encryption is required by policy, but no confidential session is established yet. Query-message has been sent to initiate OTR session.",
            ));
        }
        // "If msgstate is MSGSTATE_ENCRYPTED:
        //    Encrypt the message, and send it as a Data Message. Store the plaintext message for
        //    possible retransmission.
        //  If msgstate is MSGSTATE_FINISHED:
        //    Inform the user that the message cannot be sent at this time. Store the plaintext
        //    message for possible retransmission."
        instance.send(&mut self.whitespace_tagged, content)
    }

    /// `initiate` initiates the OTR protocol for designated receiver.
    ///
    /// # Errors
    /// In case of in-progress (D)AKE session, which requires manually aborting first.
    // TODO now that `initiate` may return an error, check if this needs handling or whether propagation is fine.
    pub fn initiate(
        &mut self,
        version: &Version,
        receiver: InstanceTag,
    ) -> Result<UserMessage, OTRError> {
        self.instances
            .entry(receiver)
            .or_insert_with(|| {
                Instance::new(
                    Rc::clone(&self.details),
                    Rc::clone(&self.host),
                    self.address.clone(),
                    receiver,
                )
            })
            .initiate(version)
    }

    /// `smp_ssid` returns the SSID used for verification in case of an established (encrypted) OTR
    /// session.
    ///
    /// # Errors
    ///
    /// Will give an `OTRError::UnknownInstance` error in case of non-existing instance.
    // TODO it is not possible to identify which half must be highlighted in the user interface.
    pub fn smp_ssid(&self, instance: InstanceTag) -> Result<SSID, OTRError> {
        self.instances
            .get(&instance)
            .ok_or(OTRError::UnknownInstance(instance))?
            .smp_ssid()
    }

    fn get_instance(&mut self, instance: InstanceTag) -> Result<&mut Instance, OTRError> {
        self.instances
            .get_mut(&instance)
            .ok_or(OTRError::UnknownInstance(instance))
    }

    /// `has_encrypted_sessions` checks if any instances are established or finished OTR sessions.
    fn has_sessions(&self) -> bool {
        self.instances.iter().any(|i| {
            assert_eq!(*i.0, i.1.receiver);
            assert!(
                *i.0 != INSTANCE_ZERO || i.1.status() == ProtocolStatus::Plaintext,
                "BUG: Given that we do not support OTR version 1 and 2, we expect instance 0 is Plaintext"
            );
            i.1.status() == ProtocolStatus::Encrypted || i.1.status() == ProtocolStatus::Finished
        })
    }

    /// `end` ends the specified OTR session and resets the state back to plaintext. This means that
    /// confidential communication ends and any subsequent message will be sent as plain text, i.e.
    /// unencrypted. This function should only be called as a result of _direct user interaction_.
    ///
    /// In the case the other party ended/aborted the session, the session would transition to
    /// `MSGSTATE_FINISHED`. In that case, too, `end` resets the session back to
    /// `MSGSTATE_PLAINTEXT`
    ///
    /// # Errors
    ///
    /// Will return an error in case the specified instance does not exist.
    pub fn end(&mut self, instance: InstanceTag) -> Result<UserMessage, OTRError> {
        Ok(self.get_instance(instance)?.reset())
    }

    /// `query` sends a OTR query-message over the host's communication network in order to probe
    /// for other parties that are willing to initiate an OTR session.
    ///
    /// # Errors
    ///
    /// Will return an error in case of no compatible errors.
    pub fn query(&mut self) -> Result<(), OTRError> {
        let accepted_versions = filter_versions(&self.details.policy, &SUPPORTED_VERSIONS);
        if accepted_versions.is_empty() {
            return Err(OTRError::UserError("No supported versions available."));
        }
        self.host.inject(
            &self.address,
            &serialize_message(&MessageType::Query(accepted_versions)),
        );
        Ok(())
    }

    /// `start_smp` initiates the Socialist Millionaires' Protocol for the specified instance. The
    /// initiator immediately supplies a question (`question`, which is optional so may be
    /// zero-length) and a `secret` which is the secret value that tested for in the SMP execution.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` in case the instance does not exist, or the protocol is in an
    /// incorrect state. An established encrypted OTR session is necessary to start SMP.
    pub fn start_smp(
        &mut self,
        instance: InstanceTag,
        secret: &[u8],
        question: &[u8],
    ) -> Result<(), OTRError> {
        self.get_instance(instance)?.start_smp(secret, question)
    }

    /// `abort_smp` aborts an (in-progress) SMP session.
    ///
    /// # Errors
    ///
    /// Will return `OTRError` in case the specified instance is not a confidential session, i.e.
    /// encrypted OTR session, and on any violations of the OTR protocol.
    pub fn abort_smp(&mut self, instance: InstanceTag) -> Result<(), OTRError> {
        self.get_instance(instance)?.abort_smp()
    }
}

/// Instance serves a single communication session, ensuring that messages always travel between the same two clients.
struct Instance {
    details: Rc<AccountDetails>,
    host: Rc<dyn Host>,
    address: Vec<u8>,
    receiver: InstanceTag,
    // assembler for each instance, such that resets of the OTR3 assembler are per instance
    assembler: fragment::Assembler,
    state: Box<dyn protocol::ProtocolState>,
    ake: AKEContext,
    dake: DAKEContext,
}

/// `Instance` represents a single instance, a communication session with a single client of an
/// account. The protocol assumes that multiple clients can be active at the same time for a single
/// chat account.
/// `Instance` expects to receive (as much as possible) preselected values to be used: selection,
/// validation to be performed in `Session` if possible.
impl Instance {
    fn new(
        details: Rc<AccountDetails>,
        host: Rc<dyn Host>,
        address: Vec<u8>,
        receiver: InstanceTag,
    ) -> Self {
        Self {
            ake: AKEContext::new(Rc::clone(&host)),
            dake: DAKEContext::new(Rc::clone(&host)),
            details,
            host,
            address,
            receiver,
            assembler: fragment::Assembler::new(),
            state: protocol::new_state(),
        }
    }

    fn status(&self) -> ProtocolStatus {
        self.state.status()
    }

    fn expire(&mut self, timeout: u64) {
        // TODO this is currently not thread-safe. Depending on how the heart-beat timer is going to work, this can cause problems.
        if let Some((disconnect_msg, new_state)) = self.state.expire(timeout) {
            let prev = core::mem::replace(
                &mut self.state,
                new_state as Box<dyn protocol::ProtocolState>,
            );
            self.inject(&prev.version(), self.receiver, disconnect_msg);
        }
    }

    fn initiate(&mut self, version: &Version) -> Result<UserMessage, OTRError> {
        let initiator = match version {
            Version::V3 => self.ake.initiate(),
            Version::V4 => self.dake.initiate()?,
            Version::None | Version::Unsupported(_) => panic!("BUG: incorrect use of API"),
        };
        self.inject(version, self.receiver, initiator);
        Ok(UserMessage::None)
    }

    fn transfer_ake_context(&self) -> Result<AKEContext, OTRError> {
        assert_eq!(INSTANCE_ZERO, self.receiver);
        self.ake.transfer().map_err(OTRError::AuthenticationError)
    }

    fn adopt_ake_context(&mut self, context: AKEContext) {
        assert_ne!(0, self.receiver);
        log::trace!("OTR AKE state transferred.");
        self.ake = context;
    }

    fn transfer_dake_context(&self) -> Result<DAKEContext, OTRError> {
        assert_eq!(INSTANCE_ZERO, self.receiver);
        self.dake.transfer()
    }

    fn adopt_dake_context(&mut self, context: DAKEContext) {
        assert_ne!(0, self.receiver);
        log::trace!("OTRv4 DAKE state transferred.");
        self.dake = context;
    }

    // TODO should established OTR sessions respond to query? (should not re-establish all active sessions, i.e. multiple instances)
    #[allow(clippy::too_many_lines)]
    fn handle(&mut self, encoded_message: EncodedMessage) -> Result<UserMessage, OTRError> {
        // Given that we are processing an actual (OTR-)encoded message intended for this instance,
        // we should reset the assembler now.
        let version = encoded_message.version;
        let sender = encoded_message.sender;
        let receiver = encoded_message.receiver;
        if version == Version::V3 {
            self.assembler.cleanup(&Version::V3);
        }
        match (&version, encoded_message.message) {
            (Version::V3, EncodedMessageType::DHCommit(msg)) => {
                let response = self
                    .ake
                    .handle_dhcommit(msg).map_err(OTRError::AuthenticationError)?;
                self.inject(&self.ake.version(), sender, response);
                Ok(UserMessage::None)
            }
            (Version::V3, EncodedMessageType::DHKey(msg)) => {
                let response = self
                    .ake
                    .handle_dhkey(msg).map_err(OTRError::AuthenticationError)?;
                self.inject(&self.ake.version(), sender, response);
                Ok(UserMessage::None)
            }
            (Version::V3, EncodedMessageType::RevealSignature(msg)) => {
                let (CryptographicMaterial{ssid, our_dh, their_dh, their_dsa}, response) = self
                    .ake
                    .handle_reveal_signature(msg).map_err(OTRError::AuthenticationError)?;
                self.state = self.state.secure(Rc::clone(&self.host), self.details.tag,
                    encoded_message.sender, ProtocolMaterial::AKE { ssid, our_dh, their_dh, their_dsa });
                assert_eq!(ProtocolStatus::Encrypted, self.state.status());
                self.inject(&self.ake.version(), sender, response);
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            (Version::V3, EncodedMessageType::Signature(msg)) => {
                let CryptographicMaterial{ssid, our_dh, their_dh, their_dsa} = self
                    .ake
                    .handle_signature(msg).map_err(OTRError::AuthenticationError)?;
                self.state = self.state.secure(Rc::clone(&self.host), self.details.tag,
                    encoded_message.sender, ProtocolMaterial::AKE { ssid, our_dh, their_dh, their_dsa });
                assert_eq!(ProtocolStatus::Encrypted, self.state.status());
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            (Version::V3, EncodedMessageType::Data(msg)) => {
                // NOTE that TLV 0 (Padding) and 1 (Disconnect) are already handled as part of the
                // protocol. Other TLVs that are their own protocol or function, therefore must be
                // handled separately.
                let authenticator_data = messages::encode_authenticator_data(&version, sender, receiver, &msg);
                let (message, transition) = self.state.handle(&msg, &authenticator_data);
                if transition.is_some() {
                    self.state = transition.unwrap();
                }
                match message {
                    Ok(Message::Confidential(content, tlvs)) if tlvs.iter().any(smp::is_smp_tlv) => {
                        if !msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) {
                            log::warn!("Other client did not set ignore-unreadable flag on SMP messages. This is preferred/recommended because these are OTR control messages, rather than user content.");
                        }
                        if !content.is_empty() {
                            log::warn!("OTR3 SMP tlv messages are not expected to contain text content. This content is ignored.");
                        }
                        if tlvs.iter().filter(|t| smp::is_smp_tlv(t)).count() > 1 {
                            // Given more than one SMP tlv, the order of processing impacts outcome.
                            // The protocol only specifies that a single SMP tlv is expected at any
                            // one time, so do not even attempt to process these. It is a violation.
                            log::warn!("OTR3 more than one SMP tlv found. This is not expected according to the specification. Aborting further processing.");
                            return Err(OTRError::ProtocolViolation("SMP: more than one SMP tlv found. This cannot occur when protocol is properly followed."));
                        }
                        let Ok(smp_context) = self.state.smp_mut() else {
                            // SMP tlvs are only relevant in encrypted-messaging state. If we
                            // transitioned away just now, then this SMP tlv no longer has any value
                            // Log this somewhat peculiar circumstance and stop processing.
                            log::warn!("OTR3 SMP state is no longer available. The state machine must have transitioned away before the SMP tlvs were processed. This seems to indicate a protocol violation. Ignoring this SMP tlv and returning result without user-content.");
                            return Err(OTRError::ProtocolViolation("OTR3 SMP tlv being processed while the state machine has already transitioned away. This cannot happen in OTR unless the other client deviated from the protocol."));
                        };
                        // Socialist Millionaire Protocol (SMP) handling.
                        let tlv = tlvs.into_iter().find(smp::is_smp_tlv).unwrap();
                        if let Some(reply_tlv) = smp_context.handle(&tlv) {
                            let otr_message = self.state.prepare(
                                MessageFlags::IGNORE_UNREADABLE,
                                &OTREncoder::new()
                                    .write_u8(0)
                                    .write_tlv(&reply_tlv)
                                    .to_vec())?;
                            self.inject(&self.state.version(), sender, otr_message);
                        }
                        match self.state.smp().unwrap().status() {
                            SMPStatus::InProgress => Ok(UserMessage::None),
                            SMPStatus::Completed => Ok(UserMessage::SMPSucceeded(self.receiver)),
                            SMPStatus::Aborted(_) => Ok(UserMessage::SMPFailed(self.receiver)),
                            SMPStatus::Initial => panic!("BUG: we should be able to reach after having processed an SMP message TLV."),
                        }
                    }
                    Ok(Message::Confidential(content, tlvs)) => Ok(UserMessage::Confidential(self.receiver, content, tlvs)),
                    Ok(Message::ConfidentialFinished(content)) => Ok(UserMessage::ConfidentialSessionFinished(self.receiver, content)),
                    Err(OTRError::UnreadableMessage(_)) if msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) => {
                        // For an unreadable message, even if the IGNORE_UNREADABLE flag is set, we
                        // need to send an OTR Error response, to indicate to the other user that
                        // we no longer have a correctly established OTR session.
                        self.host.inject(&self.address, &serialize_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Ok(UserMessage::None)
                    }
                    Err(OTRError::UnreadableMessage(_)) => {
                        self.host.inject(&self.address, &serialize_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Err(OTRError::UnreadableMessage(self.receiver))
                    }
                    Err(error) => {
                        // TODO do all these errors require Error Message response to other party?
                        log::debug!("Received unexpected error-type: {:?}", &error);
                        Err(error)
                    }
                }
            }
            (Version::V4, EncodedMessageType::Identity(message)) => {
                let response = self.dake.handle_identity(message, &self.details.account, &self.address)?;
                self.inject(&self.dake.version(), sender, response);
                Ok(UserMessage::None)
            }
            (Version::V4, EncodedMessageType::AuthR(message)) => {
                let (MixedKeyMaterial{ssid, double_ratchet, us, them}, response) = self.dake.handle_auth_r(message, &self.details.account, &self.address)?;
                self.inject(&self.dake.version(), sender, response);
                self.state = self.state.secure(Rc::clone(&self.host), self.details.tag, self.receiver, ProtocolMaterial::DAKE { ssid, double_ratchet, us, them });
                // TODO is this assertion valid? (what if we perform new DAKE while in encrypted session?)
                assert_eq!(ProtocolStatus::Encrypted, self.state.status());
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            (Version::V4, EncodedMessageType::AuthI(message)) => {
                let MixedKeyMaterial{ssid, double_ratchet, us, them} = self.dake.handle_auth_i(message, &self.details.account, &self.address)?;
                self.state = self.state.secure(Rc::clone(&self.host), self.details.tag, self.receiver, ProtocolMaterial::DAKE { ssid, double_ratchet, us, them });
                // TODO is this assertion valid? (what if we perform new DAKE while in encrypted session?)
                assert_eq!(ProtocolStatus::Encrypted, self.state.status());
                Ok(UserMessage::ConfidentialSessionStarted(self.receiver))
            }
            (Version::V4, EncodedMessageType::Data4(msg)) => {
                msg.validate()?;
                // Note that TLV 0 (Padding) and 1 (Disconnect) are already handled as part of the
                // protocol. Other TLVs that are their own protocol or function, therefore must be
                // handled separately.
                let authenticator_data = messages::encode_authenticator_data4(&version, sender, receiver, &msg);
                let (message, transition) = self.state.handle4(&msg, &authenticator_data);
                if transition.is_some() {
                    self.state = transition.unwrap();
                }
                match message {
                    Ok(Message::Confidential(content, tlvs)) if tlvs.iter().any(smp4::is_smp_tlv) => {
                        if !msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) {
                            log::warn!("Other client did not set IGNORE_UNREADABLE flag on SMP messages. This is preferred/recommended because these are OTR control messages, rather than user content.");
                        }
                        if !content.is_empty() {
                            log::warn!("OTRv4 SMP tlv messages are not expected to contain text content. This content is ignored.");
                        }
                        if tlvs.iter().filter(|t| smp4::is_smp_tlv(t)).count() > 1 {
                            // Given more than one SMP tlv, the order of processing impacts outcome.
                            // The protocol only specifies that a single SMP tlv is expected at any
                            // one time, so do not even attempt to process these. It is a violation.
                            log::warn!("OTRv4 more than one SMP tlv found. This is not expected according to the specification. Aborting further processing.");
                            return Err(OTRError::ProtocolViolation("SMP: more than one SMP tlv found. This cannot occur when protocol is properly followed."));
                        }
                        let Ok(smp4_context) = self.state.smp4_mut() else {
                            // SMP tlvs are only relevant in encrypted-messaging state. If we
                            // transitioned away just now, then this SMP tlv no longer has any value
                            // Log this somewhat peculiar circumstance and stop processing.
                            log::warn!("OTRv4 SMP state is no longer available. The state machine must have transitioned away before the SMP tlvs were processed. This seems to indicate a protocol violation. Ignoring this SMP tlv and returning result without user-content.");
                            return Err(OTRError::ProtocolViolation("OTRv4 SMP tlv being processed while the state machine has already transitioned away. This cannot happen in OTR unless the other client deviated from the protocol."));
                        };
                        // Socialist Millionaire Protocol (SMP) handling.
                        let tlv = tlvs.into_iter().find(smp4::is_smp_tlv).unwrap();
                        if let Some(response) = smp4_context.handle(&tlv) {
                            let otr_message = self.state.prepare(
                                MessageFlags::IGNORE_UNREADABLE,
                                &OTREncoder::new()
                                    .write_u8(0)
                                    .write_tlv(&response)
                                    .to_vec())?;
                            self.inject(&self.state.version(), sender, otr_message);
                        }
                        match self.state.smp4().unwrap().status() {
                            SMP4Status::InProgress => Ok(UserMessage::None),
                            SMP4Status::Completed => Ok(UserMessage::SMPSucceeded(self.receiver)),
                            SMP4Status::Aborted(_) => Ok(UserMessage::SMPFailed(self.receiver)),
                            SMP4Status::Initial => panic!("BUG: we should be able to reach after having processed an SMP message TLV."),
                        }
                    }
                    Ok(Message::Confidential(content, tlvs)) => Ok(UserMessage::Confidential(self.receiver, content, tlvs)),
                    Ok(Message::ConfidentialFinished(content)) => Ok(UserMessage::ConfidentialSessionFinished(self.receiver, content)),
                    Err(OTRError::UnreadableMessage(_)) if msg.flags.contains(MessageFlags::IGNORE_UNREADABLE) => {
                        log::debug!("Received unreadable message with flags {}", msg.flags.bits());
                        // For an unreadable message, even if the IGNORE_UNREADABLE flag is set, we
                        // need to send an OTR Error response, to indicate to the other user that
                        // we no longer have a correctly established OTR session.
                        self.host.inject(&self.address, &serialize_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Ok(UserMessage::None)
                    }
                    Err(OTRError::UnreadableMessage(_)) => {
                        self.host.inject(&self.address, &serialize_message(&MessageType::Error(
                            Vec::from("unreadable message")
                        )));
                        Err(OTRError::UnreadableMessage(self.receiver))
                    }
                    Err(error) => {
                        // TODO do all these errors require Error Message response to other party?
                        log::debug!("Received unexpected error-type: {:?}", &error);
                        Err(error)
                    }
                }
            }
            (_, EncodedMessageType::Unencoded(_)) => panic!("BUG: this message-type is used as a placeholder. It can never be an incoming message-type to be handled."),
            _ => Err(OTRError::ProtocolViolation("Illegal encoded message. Message ignored."))
        }
    }

    fn reset(&mut self) -> UserMessage {
        let previous = self.state.status();
        let version = self.state.version();
        let (abortmsg, newstate) = self.state.finish();
        self.state = newstate;
        if previous == self.state.status() {
            assert!(abortmsg.is_none());
            return UserMessage::None;
        }
        if let Some(msg) = abortmsg {
            self.inject(&version, self.receiver, msg);
        }
        UserMessage::Reset(self.receiver)
    }

    fn send(
        &mut self,
        whitespace_tagged: &mut bool,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>, OTRError> {
        let plaintext = utils::bytes::drop_by_value(plaintext, 0);
        match self.state.prepare(MessageFlags::empty(), &plaintext)? {
            EncodedMessageType::Unencoded(msg) => {
                log::trace!("Message prepared as unencoded message.");
                assert_eq!(
                    ProtocolStatus::Plaintext,
                    self.state.status(),
                    "BUG: received undefined message type in status {:?}",
                    self.state.status()
                );
                let versions = filter_versions(&self.details.policy, &SUPPORTED_VERSIONS);
                let message = if self.details.policy.contains(Policy::SEND_WHITESPACE_TAG)
                    && !*whitespace_tagged
                    && !versions.is_empty()
                {
                    *whitespace_tagged = true;
                    MessageType::Tagged(versions, msg)
                } else {
                    MessageType::Plaintext(msg)
                };
                Ok(vec![serialize_message(&message)])
            }
            message @ (EncodedMessageType::DHCommit(_)
            | EncodedMessageType::DHKey(_)
            | EncodedMessageType::RevealSignature(_)
            | EncodedMessageType::Signature(_)) => {
                log::trace!("Message prepared as OTR-encoded protocol message.");
                let content = encode_message(
                    &self.ake.version(),
                    self.details.tag,
                    self.receiver,
                    message,
                );
                Ok(self.prepare_payloads(&self.ake.version(), content))
            }
            message @ (EncodedMessageType::Identity(_)
            | EncodedMessageType::AuthR(_)
            | EncodedMessageType::AuthI(_)) => {
                log::trace!("Message prepared as OTR-encoded OTRv4 protocol message.");
                let content = encode_message(
                    &self.dake.version(),
                    self.details.tag,
                    self.receiver,
                    message,
                );
                Ok(self.prepare_payloads(&self.dake.version(), content))
            }
            message @ (EncodedMessageType::Data(_) | EncodedMessageType::Data4(_)) => {
                let content = encode_message(
                    &self.state.version(),
                    self.details.tag,
                    self.receiver,
                    message,
                );
                Ok(self.prepare_payloads(&self.state.version(), content))
            }
        }
    }

    fn prepare_payloads(&self, version: &Version, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let max_size = self.host.message_size();
        if payload.len() <= max_size {
            // send message-bytes as-is: fragmentation is not needed.
            vec![payload]
        } else {
            // fragmentation is needed: send multiple fragments instead.
            fragment::fragment(max_size, version, self.details.tag, self.receiver, &payload)
                .iter()
                .map(|f| OTREncoder::new().write_encodable(f).to_vec())
                .collect()
        }
    }

    fn start_smp(&mut self, secret: &[u8], question: &[u8]) -> Result<(), OTRError> {
        // logic currently assumes that if the call to smp succeeds, that we are in an appropriate
        // state to send a message with appended TLV.
        let tlv = self.state.smp_mut()?.initiate(secret, question)?;
        let message = self.state.prepare(
            MessageFlags::IGNORE_UNREADABLE,
            &OTREncoder::new().write_u8(0).write_tlv(&tlv).to_vec(),
        )?;
        self.inject(&self.state.version(), self.receiver, message);
        Ok(())
    }

    fn smp_ssid(&self) -> Result<SSID, OTRError> {
        Ok(self.state.smp()?.ssid())
    }

    fn abort_smp(&mut self) -> Result<(), OTRError> {
        let smp = self.state.smp_mut();
        if smp.is_err() {
            return Err(OTRError::IncorrectState(
                "SMP is unavailable in the current state",
            ));
        }
        let tlv = smp.unwrap().abort();
        let msg = self
            .state
            .prepare(
                MessageFlags::IGNORE_UNREADABLE,
                &OTREncoder::new().write_u8(0).write_tlv(&tlv).to_vec(),
            )
            .unwrap();
        self.inject(&self.state.version(), self.receiver, msg);
        Ok(())
    }

    fn inject(&self, version: &Version, receiver: InstanceTag, message: EncodedMessageType) {
        assert!(receiver != 0 && self.receiver == 0 || self.receiver == receiver);
        log::trace!(
            "Injecting encoded message with tag '{}' for '{}'.",
            self.details.tag,
            receiver
        );
        let content = encode_message(version, self.details.tag, self.receiver, message);
        let max_size = self.host.message_size();
        if content.len() <= max_size {
            self.host.inject(&self.address, &content);
        } else {
            for fragment in
                fragment::fragment(max_size, version, self.details.tag, self.receiver, &content)
                    .into_iter()
                    .map(|f| OTREncoder::new().write_encodable(&f).to_vec())
            {
                self.host.inject(&self.address, &fragment);
            }
        }
    }
}

/// `AccountDetails` contains our own, static details for an account shared among instances.
struct AccountDetails {
    policy: Policy,
    // TODO tag is duplicate with tag in client profile.
    tag: InstanceTag,
    account: Vec<u8>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn select_version(policy: &Policy, versions: &[Version]) -> Option<Version> {
    if versions.contains(&Version::V4) && policy.contains(Policy::ALLOW_V4) {
        Some(Version::V4)
    } else if versions.contains(&Version::V3) && policy.contains(Policy::ALLOW_V3) {
        Some(Version::V3)
    } else {
        None
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn filter_versions(policy: &Policy, versions: &[Version]) -> Vec<Version> {
    if versions.contains(&Version::V4) && policy.contains(Policy::ALLOW_V4) {
        vec![Version::V4]
    } else if versions.contains(&Version::V3) && policy.contains(Policy::ALLOW_V3) {
        vec![Version::V3]
    } else {
        Vec::new()
    }
}

#[allow(clippy::too_many_lines)]
#[cfg(test)]
mod tests {

    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    use crate::{
        crypto::{dsa, ed448},
        instancetag::INSTANCE_ZERO,
        Host, OTRError, Policy, ProtocolStatus, UserMessage,
    };

    use super::{Account, Session};

    #[allow(clippy::let_underscore_untyped)]
    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init();
    }

    // TODO test to prove: multiple simultaneous instances
    // TODO test with receiver tag in DH-Commit message. This will likely fail due to AKEContext transfer from instance 0.

    #[test]
    fn test_plaintext_conversation() {
        init();
        // Communicate in plaintext with the OTR logic being involved. This demonstrates that
        // plaintext messages can be sent regardless.
        let keypair_alice = dsa::Keypair::generate();
        let identity_alice = ed448::EdDSAKeyPair::generate();
        let forging_alice = ed448::EdDSAKeyPair::generate();
        let mut messages_alice: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));

        let keypair_bob = dsa::Keypair::generate();
        let identity_bob = ed448::EdDSAKeyPair::generate();
        let forging_bob = ed448::EdDSAKeyPair::generate();
        let mut messages_bob: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));

        let host_alice: Rc<dyn Host> = Rc::new(TestHost(
            Rc::clone(&messages_bob),
            keypair_alice,
            usize::MAX,
            identity_alice,
            forging_alice,
            RefCell::new(Vec::new()),
        ));
        let mut account_alice =
            Account::new(Vec::from("alice"), Policy::ALLOW_V3, Rc::clone(&host_alice)).unwrap();
        let alice = account_alice.session(b"bob");
        let host_bob: Rc<dyn Host> = Rc::new(TestHost(
            Rc::clone(&messages_alice),
            keypair_bob,
            usize::MAX,
            identity_bob,
            forging_bob,
            RefCell::new(Vec::new()),
        ));
        let mut account_bob =
            Account::new(Vec::from("bob"), Policy::ALLOW_V3, Rc::clone(&host_bob)).unwrap();
        let bob = account_bob.session(b"alice");

        messages_bob
            .borrow_mut()
            .extend(alice.send(INSTANCE_ZERO, b"Hello bob!").unwrap());
        handle_messages("Bob", &mut messages_bob, bob);
        messages_alice
            .borrow_mut()
            .extend(bob.send(INSTANCE_ZERO, b"Hello Alice!").unwrap());
        handle_messages("Alice", &mut messages_alice, alice);
    }

    #[test]
    fn test_my_first_otr_session() {
        init();
        // Verify that an OTR encrypted session can be established. Send messages to ensure
        // communication is possible over this confidential session. One side ends the session while
        // the other one continues communicating, to ensure that messages do not unintentionally
        // pass through unencrypted. Finally, finalize the session on the other side to end up with
        // two plaintext sessions, the same as we started with.
        let keypair_alice = dsa::Keypair::generate();
        let identity_alice = ed448::EdDSAKeyPair::generate();
        let forging_alice = ed448::EdDSAKeyPair::generate();
        let mut messages_alice: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));

        let keypair_bob = dsa::Keypair::generate();
        let identity_bob = ed448::EdDSAKeyPair::generate();
        let forging_bob = ed448::EdDSAKeyPair::generate();
        let mut messages_bob: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));

        let host_alice: Rc<dyn Host> = Rc::new(TestHost(
            Rc::clone(&messages_bob),
            keypair_alice,
            usize::MAX,
            identity_alice,
            forging_alice,
            RefCell::new(Vec::new()),
        ));
        let mut account_alice =
            Account::new(Vec::from("alice"), Policy::ALLOW_V3, Rc::clone(&host_alice)).unwrap();
        let alice = account_alice.session(b"bob");
        let host_bob: Rc<dyn Host> = Rc::new(TestHost(
            Rc::clone(&messages_alice),
            keypair_bob,
            usize::MAX,
            identity_bob,
            forging_bob,
            RefCell::new(Vec::new()),
        ));
        let mut account_bob =
            Account::new(Vec::from("bob"), Policy::ALLOW_V3, Rc::clone(&host_bob)).unwrap();
        let bob = account_bob.session(b"alice");

        alice.query().unwrap();
        assert!(handle_messages("Alice", &mut messages_alice, alice).is_none());
        assert!(handle_messages("Bob", &mut messages_bob, bob).is_none());
        assert!(handle_messages("Alice", &mut messages_alice, alice).is_none());
        assert!(handle_messages("Bob", &mut messages_bob, bob).is_none());
        let result = handle_messages("Alice", &mut messages_alice, alice).unwrap();
        let UserMessage::ConfidentialSessionStarted(tag_bob) = result else {
            panic!("BUG: expected confidential session to have started now.")
        };
        assert_eq!(Some(ProtocolStatus::Encrypted), alice.status(tag_bob));
        messages_bob.borrow_mut().extend(
            alice
                .send(tag_bob, b"Hello Bob! Are we chatting confidentially now?")
                .unwrap(),
        );
        let result = handle_messages("Bob", &mut messages_bob, bob).unwrap();
        let UserMessage::ConfidentialSessionStarted(tag_alice) = result else {
            panic!("BUG: expected confidential session to have started now.")
        };
        assert_eq!(Some(ProtocolStatus::Encrypted), bob.status(tag_alice));
        assert!(matches!(
            handle_messages("Bob", &mut messages_bob, bob),
            Some(UserMessage::Confidential(_, _, _))
        ));
        messages_alice
            .borrow_mut()
            .extend(bob.send(tag_alice, b"Hi Alice! I think we are!").unwrap());
        messages_alice
            .borrow_mut()
            .extend(bob.send(tag_alice, b"KTHXBYE!").unwrap());
        assert!(matches!(
            bob.end(tag_alice),
            Ok(UserMessage::Reset(tag)) if tag == tag_alice
        ));
        assert!(matches!(
            bob.status(tag_alice),
            Some(ProtocolStatus::Plaintext)
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::Confidential(_, _, _))
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::Confidential(_, _, _))
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::ConfidentialSessionFinished(_, _))
        ));
        assert_eq!(Some(ProtocolStatus::Finished), alice.status(tag_bob));
        assert!(matches!(
            alice.send(tag_bob, b"Hey, wait up!!!"),
            Err(OTRError::IncorrectState(_))
        ));
        assert!(matches!(
            alice.end(tag_bob),
            Ok(UserMessage::Reset(tag)) if tag == tag_bob
        ));
        assert!(matches!(
            alice.status(tag_bob),
            Some(ProtocolStatus::Plaintext)
        ));
        assert!(messages_bob.borrow().is_empty());
        assert!(messages_alice.borrow().is_empty());
    }

    #[test]
    fn test_my_first_otr4_session() {
        init();
        // Verify that an OTR-encrypted session can be established. Send messages to ensure
        // communication is possible over this confidential session. One side ends the session while
        // the other one continues communicating, to ensure that messages do not unintentionally
        // pass through unencrypted. Finally, finalize the session on the other side to end up with
        // two plaintext sessions, the same as we started with.
        let mut messages_alice: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));
        let mut messages_bob: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));
        let mut account_alice = Account::new(
            Vec::from("alice"),
            Policy::ALLOW_V4,
            Rc::new(TestHost(
                Rc::clone(&messages_bob),
                dsa::Keypair::generate(),
                usize::MAX,
                ed448::EdDSAKeyPair::generate(),
                ed448::EdDSAKeyPair::generate(),
                RefCell::new(Vec::new()),
            )),
        )
        .unwrap();
        let alice = account_alice.session(b"bob");
        let mut account_bob = Account::new(
            Vec::from("bob"),
            Policy::ALLOW_V4,
            Rc::new(TestHost(
                Rc::clone(&messages_alice),
                dsa::Keypair::generate(),
                usize::MAX,
                ed448::EdDSAKeyPair::generate(),
                ed448::EdDSAKeyPair::generate(),
                RefCell::new(Vec::new()),
            )),
        )
        .unwrap();
        let bob = account_bob.session(b"alice");

        alice.query().unwrap();
        assert!(handle_messages("Alice", &mut messages_alice, alice).is_none());
        assert!(handle_messages("Bob", &mut messages_bob, bob).is_none());
        assert!(handle_messages("Alice", &mut messages_alice, alice).is_none());
        let result = handle_messages("Bob", &mut messages_bob, bob);
        let Some(UserMessage::ConfidentialSessionStarted(tag_alice)) = result else {
            panic!("BUG: expected confidential session to have started now.")
        };
        assert_eq!(Some(ProtocolStatus::Encrypted), bob.status(tag_alice));
        let result = handle_messages("Alice", &mut messages_alice, alice).unwrap();
        let UserMessage::ConfidentialSessionStarted(tag_bob) = result else {
            panic!("BUG: expected confidential session to have started now.")
        };
        assert_eq!(Some(ProtocolStatus::Encrypted), alice.status(tag_bob));
        messages_bob.borrow_mut().extend(
            alice
                .send(tag_bob, b"Hello Bob! Are we chatting confidentially now?")
                .unwrap(),
        );
        assert!(matches!(
            handle_messages("Bob", &mut messages_bob, bob),
            Some(UserMessage::Confidential(_, _, _))
        ));
        messages_alice
            .borrow_mut()
            .extend(bob.send(tag_alice, b"Hi Alice! I think we are!").unwrap());
        messages_alice
            .borrow_mut()
            .extend(bob.send(tag_alice, b"KTHXBYE!").unwrap());
        assert!(matches!(
            bob.end(tag_alice),
            Ok(UserMessage::Reset(tag)) if tag == tag_alice
        ));
        assert!(matches!(
            bob.status(tag_alice),
            Some(ProtocolStatus::Plaintext)
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::Confidential(_, _, _))
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::Confidential(_, _, _))
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::ConfidentialSessionFinished(_, _))
        ));
        assert_eq!(Some(ProtocolStatus::Finished), alice.status(tag_bob));
        assert!(matches!(
            alice.send(tag_bob, b"Hey, wait up!!!"),
            Err(OTRError::IncorrectState(_))
        ));
        assert!(matches!(
            alice.end(tag_bob),
            Ok(UserMessage::Reset(tag)) if tag == tag_bob
        ));
        assert!(matches!(
            alice.status(tag_bob),
            Some(ProtocolStatus::Plaintext)
        ));
        assert!(messages_bob.borrow().is_empty());
        assert!(messages_alice.borrow().is_empty());
    }

    #[test]
    fn test_fragmented_otr_session() {
        init();
        // Verify that an OTR encrypted session can be established, even with need for
        // fragmentation. Maximum message sizes allowed for communication are specific for each side
        // to ensure that difference caused by length of user name, nickname, etc. are allowed.
        // Send messages to ensure communication is possible over this confidential session. One
        // side ends the session while the other one continues communicating, to ensure that
        // messages do not unintentionally pass through unencrypted. Finally, finalize the session
        // on the other side to end up with two plaintext sessions, the same as we started with.
        let mut messages_alice: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));
        let mut messages_bob: Rc<RefCell<VecDeque<Vec<u8>>>> =
            Rc::new(RefCell::new(VecDeque::new()));
        let mut account_alice = Account::new(
            Vec::from("alice"),
            Policy::ALLOW_V3,
            Rc::new(TestHost(
                Rc::clone(&messages_bob),
                dsa::Keypair::generate(),
                50,
                ed448::EdDSAKeyPair::generate(),
                ed448::EdDSAKeyPair::generate(),
                RefCell::new(Vec::new()),
            )),
        )
        .unwrap();
        let alice = account_alice.session(b"bob");
        let mut account_bob = Account::new(
            Vec::from("bob"),
            Policy::ALLOW_V3,
            Rc::new(TestHost(
                Rc::clone(&messages_alice),
                dsa::Keypair::generate(),
                55,
                ed448::EdDSAKeyPair::generate(),
                ed448::EdDSAKeyPair::generate(),
                RefCell::new(Vec::new()),
            )),
        )
        .unwrap();
        let bob = account_bob.session(b"alice");

        alice.query().unwrap();
        assert!(handle_messages("Alice", &mut messages_alice, alice).is_none());
        assert!(handle_messages("Bob", &mut messages_bob, bob).is_none());
        assert!(handle_messages("Alice", &mut messages_alice, alice).is_none());
        assert!(handle_messages("Bob", &mut messages_bob, bob).is_none());
        let result = handle_messages("Alice", &mut messages_alice, alice).unwrap();
        let UserMessage::ConfidentialSessionStarted(tag_bob) = result else {
            panic!("BUG: expected confidential session to have started now.")
        };
        assert_eq!(Some(ProtocolStatus::Encrypted), alice.status(tag_bob));
        messages_bob.borrow_mut().extend(
            alice
                .send(tag_bob, b"Hello Bob! Are we chatting confidentially now?")
                .unwrap(),
        );
        let result = handle_messages("Bob", &mut messages_bob, bob).unwrap();
        let UserMessage::ConfidentialSessionStarted(tag_alice) = result else {
            panic!("BUG: expected confidential session to have started now.")
        };
        assert_eq!(Some(ProtocolStatus::Encrypted), bob.status(tag_alice));
        assert!(matches!(
            handle_messages("Bob", &mut messages_bob, bob),
            Some(UserMessage::Confidential(_, _, _))
        ));
        messages_alice
            .borrow_mut()
            .extend(bob.send(tag_alice, b"Hi Alice! I think we are!").unwrap());
        messages_alice
            .borrow_mut()
            .extend(bob.send(tag_alice, b"KTHXBYE!").unwrap());
        assert!(matches!(
            bob.end(tag_alice),
            Ok(UserMessage::Reset(tag)) if tag == tag_alice
        ));
        assert!(matches!(
            bob.status(tag_alice),
            Some(ProtocolStatus::Plaintext)
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::Confidential(_, _, _))
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::Confidential(_, _, _))
        ));
        assert!(matches!(
            handle_messages("Alice", &mut messages_alice, alice),
            Some(UserMessage::ConfidentialSessionFinished(_, _))
        ));
        assert_eq!(Some(ProtocolStatus::Finished), alice.status(tag_bob));
        assert!(matches!(
            alice.send(tag_bob, b"Hey, wait up!!!"),
            Err(OTRError::IncorrectState(_))
        ));
        assert!(matches!(
            alice.end(tag_bob),
            Ok(UserMessage::Reset(tag)) if tag == tag_bob
        ));
        assert!(matches!(
            alice.status(tag_bob),
            Some(ProtocolStatus::Plaintext)
        ));
        assert!(messages_bob.borrow().is_empty());
        assert!(messages_alice.borrow().is_empty());
    }

    struct TestHost(
        Rc<RefCell<VecDeque<Vec<u8>>>>,
        dsa::Keypair,
        usize,
        ed448::EdDSAKeyPair,
        ed448::EdDSAKeyPair,
        RefCell<Vec<u8>>,
    );

    impl Host for TestHost {
        fn message_size(&self) -> usize {
            self.2
        }

        fn inject(&self, _address: &[u8], message: &[u8]) {
            self.0.borrow_mut().push_back(Vec::from(message));
        }

        fn keypair(&self) -> Option<&dsa::Keypair> {
            Some(&self.1)
        }

        fn keypair_identity(&self) -> &crate::crypto::ed448::EdDSAKeyPair {
            &self.3
        }

        fn keypair_forging(&self) -> &crate::crypto::ed448::EdDSAKeyPair {
            &self.4
        }

        fn query_smp_secret(&self, _question: &[u8]) -> Option<Vec<u8>> {
            Some(b"Password!".to_vec())
        }

        fn client_profile(&self) -> Vec<u8> {
            self.5.borrow().clone()
        }

        fn update_client_profile(&self, encoded_payload: Vec<u8>) {
            self.5.replace(encoded_payload);
        }
    }

    fn handle_messages(
        id: &str,
        channel: &mut Rc<RefCell<VecDeque<Vec<u8>>>>,
        session: &mut Session,
    ) -> Option<UserMessage> {
        println!("Messages available: {}", channel.borrow_mut().len());
        while let Some(m) = channel.borrow_mut().pop_front() {
            println!(
                "{}: processing message `{}`",
                id,
                core::str::from_utf8(&m).unwrap()
            );
            let message = session.receive(&m).unwrap();
            extract_readable(id, &message);
            if let UserMessage::None = message {
                // nothing worthwhile, continue with possible next message
            } else {
                return Some(message);
            }
        }
        None
    }

    fn extract_readable(id: &str, msg: &UserMessage) {
        match msg {
            UserMessage::None => println!("{id}: (none)"),
            UserMessage::Plaintext(msg) => {
                println!("{id}: {}", core::str::from_utf8(msg).unwrap());
            }
            UserMessage::ConfidentialSessionStarted(tag) => {
                println!("{id}: confidential session started for instance {tag}");
            }
            UserMessage::Confidential(tag, message, tlvs) => println!(
                "{id}: confidential message on {tag}: {} (TLVs: {tlvs:?})",
                core::str::from_utf8(message).unwrap(),
            ),
            UserMessage::ConfidentialSessionFinished(tag, content) => {
                println!(
                    "{id}: confidential session finished for instance {tag} (\"{}\")",
                    core::str::from_utf8(content).unwrap()
                );
            }
            UserMessage::WarningUnencrypted(content) => {
                println!(
                    "{id} WARNING: unencrypted message: {})",
                    core::str::from_utf8(content).unwrap()
                );
            }
            msg => todo!(
                "{}: [test utils: extract_readable]: To be implemented: {:?}",
                id,
                msg
            ),
        }
    }
}

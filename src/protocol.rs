// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    crypto::{chacha20, constant, dh, dsa, otr, otr4, sha1},
    encoding::{MessageFlags, OTRDecoder, OTREncoder, FINGERPRINT_LEN, MAC_LEN, TLV},
    instancetag::{InstanceTag, INSTANCE_ZERO},
    keymanager::KeyManager,
    messages::{self, encode_authenticator_data, DataMessage, DataMessage4, EncodedMessageType},
    smp::SMPContext,
    smp4::SMP4Context,
    utils, Host, OTRError, ProtocolStatus, TLVType, Version, SSID,
};

/// `TLV_TYPE_0_PADDING` is the TLV that can be used to introduce arbitrary-length padding to an
/// encrypted message.
const TLV_TYPE_0_PADDING: TLVType = 0;

/// `TLV_TYPE_1_DISCONNECT` is the TLV that signals a disconnect.
const TLV_TYPE_1_DISCONNECT: TLVType = 1;

pub trait ProtocolState {
    /// `status` indicates the protocol status of the current state, i.e. plaintext, encrypted,
    /// finished. It indicates whether a secure session is active at the time.
    fn status(&self) -> ProtocolStatus;
    /// `version` indicates the protocol version that is in effect, i.e. version 3, version 4, etc.
    /// Although, in general the version is only relevant if in encrypted messaging-state, it may
    /// (in the future) indicate a version of the `Finished` state such that we can use the version
    /// indication to prevent transitioning from a finished version 4 session immediately into a
    /// encrypted version 3 session, i.e. a (somewhat covert) session downgrade if performed
    /// sufficiently fast. (Use `status()` for reliably indicator of protocol status.)
    fn version(&self) -> Version;
    /// handle processes a received message in accordance with the active protocol state.
    fn handle(
        &mut self,
        msg: &DataMessage,
        authenticator: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn handle4(
        &mut self,
        msg: &DataMessage4,
        authenticator: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    // TODO consider defining a common EncryptedState trait to be shared with OTR2/OTR3 and OTR4.
    #[allow(clippy::too_many_arguments)]
    fn secure(
        &self,
        host: Rc<dyn Host>,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        material: ProtocolMaterial,
    ) -> Box<dyn ProtocolState>;
    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>);
    fn expire(&mut self, timeout: u64) -> Option<(EncodedMessageType, Box<FinishedState>)>;
    /// prepare prepares a message for sending in accordance with the active protocol state.
    fn prepare(
        &mut self,
        flags: MessageFlags,
        content: &[u8],
    ) -> Result<EncodedMessageType, OTRError>;
    fn smp(&self) -> Result<&SMPContext, OTRError>;
    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError>;
    fn smp4(&self) -> Result<&SMP4Context, OTRError>;
    fn smp4_mut(&mut self) -> Result<&mut SMP4Context, OTRError>;
}

pub fn new_state() -> Box<dyn ProtocolState> {
    Box::new(PlaintextState {})
}

pub struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Plaintext
    }

    fn version(&self) -> Version {
        Version::None
    }

    fn handle(
        &mut self,
        _: &DataMessage,
        _: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("PLAINTEXT: handling OTR DATA message… rejected.");
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn handle4(
        &mut self,
        _: &DataMessage4,
        _: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("PLAINTEXT: handling OTRv4 DATA message… rejected.");
        // TODO use ERROR_2 error code
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        material: ProtocolMaterial,
    ) -> Box<dyn ProtocolState> {
        match material {
            ProtocolMaterial::AKE {
                ssid,
                our_dh,
                their_dh,
                their_dsa,
            } => Box::new(EncryptedOTR3State::new(
                host,
                our_instance,
                their_instance,
                ssid,
                our_dh,
                their_dh,
                otr::fingerprint(&their_dsa),
            )),
            ProtocolMaterial::DAKE {
                ssid,
                double_ratchet,
                us,
                them,
            } => Box::new(EncryptedOTR4State {
                our_instance,
                their_instance,
                double_ratchet,
                smp: SMP4Context::new(host, us, them, ssid),
            }),
        }
    }

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn expire(&mut self, _: u64) -> Option<(EncodedMessageType, Box<FinishedState>)> {
        // Not in encrypted message-state.
        None
    }

    fn prepare(&mut self, _: MessageFlags, content: &[u8]) -> Result<EncodedMessageType, OTRError> {
        // Returned as 'Undefined' message as we are not in an encrypted state, therefore we return
        // the content as-is to the caller.
        Ok(EncodedMessageType::Unencoded(Vec::from(content)))
    }

    fn smp(&self) -> Result<&SMPContext, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP is not available when protocol is in Plaintext state.",
        ))
    }

    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP is not available when protocol is in Plaintext state.",
        ))
    }

    fn smp4(&self) -> Result<&SMP4Context, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP4 is not available when protocol is in Plaintext state.",
        ))
    }

    fn smp4_mut(&mut self) -> Result<&mut SMP4Context, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP4 is not available when protocol is in Plaintext state.",
        ))
    }
}

// TODO can we introduce a reasonable mechanism for expiration in OTR3 that doesn't cause issues with protocol (probably)
pub struct EncryptedOTR3State {
    our_instance: InstanceTag,
    their_instance: InstanceTag,
    keys: KeyManager,
    smp: SMPContext,
}

impl ProtocolState for EncryptedOTR3State {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Encrypted
    }

    fn version(&self) -> Version {
        Version::V3
    }

    fn handle(
        &mut self,
        msg: &DataMessage,
        authenticator_data: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("ENCRYPTED(OTR): handling OTR DATA message…");
        if msg.revealed.len() % 20 != 0
            || (!msg.revealed.is_empty() && utils::bytes::all_zero(&msg.revealed))
        {
            log::info!("NOTE: revealed MAC keys in received data message do not satisfy protocol expectations.");
        }
        match self.decrypt_message(msg, authenticator_data) {
            Ok(decrypted) => match parse_message(&decrypted) {
                msg @ Ok(Message::ConfidentialFinished(_)) => {
                    (msg, Some(Box::new(FinishedState {})))
                }
                msg @ Ok(_) => (msg, None),
                err @ Err(_) => {
                    // TODO if parsing message produces error, should we transition to different state or ignore? (protocol violation) ERROR_START_AKE seems to indicate that we need to assume the session is lost if OTR Error is received.
                    (err, None)
                }
            },
            Err(_) => {
                // TODO consider logging the details of the error message, but for the client it is not relevant
                (Err(OTRError::UnreadableMessage(self.their_instance)), None)
            }
        }
    }

    fn handle4(
        &mut self,
        _: &DataMessage4,
        _: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("ENCRYPTED(OTR): handling OTRv4 DATA message… rejected.");
        // TODO use ERROR_2 error code
        (Err(OTRError::UnreadableMessage(self.their_instance)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        material: ProtocolMaterial,
    ) -> Box<dyn ProtocolState> {
        // There is no indication in the OTRv3 spec that there are issues with re-transitioning into
        // `MSGSTATE_ENCRYPTED`. There does not seem to be an issue, and it also means that AKEs
        // during `MSGSTATE_ENCRYPTED` are possible as well.
        match material {
            ProtocolMaterial::AKE {
                ssid,
                our_dh,
                their_dh,
                their_dsa,
            } => Box::new(Self::new(
                host,
                our_instance,
                their_instance,
                ssid,
                our_dh,
                their_dh,
                otr::fingerprint(&their_dsa),
            )),
            ProtocolMaterial::DAKE {
                ssid,
                double_ratchet,
                us,
                them,
            } => Box::new(EncryptedOTR4State {
                our_instance,
                their_instance,
                double_ratchet,
                smp: SMP4Context::new(host, us, them, ssid),
            }),
        }
    }

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        let plaintext = OTREncoder::new()
            .write_u8(0)
            .write_tlv(&TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
            .to_vec();
        let optabort = Some(EncodedMessageType::Data(
            self.encrypt_message(MessageFlags::IGNORE_UNREADABLE, &plaintext),
        ));
        (optabort, Box::new(PlaintextState {}))
    }

    fn expire(&mut self, _: u64) -> Option<(EncodedMessageType, Box<FinishedState>)> {
        // TODO implement OTR3 session expiration.
        None
    }

    fn prepare(
        &mut self,
        flags: MessageFlags,
        content: &[u8],
    ) -> Result<EncodedMessageType, OTRError> {
        Ok(EncodedMessageType::Data(
            self.encrypt_message(flags, content),
        ))
    }

    fn smp(&self) -> Result<&SMPContext, OTRError> {
        Ok(&self.smp)
    }

    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError> {
        Ok(&mut self.smp)
    }

    fn smp4(&self) -> Result<&SMP4Context, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP4 is not available when protocol is in OTRv3 Encrypted state.",
        ))
    }

    fn smp4_mut(&mut self) -> Result<&mut SMP4Context, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP4 is not available when protocol is in OTRv3 Encrypted state.",
        ))
    }
}

impl EncryptedOTR3State {
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn new(
        host: Rc<dyn Host>,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_fingerprint: [u8; FINGERPRINT_LEN],
    ) -> Self {
        Self {
            our_instance,
            their_instance,
            keys: KeyManager::new((1, our_dh), (1, their_dh)),
            smp: SMPContext::new(Rc::clone(&host), ssid, their_fingerprint),
        }
    }

    fn encrypt_message(&mut self, flags: MessageFlags, plaintext_message: &[u8]) -> DataMessage {
        let ctr = self.keys.take_counter();
        let (receiver_keyid, receiver_key) = self.keys.their_current();
        let (our_keyid, our_dh) = self.keys.current_keys();
        let next_dh = self.keys.next_keys().1.public().clone();
        let shared_secret = self.keys.current_shared_secret();
        let secbytes = OTREncoder::new().write_mpi(&shared_secret).to_vec();
        let secrets = otr::DataSecrets::derive(our_dh.public(), receiver_key, &secbytes);
        let mut nonce = [0u8; 16];
        utils::slice::copy(&mut nonce, &ctr);
        let ciphertext = secrets
            .sender_crypt_key()
            .encrypt(&nonce, plaintext_message);
        assert!(utils::bytes::any_nonzero(&ciphertext));
        let oldmackeys = self.keys.get_reveal_macs();
        assert_eq!(oldmackeys.len() % 20, 0);
        assert!(oldmackeys.is_empty() || utils::bytes::any_nonzero(&oldmackeys));

        // Create data message without valid authenticator.
        let mut data_message = DataMessage {
            flags,
            sender_keyid: our_keyid,
            receiver_keyid,
            dh_y: next_dh,
            ctr,
            encrypted: ciphertext,
            authenticator: [0u8; MAC_LEN],
            revealed: oldmackeys,
        };

        // Generate authenticator for data message, then update data message with correct
        // authenticator.
        let authenticator = sha1::hmac(
            &secrets.sender_mac_key(),
            &encode_authenticator_data(
                &Version::V3,
                self.our_instance,
                self.their_instance,
                &data_message,
            ),
        );
        data_message.authenticator = authenticator;
        assert!(
            utils::bytes::any_nonzero(&data_message.authenticator),
            "BUG: authenticator is all zero-bytes. This is very unlikely."
        );
        data_message
    }

    fn decrypt_message(
        &mut self,
        message: &DataMessage,
        authenticator_data: &[u8],
    ) -> Result<Vec<u8>, OTRError> {
        log::debug!("Decrypting confidential message ...");
        // "Uses Diffie-Hellman to compute a shared secret from the two keys labelled by keyidA and
        //  keyidB, and generates the receiving AES key, ek, and the receiving MAC key, mk, as
        //  detailed below. (These will be the same as the keys Alice generated, above.)"
        let their_key = self.keys.their_key(message.sender_keyid)?;
        let our_dh = self.keys.our_keys(message.receiver_keyid)?;
        let secbytes = OTREncoder::new()
            .write_mpi(&our_dh.generate_shared_secret(their_key))
            .to_vec();
        let secrets = otr::DataSecrets::derive(our_dh.public(), their_key, &secbytes);
        // "Uses mk to verify MACmk(TA)."
        let receiving_mac_key = secrets.receiver_mac_key();
        let authenticator = sha1::hmac(&receiving_mac_key, authenticator_data);
        constant::compare_bytes_distinct(&message.authenticator, &authenticator)
            .map_err(OTRError::CryptographicViolation)?;
        log::debug!("Authenticator of received confidential message verified.");
        self.keys.register_used_mac_key(receiving_mac_key);
        // "Uses ek and ctr to decrypt AES-CTRek,ctr(msg)."
        self.keys.verify_counter(&message.ctr)?;
        let mut nonce = [0u8; 16];
        utils::slice::copy(&mut nonce, &message.ctr);
        utils::bytes::verify_nonzero(
            &nonce,
            OTRError::ProtocolViolation("Nonce contains all zero-bytes."),
        )?;
        self.keys.acknowledge_ours(message.receiver_keyid)?;
        self.keys
            .register_their_key(message.sender_keyid + 1, message.dh_y.clone())?;
        // finally, return the message
        log::debug!("Decrypting and returning confidential message.");
        Ok(secrets
            .receiver_crypt_key()
            .decrypt(&nonce, &message.encrypted))
    }
}

pub struct EncryptedOTR4State {
    our_instance: InstanceTag,
    their_instance: InstanceTag,
    double_ratchet: otr4::DoubleRatchet,
    smp: SMP4Context,
}

impl ProtocolState for EncryptedOTR4State {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Encrypted
    }

    fn version(&self) -> Version {
        Version::V4
    }

    fn handle(
        &mut self,
        _: &DataMessage,
        _: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("ENCRYPTED(OTRv4): handling OTR DATA message… rejected.");
        (Err(OTRError::UnreadableMessage(self.their_instance)), None)
    }

    fn handle4(
        &mut self,
        msg: &DataMessage4,
        authenticator_data: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("ENCRYPTED(OTRv4): handling OTRv4 DATA message…");
        match self.decrypt_message(msg, authenticator_data) {
            Ok(decrypted) => match parse_message(&decrypted) {
                msg @ Ok(Message::ConfidentialFinished(_)) => {
                    (msg, Some(Box::new(FinishedState {})))
                }
                msg @ Ok(_) => (msg, None),
                err @ Err(_) => {
                    // TODO if parsing message produces error, should we transition to different state or ignore? (protocol violation) ERROR_START_AKE seems to indicate that we need to assume the session is lost if OTR Error is received.
                    (err, None)
                }
            },
            Err(_) => {
                // TODO consider logging the details of the error message, but for the client it is not relevant
                // TODO use ERROR_2 error code
                (Err(OTRError::UnreadableMessage(self.their_instance)), None)
            }
        }
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        material: ProtocolMaterial,
    ) -> Box<dyn ProtocolState> {
        match material {
            ProtocolMaterial::AKE {
                ssid: _,
                our_dh: _,
                their_dh: _,
                their_dsa: _,
            } => {
                panic!("BUG: do not allow transitioning to a lower version of the OTR protocol.")
            }
            ProtocolMaterial::DAKE {
                ssid,
                double_ratchet,
                us,
                them,
            } => Box::new(Self {
                our_instance,
                their_instance,
                double_ratchet,
                smp: SMP4Context::new(host, us, them, ssid),
            }),
        }
    }

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        let content = OTREncoder::new()
            .write_u8(0)
            .write_tlv(&TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
            .to_vec();
        // TODO generate MK_mac reveals for stored message keys when stored message keys are implemented.
        let reveals = self.double_ratchet.collect_reveals();
        let optabort = Some(EncodedMessageType::Data4(self.encrypt_message(
            MessageFlags::IGNORE_UNREADABLE,
            &content,
            reveals,
        )));
        (optabort, Box::new(PlaintextState {}))
    }

    fn expire(&mut self, timeout: u64) -> Option<(EncodedMessageType, Box<FinishedState>)> {
        if self.double_ratchet.created().elapsed().as_secs() < timeout {
            return None;
        }
        let content = OTREncoder::new()
            .write_u8(0)
            .write_tlv(&TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
            .to_vec();
        // TODO generate MK_mac reveals for stored message keys when stored message keys are implemented.
        let reveals = self.double_ratchet.collect_reveals();
        let abort = EncodedMessageType::Data4(self.encrypt_message(
            MessageFlags::IGNORE_UNREADABLE,
            &content,
            reveals,
        ));
        Some((abort, Box::new(FinishedState {})))
    }

    fn prepare(
        &mut self,
        flags: MessageFlags,
        content: &[u8],
    ) -> Result<EncodedMessageType, OTRError> {
        Ok(EncodedMessageType::Data4(self.encrypt_message(
            flags,
            content,
            Vec::new(),
        )))
    }

    fn smp(&self) -> Result<&SMPContext, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP (version 3) is not available when protocol is in OTRv4 Encrypted state.",
        ))
    }

    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP (version 3) is not available when protocol is in OTRv4 Encrypted state.",
        ))
    }

    fn smp4(&self) -> Result<&SMP4Context, OTRError> {
        Ok(&self.smp)
    }

    fn smp4_mut(&mut self) -> Result<&mut SMP4Context, OTRError> {
        Ok(&mut self.smp)
    }
}

impl EncryptedOTR4State {
    fn encrypt_message(
        &mut self,
        flags: MessageFlags,
        content: &[u8],
        mut reveals: Vec<u8>,
    ) -> DataMessage4 {
        log::trace!(
            "Current double ratchet state: i={}, j={}, k={}",
            self.double_ratchet.i(),
            self.double_ratchet.j(),
            self.double_ratchet.k()
        );
        if self.double_ratchet.next() == otr4::Selector::SENDER {
            // ratchet and immediately persist
            reveals.extend(self.double_ratchet.collect_reveals());
            self.double_ratchet = self.double_ratchet.rotate_sender();
        }
        let keys = self.double_ratchet.sender_keys();
        let encrypted = chacha20::encrypt(Self::extract_encryption_key(&keys.0), content);
        let msg_i = self.double_ratchet.i().saturating_sub(1);
        let dh = if msg_i % 3 == 0 {
            Some(self.double_ratchet.dh_public().clone())
        } else {
            None
        };
        let mut message = DataMessage4 {
            flags,
            pn: self.double_ratchet.pn(),
            // TODO do I understand correctly that `saturating_sub` will stay 0 if 1 subtracted from 0?
            i: msg_i,
            j: self.double_ratchet.j(),
            ecdh: self.double_ratchet.ecdh_public().clone(),
            dh,
            encrypted,
            authenticator: [0u8; otr4::MAC_LENGTH],
            revealed: reveals,
        };
        let authenticator_data = messages::encode_authenticator_data4(
            &self.version(),
            self.our_instance,
            self.their_instance,
            &message,
        );
        message.authenticator = otr4::kdf2::<{ otr4::MAC_LENGTH }>(
            otr4::USAGE_AUTHENTICATOR,
            &keys.1,
            &authenticator_data,
        );
        debug_assert!(message.validate().is_ok());
        self.double_ratchet.rotate_sender_chainkey();
        message
    }

    fn decrypt_message(
        &mut self,
        msg: &DataMessage4,
        authenticator_data: &[u8],
    ) -> Result<Vec<u8>, OTRError> {
        log::debug!("OTRv4: decrypting data message…");
        log::trace!(
            "Current double ratchet state: i={}, j={}, k={}",
            self.double_ratchet.i(),
            self.double_ratchet.j(),
            self.double_ratchet.k()
        );
        log::trace!(
            "Data-message: flags={}, pn={}, i={}, j={}, content=[{}], reveals={}",
            msg.flags.bits(),
            msg.pn,
            msg.i,
            msg.j,
            msg.encrypted.len(),
            msg.revealed.len() / otr4::MAC_LENGTH,
        );
        if msg.i > self.double_ratchet.i() {
            return Err(OTRError::ProtocolViolation(
                "Message contains illegal content: ratchet ID cannot be in the far future.",
            ));
        }
        let current_ratchet = self.double_ratchet.i().saturating_sub(1);
        let mut speculate: otr4::DoubleRatchet;
        if msg.i < current_ratchet || (msg.i == current_ratchet && msg.j < self.double_ratchet.k())
        {
            log::trace!("Double ratchet: working with stored message keys…");
            // TODO stored message-keys: get key from stored-keys-store
            return Err(OTRError::UserError(
                "Stored message keys are not supported yet.",
            ));
        } else if msg.i == self.double_ratchet.i() {
            log::trace!("Double ratchet: ratcheting forward to the right ratchet…");
            if self.double_ratchet.next() != otr4::Selector::RECEIVER {
                log::trace!("Protocol violation: there cannot be a valid message for a future ratchet, if we need to rotate sender keys first.");
                return Err(OTRError::ProtocolViolation("Message received in future ratchet even though this client is scheduled to perform next ratchet rotation."));
            }
            // This protocol violation should have been detected during message validation.
            assert_eq!(msg.i % 3 == 0, msg.dh.is_some());
            if msg.dh.is_some() && msg.dh.as_ref().unwrap() == self.double_ratchet.other_dh() {
                return Err(OTRError::ProtocolViolation(
                    // REMARK probably needs a proper formulated sentence :-P
                    "The same DH public key was provided on (new) DH-ratchet.",
                ));
            }
            speculate = self
                .double_ratchet
                .rotate_receiver(
                    msg.ecdh.clone(),
                    msg.dh
                        .as_ref()
                        .unwrap_or(self.double_ratchet.other_dh())
                        .clone(),
                )
                .map_err(OTRError::CryptographicViolation)?;
        } else {
            log::trace!("Double ratchet: working with the current ratchet…");
            speculate = self.double_ratchet.clone();
        }
        // TODO should we perform a sanity check in order to not go to far out in the chainkey message id counter?
        while speculate.k() < msg.j {
            log::trace!(
                "Current chainkey index: {}. Needed: {}. Rotating.",
                speculate.k(),
                msg.j
            );
            // stored message-keys: need to fast-forward and store all keys we pass by. (different method, store internally?)
            speculate.rotate_receiver_chainkey();
        }
        let keys = speculate.receiver_keys();
        let authenticator = otr4::kdf2::<{ otr4::MAC_LENGTH }>(
            otr4::USAGE_AUTHENTICATOR,
            &keys.1,
            authenticator_data,
        );
        constant::compare_bytes_distinct(&authenticator, &msg.authenticator)
            .map_err(OTRError::CryptographicViolation)?;
        let content = chacha20::decrypt(Self::extract_encryption_key(&keys.0), &msg.encrypted);
        // after successfully processing message, persist state of Double Ratchet and rotate past this chainkey
        self.double_ratchet = speculate;
        self.double_ratchet.confirm_receiver_keys();
        Ok(content)
    }

    fn extract_encryption_key(mk_enc: &[u8; 64]) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.clone_from_slice(&mk_enc[..32]);
        key
    }
}

// TODO keep track of protocol version we transitioned from, to ensure that StateFinished is not used to subtle downgrade the session protocol.
pub struct FinishedState {}

impl ProtocolState for FinishedState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Finished
    }

    fn version(&self) -> Version {
        // TODO consider if it makes sense to keep the protocol version of the last encrypted session? (may be useful to evaluate re-establishing secure session if different version is used)
        Version::None
    }

    fn handle(
        &mut self,
        _: &DataMessage,
        _: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("FINISHED: handling OTR DATA message… rejected.");
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn handle4(
        &mut self,
        _: &DataMessage4,
        _: &[u8],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        log::trace!("FINISHED: handling OTRv4 DATA message… rejected.");
        // TODO use ERROR_2 error code
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        material: ProtocolMaterial,
    ) -> Box<dyn ProtocolState> {
        // There is no indication in the OTRv3 spec that there are issues with re-transitioning into
        // `MSGSTATE_ENCRYPTED`. There does not seem to be an issue, and it also means that AKEs
        // during `MSGSTATE_ENCRYPTED` are possible as well.
        match material {
            ProtocolMaterial::AKE {
                ssid,
                our_dh,
                their_dh,
                their_dsa,
            } => Box::new(EncryptedOTR3State::new(
                host,
                our_instance,
                their_instance,
                ssid,
                our_dh,
                their_dh,
                otr::fingerprint(&their_dsa),
            )),
            ProtocolMaterial::DAKE {
                ssid,
                double_ratchet,
                us,
                them,
            } => Box::new(EncryptedOTR4State {
                our_instance,
                their_instance,
                double_ratchet,
                smp: SMP4Context::new(host, us, them, ssid),
            }),
        }
    }

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn expire(&mut self, _: u64) -> Option<(EncodedMessageType, Box<FinishedState>)> {
        None
    }

    fn prepare(&mut self, _: MessageFlags, _: &[u8]) -> Result<EncodedMessageType, OTRError> {
        Err(OTRError::IncorrectState("Sending messages is prohibited in 'Finished' state to prevent races that result in sensitive message being transmitted insecurely."))
    }

    fn smp(&self) -> Result<&SMPContext, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP is not available when protocol is in Finished state.",
        ))
    }

    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP is not available when protocol is in Finished state.",
        ))
    }

    fn smp4(&self) -> Result<&SMP4Context, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP4 is not available when protocol is in Finished state.",
        ))
    }

    fn smp4_mut(&mut self) -> Result<&mut SMP4Context, OTRError> {
        Err(OTRError::IncorrectState(
            "SMP4 is not available when protocol is in Finished state.",
        ))
    }
}

// TODO consider moving instance tags and protocol version into here.
#[allow(clippy::large_enum_variant, clippy::upper_case_acronyms)]
pub enum ProtocolMaterial {
    /// AKE is the OTRv2/v3 key material.
    AKE {
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_dsa: dsa::PublicKey,
    },
    /// DAKE is the OTRv4 DAKE mixed key material.
    DAKE {
        ssid: SSID,
        double_ratchet: otr4::DoubleRatchet,
        us: otr4::Fingerprint,
        them: otr4::Fingerprint,
    },
}

fn parse_message(raw_content: &[u8]) -> Result<Message, OTRError> {
    let mut decoder = OTRDecoder::new(raw_content);
    let content = decoder.read_bytes_null_terminated();
    let tlvs: Vec<TLV> = decoder
        .read_tlvs()?
        .into_iter()
        .filter(|t| t.0 != TLV_TYPE_0_PADDING)
        .collect();
    decoder.done()?;
    if tlvs.iter().any(|e| e.0 == TLV_TYPE_1_DISCONNECT) {
        log::debug!("Received confidential message with type 1 TLV (DISCONNECT)");
        Ok(Message::ConfidentialFinished(content))
    } else {
        log::debug!("Received confidential message.");
        Ok(Message::Confidential(content, tlvs))
    }
}

pub enum Message {
    Confidential(Vec<u8>, Vec<TLV>),
    ConfidentialFinished(Vec<u8>),
}

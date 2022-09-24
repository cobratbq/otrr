#![allow(clippy::too_many_arguments)]

use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    crypto::{constant, DH, DSA, OTR, SHA1},
    encoding::{
        encode_authenticator_data, DataMessage, Fingerprint, MessageFlags, OTRDecoder, OTREncoder,
        OTRMessageType, MAC_LEN, SSID, TLV,
    },
    instancetag::{InstanceTag, INSTANCE_ZERO},
    keymanager::KeyManager,
    smp::SMPContext,
    utils::std::{bytes, slice},
    Host, OTRError, ProtocolStatus, UserMessage, Version, TLV_TYPE_1_DISCONNECT,
};

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn version(&self) -> Version;
    /// handle processes a received message in accordance with the active protocol state.
    // TODO check but I believe we should also handle plaintext message for state correction purposes.
    // FIXME consider not returning a UserMessage here, but some convenient intermediate format.
    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    );
    // TODO review to check that `secure` functions all have same quality of implementation/delegation
    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState>;
    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>);
    /// prepare prepares a message for sending in accordance with the active protocol state.
    // TODO check logic sequence using `prepare` because this send seems to prepare for a sendable OTR message type only.
    fn prepare(&mut self, flags: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError>;
    // TODO integrate SMP use in session handling logic
    fn smp(&self) -> Result<&SMPContext, OTRError>;
    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError>;
}

pub fn new_state() -> Box<dyn ProtocolState> {
    Box::new(PlaintextState {})
}

// TODO review public access for various state structs
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
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState> {
        let their_fingerprint = OTR::fingerprint(&their_dsa);
        Box::new(EncryptedState::new(
            host,
            version,
            our_instance,
            their_instance,
            ssid,
            our_dh,
            their_dh,
            their_fingerprint,
        ))
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn prepare(&mut self, _: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        // Returned as 'Undefined' message as we are not in an encrypted state, therefore we return
        // the content as-is to the caller.
        // TODO not sure if this is the best solution
        Ok(OTRMessageType::Undefined(Vec::from(content)))
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
}

pub struct EncryptedState {
    version: Version,
    our_instance: InstanceTag,
    their_instance: InstanceTag,
    keys: KeyManager,
    smp: SMPContext,
}

impl ProtocolState for EncryptedState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Encrypted
    }

    fn version(&self) -> Version {
        self.version.clone()
    }

    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        // TODO can/should we sanity-check revealed MAC keys? They have already been exposed on the network as we receive them, but we might validate whether they contain some measure of sane information.
        assert_eq!(msg.revealed.len() % 20, 0);
        assert!(msg.revealed.is_empty() || bytes::any_nonzero(&msg.revealed));
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        match self.decrypt_message(msg) {
            // TODO carefully inspect possible state transitions, now assumes None.
            // TODO check if just plaintext or contains OTR protocol directions, ...
            Ok(plaintext) => match parse_message(&plaintext) {
                msg @ Ok(UserMessage::ConfidentialSessionFinished(_)) => {
                    (msg, Some(Box::new(FinishedState {})))
                }
                msg @ Ok(_) => (msg, None),
                err @ Err(_) => (err, None),
            },
            Err(_) => {
                // TODO consider logging the details of the error message, but for the client it is not relevant
                (Err(OTRError::UnreadableMessage(self.their_instance)), None)
            }
        }
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState> {
        let their_fingerprint = OTR::fingerprint(&their_dsa);
        // There is no indication in the OTRv3 spec that there are issues with re-transitioning into
        // `MSGSTATE_ENCRYPTED`. There does not seem to be an issue, and it also means that AKEs
        // during `MSGSTATE_ENCRYPTED` are possible as well.
        Box::new(EncryptedState::new(
            host,
            version,
            our_instance,
            their_instance,
            ssid,
            our_dh,
            their_dh,
            their_fingerprint,
        ))
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        let plaintext = OTREncoder::new()
            .write_byte(0)
            .write_tlv(TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
            .to_vec();
        let optabort = Some(OTRMessageType::Data(
            self.encrypt_message(MessageFlags::IGNORE_UNREADABLE, &plaintext),
        ));
        (optabort, Box::new(PlaintextState {}))
    }

    fn prepare(&mut self, flags: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        Ok(OTRMessageType::Data(self.encrypt_message(flags, content)))
    }

    fn smp(&self) -> Result<&SMPContext, OTRError> {
        Ok(&self.smp)
    }

    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError> {
        Ok(&mut self.smp)
    }
}

impl EncryptedState {
    fn new(
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_fingerprint: Fingerprint,
    ) -> Self {
        let our_fingerprint = OTR::fingerprint(&host.keypair().public_key());
        Self {
            version,
            our_instance,
            their_instance,
            keys: KeyManager::new((1, our_dh), (1, their_dh)),
            smp: SMPContext::new(Rc::clone(&host), ssid, our_fingerprint, their_fingerprint),
        }
    }

    fn encrypt_message(&mut self, flags: MessageFlags, plaintext_message: &[u8]) -> DataMessage {
        let ctr = self.keys.take_counter();
        assert!(bytes::any_nonzero(&ctr));
        let (receiver_keyid, receiver_key) = self.keys.their_current();
        let (our_keyid, our_dh) = self.keys.current_keys();
        let next_dh = self.keys.next_keys().1.public.clone();
        let shared_secret = self.keys.take_shared_secret();
        let secbytes = OTREncoder::new().write_mpi(&shared_secret).to_vec();
        assert!(bytes::any_nonzero(&secbytes));
        let secrets = OTR::DataSecrets::derive(&our_dh.public, receiver_key, &secbytes);
        let mut nonce = [0u8; 16];
        slice::copy(&mut nonce, &ctr);
        assert!(bytes::any_nonzero(&nonce));
        let ciphertext = secrets
            .sender_crypt_key()
            .encrypt(&nonce, plaintext_message);
        assert!(bytes::any_nonzero(&ciphertext));
        // TODO the spec says ".. whenever we are about to forget one of our D-H key pairs, ...". Check if implementation satisfies this requiremend.
        let oldmackeys = self.keys.get_used_macs();
        assert_eq!(oldmackeys.len() % 20, 0);
        assert!(bytes::any_nonzero(&oldmackeys));

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
        let authenticator = SHA1::hmac(
            &secrets.sender_mac_key(),
            &encode_authenticator_data(
                &self.version,
                self.our_instance,
                self.their_instance,
                &data_message,
            ),
        );
        assert!(bytes::any_nonzero(&authenticator));
        data_message.authenticator = authenticator;

        data_message
    }

    fn decrypt_message(&mut self, message: &DataMessage) -> Result<Vec<u8>, OTRError> {
        // "Uses Diffie-Hellman to compute a shared secret from the two keys labelled by keyidA and
        //  keyidB, and generates the receiving AES key, ek, and the receiving MAC key, mk, as
        //  detailed below. (These will be the same as the keys Alice generated, above.)"
        let their_key = self.keys.their_key(message.sender_keyid)?;
        let our_dh = self.keys.our_keys(message.receiver_keyid)?;
        let secbytes = OTREncoder::new()
            .write_mpi(&our_dh.generate_shared_secret(their_key))
            .to_vec();
        let secrets = OTR::DataSecrets::derive(&our_dh.public, their_key, &secbytes);
        let authenticator = SHA1::hmac(
            &secrets.receiver_mac_key(),
            &encode_authenticator_data(
                &self.version,
                self.their_instance,
                self.our_instance,
                message,
            ),
        );
        // TODO do we need to verify dh key against local key cache?
        // "Uses mk to verify MACmk(TA)."
        constant::verify(&message.authenticator, &authenticator)
            .map_err(OTRError::CryptographicViolation)?;
        // "Uses ek and ctr to decrypt AES-CTRek,ctr(msg)."
        self.keys.verify_counter(&message.ctr)?;
        let mut nonce = [0u8; 16];
        slice::copy(&mut nonce, &message.ctr);
        assert!(utils::std::bytes::any_nonzero(&nonce));
        // TODO double-check if this is appropriate time to register mac-to-be-revealed.
        self.keys.reveal_mac(&message.authenticator);
        self.keys.acknowledge_ours(message.receiver_keyid)?;
        self.keys
            .register_their_key(message.sender_keyid + 1, message.dh_y.clone())?;
        // finally, return the message
        Ok(secrets
            .receiver_crypt_key()
            .decrypt(&nonce, &message.encrypted))
    }
}

fn parse_message(raw_content: &[u8]) -> Result<UserMessage, OTRError> {
    let mut decoder = OTRDecoder::new(raw_content);
    let content = decoder.read_bytes_null_terminated()?;
    let tlvs = decoder.read_tlvs()?;
    // TODO drop TLV-0-PADDING as it is only padding?
    // TODO handle possibility for multiple TLVs, including TLV-1-DISCONNECT above
    // TODO add logic for handling SMP
    if tlvs.iter().any(|e| e.0 == TLV_TYPE_1_DISCONNECT) {
        // TODO strictly speaking there may be a user-readable message that we do to return to the client. (Spec does not strictly say this is a use case to consider.)
        Ok(UserMessage::ConfidentialSessionFinished(INSTANCE_ZERO))
    } else {
        Ok(UserMessage::Confidential(INSTANCE_ZERO, content, tlvs))
    }
}

pub struct FinishedState {}

impl ProtocolState for FinishedState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Finished
    }

    fn version(&self) -> Version {
        Version::None
    }

    fn handle(
        &mut self,
        _: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState> {
        let their_fingerprint = OTR::fingerprint(&their_dsa);
        Box::new(EncryptedState::new(
            host,
            version,
            our_instance,
            their_instance,
            ssid,
            our_dh,
            their_dh,
            their_fingerprint,
        ))
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn prepare(&mut self, _: MessageFlags, _: &[u8]) -> Result<OTRMessageType, OTRError> {
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
}

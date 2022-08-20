use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    crypto::{DH, DSA, OTR, SHA1, constant},
    encoding::{
        DataMessage, Fingerprint, MessageFlags, OTRDecoder, OTREncoder, OTRMessageType, CTR, SSID,
        TLV,
    },
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
    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    );
    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState>;
    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>);
    /// prepare prepares a message for sending in accordance with the active protocol state.
    // TODO check logic sequence using `prepare` because this send seems to prepare for a sendable OTR message type only.
    fn prepare(&mut self, flags: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError>;
        // TODO integrate SMP use in session handling logic
    fn smp(&mut self) -> Result<&mut SMPContext, OTRError>;
}

pub fn new_state() -> Box<dyn ProtocolState> {
    return Box::new(PlaintextState {});
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
        (Err(OTRError::UnreadableMessage), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState> {
        let their_fingerprint = OTR::fingerprint(&their_dsa);
        return Box::new(EncryptedState::new(
            host,
            version,
            ssid,
            ctr,
            our_dh,
            their_dh,
            their_fingerprint,
        ));
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        // FIXME is it desireable/harmful to have to construct a new instance?
        (None, Box::new(PlaintextState {}))
    }

    fn prepare(&mut self, flags: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        // Returned as 'Undefined' message as we are not in an encrypted state,
        // therefore we return the content as-is to the caller.
        // FIXME not sure if this is the best solution
        Ok(OTRMessageType::Undefined(Vec::from(content)))
    }

    fn smp(&mut self) -> Result<&mut SMPContext, OTRError> {
        Err(OTRError::SMPIncorrectState)
    }
}

pub struct EncryptedState {
    version: Version,
    keys: KeyManager,
    smp: SMPContext,
}

impl Drop for EncryptedState {
    fn drop(&mut self) {
        // FIXME ensure thorough clean-up of sensitive material
        todo!()
    }
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
        // sanity-checking incoming message content
        // FIXME can we actually validate the counter-value against local data?
        assert!(bytes::any_nonzero(&msg.ctr));
        // TODO can/should we sanity-check revealed MAC keys? They have already been exposed on the network as we receive them, but we might validate whether they contain some measure of sane information.
        assert_eq!(msg.revealed.len() % 20, 0);
        assert!(msg.revealed.len() == 0 || bytes::any_nonzero(&msg.revealed));
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        match self.decrypt_message(msg) {
            // TODO carefully inspect possible state transitions, now assumes None.
            // TODO check if just plaintext or contains OTR protocol directions, ...
            // TODO carefully inspect possible state transitions, now assumes None.
            Ok(plaintext) => match self.parse_message(&plaintext) {
                msg @ Ok(UserMessage::ConfidentialSessionFinished) => {
                    (msg, Some(Box::new(FinishedState {})))
                }
                msg @ Ok(_) => (msg, None),
                err @ Err(_) => (err, None),
            },
            Err(error) => (Err(error), None),
        }
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState> {
        let their_fingerprint = OTR::fingerprint(&their_dsa);
        // FIXME check if allowed to transition from Encrypted to Encrypted.
        Box::new(EncryptedState::new(
            host,
            version,
            ssid,
            ctr,
            our_dh,
            their_dh,
            their_fingerprint,
        ))
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        let plaintext = OTREncoder::new()
            .write_bytes_null_terminated(&[])
            .write_tlv(TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
            .to_vec();
        let optabort = Some(OTRMessageType::Data(
            self.encrypt_message(MessageFlags::IGNORE_UNREADABLE, &plaintext),
        ));
        (optabort, Box::new(PlaintextState {}))
    }

    fn prepare(&mut self, flags: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        Ok(OTRMessageType::Data(
            self.encrypt_message(MessageFlags::empty(), content),
        ))
    }

    fn smp(&mut self) -> Result<&mut SMPContext, OTRError> {
        Ok(&mut self.smp)
    }
}

impl EncryptedState {
    // FIXME what to do with ctr here (haven't bothered to look it up. Do we reuse or create new CTR value?)
    fn new(
        host: Rc<dyn Host>,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_fingerprint: Fingerprint,
    ) -> Self {
        let our_fingerprint = OTR::fingerprint(&host.keypair().public_key());
        Self {
            version,
            // FIXME spec describes some possible deviations for key-ids/public keys(???)
            // FIXME verify key-ids
            // FIXME need to pass on ctr to keymanager or is next counter predetermined by protocol?
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
        let secrets = OTR::DataSecrets::derive(&our_dh.public, &receiver_key, &secbytes);
        let mut nonce = [0u8; 16];
        assert!(bytes::any_nonzero(&nonce));
        slice::copy(&mut nonce, &ctr);
        let ciphertext = secrets.send_crypt_key().encrypt(&nonce, plaintext_message);
        assert!(bytes::any_nonzero(&ciphertext));
        let oldmackeys = self.keys.get_used_macs();
        assert_eq!(oldmackeys.len() % 20, 0);
        assert!(bytes::any_nonzero(&oldmackeys));

        // compute authenticator
        let ta = OTREncoder::new()
            .write_int(our_keyid)
            .write_int(receiver_keyid)
            .write_mpi(&next_dh)
            .write_ctr(&ctr)
            .write_data(&ciphertext)
            .to_vec();
        assert!(bytes::any_nonzero(&ta));
        let mac_ta = SHA1::hmac(&secrets.send_mac_key(), &ta);
        assert!(bytes::any_nonzero(&mac_ta));

        DataMessage {
            flags,
            sender_keyid: our_keyid,
            receiver_keyid,
            dh_y: next_dh,
            ctr,
            encrypted: ciphertext,
            authenticator: mac_ta,
            revealed: oldmackeys,
        }
    }

    fn decrypt_message(&mut self, message: &DataMessage) -> Result<Vec<u8>, OTRError> {
        // "Uses Diffie-Hellman to compute a shared secret from the two keys labelled by keyidA and
        // keyidB, and generates the receiving AES key, ek, and the receiving MAC key, mk, as
        // detailed below. (These will be the same as the keys Alice generated, above.)"
        let (their_keyid, their_key) = self.keys.their_current();
        if their_keyid != message.sender_keyid {
            return Err(OTRError::ProtocolViolation("unknown keyid for sender key"));
        }
        let (our_keyid, our_dh) = self.keys.current_keys();
        if our_keyid != message.receiver_keyid {
            return Err(OTRError::ProtocolViolation(
                "unknown keyid for receiver key",
            ));
        }
        let secbytes = OTREncoder::new()
            .write_mpi(&our_dh.generate_shared_secret(their_key))
            .to_vec();
        let secrets = OTR::DataSecrets::derive(&our_dh.public, their_key, &secbytes);
        let ta = OTREncoder::new()
            .write_int(message.sender_keyid)
            .write_int(message.receiver_keyid)
            .write_mpi(&message.dh_y)
            .write_ctr(&message.ctr)
            .write_data(&message.encrypted)
            .to_vec();
        let mac_ta = SHA1::hmac(&secrets.recv_mac_key(), &ta);
        // TODO do we need to verify dh key against local key cache?
        // "Uses mk to verify MACmk(TA)."
        constant::verify(&message.authenticator, &mac_ta)
            .or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        // "Uses ek and ctr to decrypt AES-CTRek,ctr(msg)."
        let mut nonce = [0u8; 16];
        slice::copy(&mut nonce, &message.ctr);
        // TODO cryptographic maintenance such as registering new dh-key, etc.
        self.keys.reveal_mac(&message.authenticator);
        self.keys
            .register_their_next(message.sender_keyid + 1, message.dh_y.clone())?;
        // TODO check with spec if these should happen at same time? This is written from memory/logical reasoning, so needs some reviewing.
        self.keys.acknowledge_ours(message.receiver_keyid)?;
        // finally, return the message
        Ok(secrets.recv_crypt_key().decrypt(&nonce, &message.encrypted))
    }

    fn parse_message(&self, raw_content: &[u8]) -> Result<UserMessage, OTRError> {
        let mut decoder = OTRDecoder::new(raw_content);
        let content = decoder.read_bytes_null_terminated()?;
        let tlvs = decoder.read_tlvs()?;
        // TODO drop TLV-0-PADDING as it is only padding?
        // TODO handle possibility for multiple TLVs, including TLV-1-DISCONNECT above
        // TODO add logic for handling SMP
        if tlvs.iter().any(|e| e.0 == TLV_TYPE_1_DISCONNECT) {
            Ok(UserMessage::ConfidentialSessionFinished)
        } else {
            Ok(UserMessage::Confidential(content, tlvs))
        }
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
        (Err(OTRError::UnreadableMessage), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
        their_dsa: DSA::PublicKey,
    ) -> Box<EncryptedState> {
        let their_fingerprint = OTR::fingerprint(&their_dsa);
        // FIXME check if allowed to transition to Encrypted from here.
        Box::new(EncryptedState::new(
            host,
            version,
            ssid,
            ctr,
            our_dh,
            their_dh,
            their_fingerprint,
        ))
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        // TODO should we send UserMessage::Reset?
        (None, Box::new(PlaintextState {}))
    }

    fn prepare(&mut self, flags: MessageFlags, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        Err(OTRError::ProtocolInFinishedState)
    }

    fn smp(&mut self) -> Result<&mut SMPContext, OTRError> {
        Err(OTRError::SMPIncorrectState)
    }
}

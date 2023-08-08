// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;

use crate::{
    crypto::{constant, dh, dsa, otr, sha1},
    encoding::{
        encode_authenticator_data, DataMessage, EncodedMessageType, Fingerprint, MessageFlags,
        OTRDecoder, OTREncoder, MAC_LEN, TLV,
    },
    instancetag::{InstanceTag, INSTANCE_ZERO},
    keymanager::KeyManager,
    smp::SMPContext,
    utils, Host, OTRError, ProtocolStatus, TLVType, Version, SSID, smp4::SMP4Context,
};

/// `TLV_TYPE_0_PADDING` is the TLV that can be used to introduce arbitrary-length padding to an
/// encrypted message.
const TLV_TYPE_0_PADDING: TLVType = 0;

/// `TLV_TYPE_1_DISCONNECT` is the TLV that signals a disconnect.
const TLV_TYPE_1_DISCONNECT: TLVType = 1;

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn version(&self) -> Version;
    /// handle processes a received message in accordance with the active protocol state.
    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    // TODO consider defining a common EncryptedState trait to be shared with OTR2/OTR3 and OTR4.
    #[allow(clippy::too_many_arguments)]
    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_dsa: dsa::PublicKey,
    ) -> Box<dyn ProtocolState>;
    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>);
    /// prepare prepares a message for sending in accordance with the active protocol state.
    fn prepare(
        &mut self,
        flags: MessageFlags,
        content: &[u8],
    ) -> Result<EncodedMessageType, OTRError>;
    fn smp(&self) -> Result<&SMPContext, OTRError>;
    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError>;
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
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_dsa: dsa::PublicKey,
    ) -> Box<dyn ProtocolState> {
        let their_fingerprint = otr::fingerprint(&their_dsa);
        Box::new(EncryptedOTR3State::new(
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

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
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
}

pub struct EncryptedOTR3State {
    version: Version,
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
        self.version.clone()
    }

    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        if msg.revealed.len() % 20 != 0
            || (!msg.revealed.is_empty() && utils::bytes::all_zero(&msg.revealed))
        {
            log::info!("NOTE: revealed MAC keys in received data message do not satisfy protocol expectations.");
        }
        match self.decrypt_message(msg) {
            Ok(decrypted) => match parse_message(&decrypted) {
                msg @ Ok(Message::ConfidentialFinished(_)) => (msg, Some(Box::new(FinishedState {}))),
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

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_dsa: dsa::PublicKey,
    ) -> Box<dyn ProtocolState> {
        let their_fingerprint = otr::fingerprint(&their_dsa);
        // There is no indication in the OTRv3 spec that there are issues with re-transitioning into
        // `MSGSTATE_ENCRYPTED`. There does not seem to be an issue, and it also means that AKEs
        // during `MSGSTATE_ENCRYPTED` are possible as well.
        Box::new(Self::new(
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
}

impl EncryptedOTR3State {
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn new(
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_fingerprint: Fingerprint,
    ) -> Self {
        Self {
            version,
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
        let next_dh = self.keys.next_keys().1.public.clone();
        let shared_secret = self.keys.current_shared_secret();
        let secbytes = OTREncoder::new().write_mpi(&shared_secret).to_vec();
        let secrets = otr::DataSecrets::derive(&our_dh.public, receiver_key, &secbytes);
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
                &self.version,
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

    fn decrypt_message(&mut self, message: &DataMessage) -> Result<Vec<u8>, OTRError> {
        log::debug!("Decrypting confidential message ...");
        // "Uses Diffie-Hellman to compute a shared secret from the two keys labelled by keyidA and
        //  keyidB, and generates the receiving AES key, ek, and the receiving MAC key, mk, as
        //  detailed below. (These will be the same as the keys Alice generated, above.)"
        let their_key = self.keys.their_key(message.sender_keyid)?;
        let our_dh = self.keys.our_keys(message.receiver_keyid)?;
        let secbytes = OTREncoder::new()
            .write_mpi(&our_dh.generate_shared_secret(their_key))
            .to_vec();
        let secrets = otr::DataSecrets::derive(&our_dh.public, their_key, &secbytes);
        // "Uses mk to verify MACmk(TA)."
        let receiving_mac_key = secrets.receiver_mac_key();
        let authenticator = sha1::hmac(
            &receiving_mac_key,
            &encode_authenticator_data(
                &self.version,
                self.their_instance,
                self.our_instance,
                message,
            ),
        );
        constant::verify(&message.authenticator, &authenticator)
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

pub struct EncryptedOTR4State {
    our_instance: InstanceTag,
    their_instance: InstanceTag,
    smp: SMP4Context,
}

impl ProtocolState for EncryptedOTR4State {
    fn status(&self) -> ProtocolStatus {
        todo!()
    }

    fn version(&self) -> Version {
        todo!()
    }

    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        todo!()
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_dsa: dsa::PublicKey,
    ) -> Box<dyn ProtocolState> {
        // FIXME to be implemented
        Box::new(EncryptedOTR4State{
            our_instance,
            their_instance,
            smp: SMP4Context::new(&[0u8;0], &[0u8;0], [0u8;8])
        })
    }

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        todo!()
    }

    fn prepare(
        &mut self,
        flags: MessageFlags,
        content: &[u8],
    ) -> Result<EncodedMessageType, OTRError> {
        todo!()
    }

    fn smp(&self) -> Result<&SMPContext, OTRError> {
        todo!()
    }

    fn smp_mut(&mut self) -> Result<&mut SMPContext, OTRError> {
        todo!()
    }
}

impl EncryptedOTR4State {

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
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        (Err(OTRError::UnreadableMessage(INSTANCE_ZERO)), None)
    }

    fn secure(
        &self,
        host: Rc<dyn Host>,
        version: Version,
        our_instance: InstanceTag,
        their_instance: InstanceTag,
        ssid: SSID,
        our_dh: dh::Keypair,
        their_dh: BigUint,
        their_dsa: dsa::PublicKey,
    ) -> Box<dyn ProtocolState> {
        let their_fingerprint = otr::fingerprint(&their_dsa);
        Box::new(EncryptedOTR3State::new(
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

    fn finish(&mut self) -> (Option<EncodedMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
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
}

pub enum Message {
    Confidential(Vec<u8>, Vec<TLV>),
    ConfidentialFinished(Vec<u8>),
}

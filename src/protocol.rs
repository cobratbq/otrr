use num::BigUint;

use crate::{
    crypto::{DH, OTR::DataSecrets, self},
    encoding::{
        DataMessage, MessageFlags, OTREncoder, OTRMessageType, CTR, SSID, TLV,
        TLV_TYPE_1_DISCONNECT,
    },
    keymanager::KeyManager,
    utils::std::{bytes, slice},
    OTRError, ProtocolStatus, UserMessage, Version,
};

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn version(&self) -> Version;
    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    );
    fn secure(
        &self,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
    ) -> Box<EncryptedState>;
    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>);
    fn send(&mut self, content: &[u8]) -> Result<OTRMessageType, OTRError>;
}

pub fn new_state() -> Box<dyn ProtocolState> {
    return Box::new(PlaintextState {});
}

pub struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Plaintext
    }

    fn version(&self) -> Version {
        // FIXME define variant to indicate version is irrelevant due to not in encrypted state.
        Version::Unsupported(0)
    }

    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        // FIXME assumes that this only needs to handle encrypted (OTR Data messages).
        (Err(OTRError::UnreadableMessage), None)
    }

    fn secure(
        &self,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
    ) -> Box<EncryptedState> {
        return Box::new(EncryptedState::new(version, ssid, ctr, our_dh, their_dh));
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        // FIXME is it desireable/harmful to have to construct a new instance?
        (None, Box::new(PlaintextState {}))
    }

    fn send(&mut self, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        // Returned as 'Undefined' message as we are not in an encrypted state,
        // therefore we return the content as-is to the caller.
        // FIXME not sure if this is the best solution
        Ok(OTRMessageType::Undefined(Vec::from(content)))
    }
}

pub struct EncryptedState {
    version: Version,
    keys: KeyManager,
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
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        todo!("To be implemented")
    }

    fn secure(
        &self,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
    ) -> Box<EncryptedState> {
        // FIXME check if allowed to transition to Encrypted from here.
        return Box::new(EncryptedState::new(version, ssid, ctr, our_dh, their_dh));
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        let plaintext = OTREncoder::new()
            .write_tlv(TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
            .to_vec();
        let optabort = Some(OTRMessageType::Data(
            self.create_encrypted_data_message(MessageFlags::IGNORE_UNREADABLE, &plaintext),
        ));
        (optabort, Box::new(PlaintextState {}))
    }

    fn send(&mut self, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        Ok(OTRMessageType::Data(self.create_encrypted_data_message(
            MessageFlags::empty(),
            content,
        )))
    }
}

impl EncryptedState {
    fn new(version: Version, ssid: SSID, ctr: CTR, our_dh: DH::Keypair, their_dh: BigUint) -> Self {
        // FIXME complete initialization
        Self {
            version,
            // FIXME spec describes some possible deviations for key-ids/public keys(???)
            // FIXME verify key-ids
            keys: KeyManager::new((1, our_dh), (1, their_dh)),
        };
        // FIXME implement private creation of encrypted state and key management.
        todo!("To be implemented")
    }

    // FIXME note that this message needs to be already encrypted. This is error-prone!
    fn create_encrypted_data_message(
        &mut self,
        flags: MessageFlags,
        plaintext_message: &[u8],
    ) -> DataMessage {
        let ctr = self.keys.take_counter();
        let (receiver_keyid, receiver_key) = self.keys.their_current();
        let (our_keyid, our_dh) = self.keys.current_keys();
        let next_dh = self.keys.next_keys().1.public.clone();
        let shared_secret = self.keys.take_shared_secret();
        let secbytes = OTREncoder::new().write_mpi(&shared_secret).to_vec();
        let secrets = DataSecrets::derive(&our_dh.public, &receiver_key, &secbytes);
        let mut nonce = [0u8; 16];
        slice::copy(&mut nonce[..], &ctr);
        let ciphertext = secrets.send_crypt_key().encrypt(&nonce, plaintext_message);
        let oldmackeys = self.keys.get_used_macs();

        // compute authenticator
        let ta = OTREncoder::new()
            .write_int(our_keyid)
            .write_int(receiver_keyid)
            .write_mpi(&next_dh)
            .write_ctr(&ctr)
            .write_data(&ciphertext)
            .to_vec();
        let mac_ta = crypto::SHA1::hmac(&secrets.send_mac_key(), &ta);

        // some sanity-checking ...
        assert!(bytes::any_nonzero(&ctr));
        assert!(bytes::any_nonzero(&nonce[..]));
        assert_eq!(oldmackeys.len() % 20, 0);

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
}

pub struct FinishedState {}

impl ProtocolState for FinishedState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Finished
    }

    fn version(&self) -> Version {
        // FIXME define variant to indicate version is irrelevant due to not in encrypted state.
        Version::Unsupported(0)
    }

    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        (Err(OTRError::UnreadableMessage), None)
    }

    fn secure(
        &self,
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: DH::Keypair,
        their_dh: BigUint,
    ) -> Box<EncryptedState> {
        // FIXME check if allowed to transition to Encrypted from here.
        return Box::new(EncryptedState::new(version, ssid, ctr, our_dh, their_dh));
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn send(&mut self, _: &[u8]) -> Result<OTRMessageType, OTRError> {
        Err(OTRError::ProtocolInFinishedState)
    }
}

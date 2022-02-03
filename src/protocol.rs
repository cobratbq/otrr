use std::rc::Rc;

use num::BigUint;

use crate::{
    crypto::DH,
    encoding::{
        DataMessage, KeyID, MessageFlags, OTREncoder, OTRMessageType, CTR, CTR_LEN, MAC_LEN, SSID,
    },
    OTRError, ProtocolStatus, UserMessage, Version, TLV,
};

const TLV_TYPE_0_PADDING: u16 = 0;
const TLV_TYPE_1_DISCONNECT: u16 = 1;

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
        our_dh: Rc<DH::Keypair>,
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
        our_dh: Rc<DH::Keypair>,
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
    sender_keyid: KeyID,
    receiver_keyid: KeyID,
    dh_y: BigUint,
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
        our_dh: Rc<DH::Keypair>,
        their_dh: BigUint,
    ) -> Box<EncryptedState> {
        // FIXME check if allowed to transition to Encrypted from here.
        return Box::new(EncryptedState::new(version, ssid, ctr, our_dh, their_dh));
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        // FIXME send DataMessage with empty content and TLV1 (abort) and FLAG_IGNORE_UNREADABLE set.
        let optabort: Option<OTRMessageType>;
        if let Ok(encrypted) = self.encrypt(
            OTREncoder::new()
                .write_tlv(TLV(TLV_TYPE_1_DISCONNECT, Vec::new()))
                .to_vec(),
        ) {
            optabort = Some(OTRMessageType::Data(
                self.create_data_message(MessageFlags::IgnoreUnreadable, encrypted),
            ));
        } else {
            optabort = None;
        }
        (optabort, Box::new(PlaintextState {}))
    }

    fn send(&mut self, content: &[u8]) -> Result<OTRMessageType, OTRError> {
        // FIXME implement encryption and send
        todo!()
    }
}

impl EncryptedState {
    fn new(
        version: Version,
        ssid: SSID,
        ctr: CTR,
        our_dh: Rc<DH::Keypair>,
        their_dh: BigUint,
    ) -> EncryptedState {
        // FIXME implement private creation of encrypted state and key management.
        todo!("To be implemented")
    }

    // FIXME note that this message needs to be already encrypted. This is error-prone!
    fn create_data_message(&self, flags: MessageFlags, message: Vec<u8>) -> DataMessage {
        // FIXME temporary values
        DataMessage {
            flags,
            sender_keyid: self.sender_keyid,
            receiver_keyid: self.receiver_keyid,
            dh_y: self.dh_y.clone(),
            ctr: [0u8; CTR_LEN],
            encrypted: message,
            authenticator: [0u8; MAC_LEN],
            revealed: Vec::new(),
        }
    }

    fn encrypt(&mut self, message: Vec<u8>) -> Result<Vec<u8>, OTRError> {
        // FIXME implement encryption
        todo!("To be implemented: encryption")
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
        our_dh: Rc<DH::Keypair>,
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

const NUM_KEYS: usize = 2;

struct KeyManager {
    ours: KeyRotation,
    theirs: [BigUint; NUM_KEYS],
    // FIXME confirm correct type and sizes
    ctr: [u8; 16],
}

struct KeyRotation {
    keys: [DH::Keypair; NUM_KEYS],
    key_id: KeyID,
    acknowledged: bool,
}

impl KeyRotation {
    fn new(initial_key: DH::Keypair, initial_keyid: KeyID) -> KeyRotation {
        let mut keys: [DH::Keypair; NUM_KEYS] = [DH::Keypair::generate(), DH::Keypair::generate()];
        let idx = (initial_keyid as usize) % NUM_KEYS;
        keys[idx] = initial_key;
        KeyRotation {
            key_id: initial_keyid,
            keys,
            acknowledged: true,
        }
    }

    fn current(&self) -> (KeyID, &DH::Keypair) {
        let current_id = if self.acknowledged {
            self.key_id
        } else {
            self.key_id - 1
        };
        let idx = (current_id as usize) % NUM_KEYS;
        (current_id, &self.keys[idx])
    }

    fn next(&mut self) -> (KeyID, &DH::Keypair) {
        if self.acknowledged {
            self.acknowledged = false;
            self.key_id += 1;
            let idx = (self.key_id as usize) % NUM_KEYS;
            self.keys[idx] = DH::Keypair::generate();
            (self.key_id, &self.keys[idx])
        } else {
            (self.key_id, &self.keys[(self.key_id as usize) % NUM_KEYS])
        }
    }

    fn acknowledge(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        if key_id == self.key_id - 1 {
            // this keyID was already acknowledged otherwise we couldn't have rotated away
            Ok(())
        } else if key_id == self.key_id {
            // this keyID is for next key, now acknowledged. (May be acknowledged multiple times.)
            self.acknowledged = true;
            Ok(())
        } else {
            Err(OTRError::ProtocolViolation(
                "unexpected keyID confirming ephemeral keyID",
            ))
        }
    }
}

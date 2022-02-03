use std::rc::Rc;

use num::BigUint;

use crate::{
    encoding::{DataMessage, KeyID, MessageFlags, OTREncoder, OTRMessageType, SSID},
    OTRError, UserMessage, Version, CTR, MAC_LEN, TLV, crypto::DH, ProtocolStatus,
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
    fn secure(&self, version: Version, ssid: SSID, our_dh: Rc<DH::Keypair>, their_dh: BigUint) -> Box<EncryptedState>;
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
        _msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        // FIXME assumes that this only needs to handle encrypted (OTR Data messages).
        (Err(OTRError::UnreadableMessage), None)
    }

    fn secure(&self, version: Version, ssid: SSID, our_dh: Rc<DH::Keypair>, their_dh: BigUint) -> Box<EncryptedState> {
        return Box::new(EncryptedState::new(version, ssid, our_dh, their_dh));
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
    ctr: CTR,
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
        _msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        todo!("To be implemented")
    }

    fn secure(&self, version: Version, ssid: SSID, our_dh: Rc<DH::Keypair>, their_dh: BigUint) -> Box<EncryptedState> {
        // FIXME check if allowed to transition to Encrypted from here.
        return Box::new(EncryptedState::new(version, ssid, our_dh, their_dh));
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

    fn send(&mut self, _content: &[u8]) -> Result<OTRMessageType, OTRError> {
        todo!()
    }
}

impl EncryptedState {

    fn new(version: Version, ssid: SSID, our_dh: Rc<DH::Keypair>, their_dh: BigUint) -> EncryptedState {
        // FIXME implement private creation of encrypted state and key management.
        todo!("To be implemented")
    }

    // FIXME note that this message needs to be already encrypted. This is error-prone!
    fn create_data_message(&self, flags: MessageFlags, message: Vec<u8>) -> DataMessage {
        DataMessage {
            flags,
            sender_keyid: self.sender_keyid,
            receiver_keyid: self.receiver_keyid,
            dh_y: self.dh_y.clone(),
            ctr: self.ctr,
            encrypted: message,
            authenticator: [0u8; MAC_LEN],
            revealed: Vec::new(),
        }
    }

    fn encrypt(&mut self, _message: Vec<u8>) -> Result<Vec<u8>, OTRError> {
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
        _: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    ) {
        (Err(OTRError::UnreadableMessage), None)
    }

    fn secure(&self, version: Version, ssid: SSID, our_dh: Rc<DH::Keypair>, their_dh: BigUint) -> Box<EncryptedState> {
        // FIXME check if allowed to transition to Encrypted from here.
        return Box::new(EncryptedState::new(version, ssid, our_dh, their_dh));
    }

    fn finish(&mut self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn send(&mut self, _: &[u8]) -> Result<OTRMessageType, OTRError> {
        Err(OTRError::ProtocolInFinishedState)
    }
}

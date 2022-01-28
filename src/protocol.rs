use crate::{encoding::{DataMessage, OTRMessageType}, OTRError, UserMessage, Version};

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn handle(
        &mut self,
        msg: &DataMessage,
    ) -> (
        Result<UserMessage, OTRError>,
        Option<Box<dyn ProtocolState>>,
    );
    fn secure(&self) -> Box<EncryptedState>;
    fn finish(&self) -> (Option<OTRMessageType>, Box<PlaintextState>);
    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError>;
}

pub fn new_state() -> Box<dyn ProtocolState> {
    return Box::new(PlaintextState {});
}

pub struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Plaintext
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

    fn secure(&self) -> Box<EncryptedState> {
        todo!()
    }

    fn finish(&self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        // FIXME is it desireable/harmful to have to construct a new instance?
        (None, Box::new(PlaintextState {}))
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        Ok(Vec::from(content))
    }
}

pub struct EncryptedState {
    version: Version,
}

impl Drop for EncryptedState {
    fn drop(&mut self) {
        todo!()
    }
}

impl ProtocolState for EncryptedState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Encrypted
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

    fn secure(&self) -> Box<EncryptedState> {
        todo!()
    }

    fn finish(&self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        // let msg = DataMessage{
        //     flags: MessageFlag::FLAG_IGNORE_UNREADABLE,
        //     sender_keyid:,
        //     receiver_keyid:,
        //     dh_y:,
        //     ctr:,
        //     encrypted:,
        //     authenticator: [0u8;MAC_LEN],
        //     // TODO need to check for to-be-revealed MACs
        //     revealed: Vec::new(),
        // }
        // FIXME send DataMessage with empty content and TLV1 (abort) and FLAG_IGNORE_UNREADABLE set.
        (None, Box::new(PlaintextState {}))
    }

    fn send(&mut self, _content: &[u8]) -> Result<Vec<u8>, OTRError> {
        todo!()
    }
}

pub struct FinishedState {}

impl ProtocolState for FinishedState {
    fn status(&self) -> ProtocolStatus {
        ProtocolStatus::Finished
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

    fn secure(&self) -> Box<EncryptedState> {
        todo!()
    }

    fn finish(&self) -> (Option<OTRMessageType>, Box<PlaintextState>) {
        (None, Box::new(PlaintextState {}))
    }

    fn send(&mut self, _: &[u8]) -> Result<Vec<u8>, OTRError> {
        Err(OTRError::ProtocolInFinishedState)
    }
}

#[derive(PartialEq)]
pub enum ProtocolStatus {
    Plaintext,
    Encrypted,
    Finished,
}

use crate::{CTR, Host, Message, OTRError};

pub trait ProtocolState {
    fn status(&self) -> ProtocolStatus;
    fn handle(
        &mut self,
        host: &dyn Host,
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>);
    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError>;
}

pub enum ProtocolStatus {
    Plaintext,
    Encrypted,
    Finished,
}

pub fn new_protocol_state() -> Box<dyn ProtocolState> {
    return Box::new(PlaintextState {});
}

struct PlaintextState {}

impl ProtocolState for PlaintextState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Plaintext;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME assumes that this only needs to handle encrypted (OTR Data messages).
        return (Err(OTRError::UnreadableMessage), None)
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Ok(Message::None), None);
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Ok(Vec::from(content));
    }
}

struct EncryptedState {}

impl ProtocolState for EncryptedState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Encrypted;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME allow handling of AKE messages in 'Encrypted' state or transition to Plaintext? (Immediate transition to plaintext may be dangerous due to unanticipated move disclosing information)
        todo!("To be implemented")
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        // FIXME send/inject session end message to other party (with ignore unreadable).
        return (
            Ok(Message::Reset),
            Some(Box::new(PlaintextState {})),
        );
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        todo!()
    }
}

struct FinishedState {}

impl ProtocolState for FinishedState {
    fn status(&self) -> ProtocolStatus {
        return ProtocolStatus::Finished;
    }

    fn handle(
        &mut self,
        host: &dyn Host,
        dh_y: num_bigint::BigUint,
        ctr: CTR,
        encrypted: Vec<u8>,
        authenticator: [u8;20],
    ) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (Err(OTRError::UnreadableMessage), None)
    }

    fn finish(&mut self) -> (Result<Message, OTRError>, Option<Box<dyn ProtocolState>>) {
        return (
            Ok(Message::Reset),
            Some(Box::new(PlaintextState {})),
        );
    }

    fn send(&mut self, content: &[u8]) -> Result<Vec<u8>, OTRError> {
        return Err(OTRError::ProtocolInFinishedState);
    }
}

// FIXME consider if this should move somewhere else...
/// read_content reads content until null-terminated or end of buffer.
fn read_content(&mut self) -> Result<Vec<u8>, OTRError> {
    let mut content_end_index = self.content.len();
    for i in 0..self.content.len() {
        if self.content[i] == 0 {
            content_end_index = i;
            break;
        }
    }
    let content = Vec::from(&self.content[0..content_end_index]);
    self.content = &self.content[content_end_index + 1..];
    return Ok(content);
}

// FIXME consider if this should move somewhere else...
/// read_tlvs reads TLV-records until end of buffer.
fn read_tlvs(&mut self) -> Result<Vec<TLV>, OTRError> {
    // FIXME check for content length before reading type, length and value from the content array
    let mut tlvs = Vec::new();
    while self.content.len() > 0 {
        if self.content.len() < 4 {
            return Err(OTRError::IncompleteMessage);
        }
        let typ = (self.content[0] as u16) << 8 + self.content[1] as u16;
        let len = (self.content[2] as usize) << 8 + self.content[3] as usize;
        if self.content.len() < 4 + len {
            return Err(OTRError::IncompleteMessage);
        }
        tlvs.push(TLV {
            typ: typ,
            value: Vec::from(&self.content[4..4 + len]),
        });
        self.content = &self.content[4 + len..];
    }
    return Ok(tlvs);
}

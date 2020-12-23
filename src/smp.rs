use num_bigint::BigUint;
use ring::rand::{SecureRandom, SystemRandom};

use crate::{crypto::{DH, SHA256}, encoding::{Fingerprint, OTREncoder, SSID, TLV}};

/// TLV for initiating SMP
const TLV_TYPE_SMP_MESSAGE_1: u16 = 2u16;
const TLV_TYPE_SMP_MESSAGE_2: u16 = 3u16;
const TLV_TYPE_SMP_MESSAGE_3: u16 = 4u16;
const TLV_TYPE_SMP_MESSAGE_4: u16 = 5u16;
const TLV_TYPE_SMP_ABORT: u16 = 6u16;

/// TLV similar to message 1 but includes a user-specified question (null-terminated) in the payload.
const TLV_TYPE_SMP_MESSAGE_1Q: u16 = 7u16;

pub struct SMPContext {
    smp: SMPState,
    rand: SystemRandom,
}

impl SMPContext {
    pub fn new() -> SMPContext {
        SMPContext{
            smp: SMPState::Expect1,
            rand: SystemRandom::new(),
        }
    }

    /// Initiate SMP. Produces SMPError::AlreadyInProgress if SMP is in progress.
    pub fn initiate(&mut self, ssid: &[u8; 8], question: &[u8], secret: &[u8]) -> Result<TLV, SMPError> {
        match self.smp {
            SMPState::Expect1 {} => {},
            _ => return Err(SMPError::AlreadyInProgress),
        }
        let initiator: Fingerprint;
        let responder: Fingerprint;
        let x = compute_secret(initiator, responder, ssid, secret);
        let a2 = DH::random();
        let a3 = DH::random();
        let r2 = DH::random();
        let r3 = DH::random();

        let g2a: BigUint;
        let c2: BigUint;
        let D2: BigUint;
        let g3a: BigUint;
        let c3: BigUint;
        let D3: BigUint;
        let mut encoder = OTREncoder::new();
        if question.len() > 0 {
            encoder.write_bytes_null_terminated(question);
        }
        let payload = encoder
            .to_vec();
        Ok(TLV(TLV_TYPE_SMP_MESSAGE_1, payload))
    }

    /// Indiscriminately reset SMP state to StateExpect1. Returns TLV with SMP Abort-payload.
    pub fn abort(&mut self) -> Result<TLV, SMPError> {
        self.smp = SMPState::Expect1;
        Ok(TLV(TLV_TYPE_SMP_ABORT, Vec::new()))
    }

    pub fn handleMessage1(&mut self, g2a: BigUint) -> Result<TLV, SMPError> {
        todo!()
    }

    pub fn handleMessage2(&mut self) -> Result<TLV, SMPError> {
        todo!()
    }

    pub fn handleMessage3(&mut self) -> Result<TLV, SMPError> {
        todo!()
    }

    pub fn handleMessage4(&mut self) -> Result<TLV, SMPError> {
        todo!()
    }
}

// FIXME is there a nicer (more fluent) way to make the second mpi optional?
fn hash(version: u8, mpi1: BigUint, mpi2: Option<BigUint>) -> [u8; 32] {
    let mut data = vec![version];
    data.extend(OTREncoder::new().write_mpi(&mpi1).to_vec());
    mpi2.map(|v| data.extend(OTREncoder::new().write_mpi(&v).to_vec()));
    SHA256::digest(&data)
}

fn compute_secret(initiator: Fingerprint, responder: Fingerprint, ssid: SSID, secret: &[u8]) -> [u8; 32] {
    return SHA256::digest(&OTREncoder::new()
        .write_byte(1)
        .write_fingerprint(initiator)
        .write_fingerprint(responder)
        .write_ssid(ssid)
        // FIXME is 'data' the write serialization type for user-specified secret?
        .write_data(secret)
        .to_vec());
}

enum SMPState {
    Expect1,
    Expect2,
    Expect3,
    Expect4,
}

#[derive(std::fmt::Debug)]
enum SMPError {
    AlreadyInProgress,
}

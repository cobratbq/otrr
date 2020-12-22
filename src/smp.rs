use num_bigint::BigUint;
use ring::rand::{SecureRandom, SystemRandom};

use crate::{
    crypto::SHA256,
    encoding::{OTREncoder, TLV},
};

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
}

impl SMPContext {
    pub fn initiate(&mut self, question: &[u8], secret: &[u8]) -> Result<TLV, SMPError> {
        match self.smp {
            SMPState::Expect1 {} => todo!(),
            _ => Err(SMPError::AlreadyInProgress),
        }
    }

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

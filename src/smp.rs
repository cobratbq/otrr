use DH::MODULUS;
use num::integer::{Integer, mod_floor};
use num_bigint::BigUint;
use ring::rand::{SecureRandom, SystemRandom};

use crate::{OTRError, crypto::{DH, SHA256}, encoding::{Fingerprint, OTRDecoder, OTREncoder, SSID, TLV}};

/// TLV for initiating SMP
const TLV_TYPE_SMP_MESSAGE_1: u16 = 2u16;
const TLV_TYPE_SMP_MESSAGE_2: u16 = 3u16;
const TLV_TYPE_SMP_MESSAGE_3: u16 = 4u16;
const TLV_TYPE_SMP_MESSAGE_4: u16 = 5u16;
const TLV_TYPE_SMP_ABORT: u16 = 6u16;

/// TLV similar to message 1 but includes a user-specified question (null-terminated) in the payload.
const TLV_TYPE_SMP_MESSAGE_1Q: u16 = 7u16;

lazy_static! {
    static ref RAND: SystemRandom = SystemRandom::new();
}

pub struct SMPContext {
    /// fingerprint of the other party
    fingerprint: Fingerprint,
    smp: SMPState,
    rand: SystemRandom,
}

impl SMPContext {
    pub fn new(fingerprint: Fingerprint) -> SMPContext {
        SMPContext{
            fingerprint,
            smp: SMPState::Expect1,
            rand: SystemRandom::new(),
        }
    }

    /// Initiate SMP. Produces SMPError::AlreadyInProgress if SMP is in progress.
    pub fn initiate(&mut self, ssid: &[u8; 8], question: &[u8], secret: &[u8]) -> Result<TLV, OTRError> {
        match self.smp {
            SMPState::Expect1 {} => {},
            _ => return Err(OTRError::SMPInProgress),
        }
        let g1 = DH::generator();
        let initiator: Fingerprint;
        let x = compute_secret(&initiator, &self.fingerprint, ssid, secret);
        let (a2, a3) = (random(), random());
        let g2a = g1.modpow(&a2, &MODULUS);
        let g3a = g1.modpow(&a3, &MODULUS);
        let (r2, r3) = (random(), random());

        // FIXME should we strip prefix zeroes for public keys when serializing?
        // FIXME perform modulation?
        let c2 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(1u8,
            &OTREncoder::new().write_mpi(&g1.modpow(&r2, &MODULUS)).to_vec()));
        let D2: BigUint = (&r2 - &a2*&c2).mod_floor(&MODULUS);
        let c3 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(2u8,
            &OTREncoder::new().write_mpi(&g1.modpow(&r3, &MODULUS)).to_vec()));
        let D3: BigUint = (&r3 - &a3*&c3).mod_floor(&MODULUS);

        let mut typ = TLV_TYPE_SMP_MESSAGE_1;
        let mut encoder = OTREncoder::new();
        if question.len() > 0 {
            typ = TLV_TYPE_SMP_MESSAGE_1Q;
            encoder.write_bytes_null_terminated(question);
        }
        let payload = encoder.write_mpi_sequence(&[&g2a, &c2, &D2, &g3a, &c3, &D3]).to_vec();
        self.smp = SMPState::Expect2{x, a2, a3};
        Ok(TLV(typ, payload))
    }

    /// Indiscriminately reset SMP state to StateExpect1. Returns TLV with SMP Abort-payload.
    pub fn abort(&mut self) -> Result<TLV, OTRError> {
        self.smp = SMPState::Expect1;
        Ok(TLV(TLV_TYPE_SMP_ABORT, Vec::new()))
    }

    pub fn handleMessage1(&mut self, tlv: TLV, ssid: &SSID, question: &[u8], secret: &[u8]) -> Result<TLV, OTRError> {
        let g1 = DH::generator();
        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 6 {
            return Err(OTRError::ProtocolViolation("Unexpected number of MPI values"));
        }
        let D3 = mpis.pop().unwrap();
        let c3 = mpis.pop().unwrap();
        let g3a = mpis.pop().unwrap();
        let D2 = mpis.pop().unwrap();
        let c2 = mpis.pop().unwrap();
        let g2a = mpis.pop().unwrap();
        
        DH::verify_public_key(&g2a)
            .or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        DH::verify_public_key(&g3a)
            .or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        let expected_c2 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(1u8,
            &OTREncoder::new().write_mpi(
                    &(g1.modpow(&D2, &MODULUS) * g2a.modpow(&c2, &MODULUS)).mod_floor(&MODULUS)
                ).to_vec()));
        DH::verify(&expected_c2, &c2)
            .or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        let expected_c3 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(2u8,
            &OTREncoder::new().write_mpi(
                    &(g1.modpow(&D3, &MODULUS) * g3a.modpow(&c3, &MODULUS)).mod_floor(&MODULUS)
                ).to_vec()));
        DH::verify(&expected_c3, &c3)
            .or_else(|err| Err(OTRError::CryptographicViolation(err)))?;


        let our_fingerprint: Fingerprint;
        let y = compute_secret(&self.fingerprint, &our_fingerprint, ssid, secret);
        let (b2, b3) = (random(), random());
        let (r2, r3, r4, r5, r6) = (random(), random(), random(), random(), random());
        let g2b = g1.modpow(&b2, &MODULUS);
        let g3b = g1.modpow(&b3, &MODULUS);
        let c2 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(3u8, &OTREncoder::new().write_mpi(
            &g1.modpow(&r2, &MODULUS)
        ).to_vec()));
        // FIXME Verify what this means for the constants used: "In the zero-knowledge proofs the D values are calculated modulo q = (p - 1) / 2, where p is the same 1536-bit prime as elsewhere. The random exponents are 1536-bit numbers."
        let D2 = (&r2 - &b2*&c2).mod_floor(&MODULUS);
        let c3 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(4u8, &OTREncoder::new().write_mpi(
            &g1.modpow(&r3, &MODULUS)
        ).to_vec()));
        let D3 = (&r3 - &b3*&c3).mod_floor(&MODULUS);

        let g2 = g2a.modpow(&b2, &MODULUS);
        let g3 = g3a.modpow(&b3, &MODULUS);
        let pb = g3.modpow(&r4, &MODULUS);
        let qb = (g1.modpow(&r4, &MODULUS) * g2.modpow(&y, &MODULUS)).mod_floor(&MODULUS);

        // FIXME continue with 9 (generate cP D6)

        let payload: Vec<u8>;
        self.smp = SMPState::Expect3{g3a, g2, g3, b3, pb, qb};
        Ok(TLV(TLV_TYPE_SMP_MESSAGE_2, payload))
    }

    pub fn handleMessage2(&mut self, tlv: TLV) -> Result<TLV, OTRError> {
        todo!()
    }

    pub fn handleMessage3(&mut self, tlv: TLV) -> Result<TLV, OTRError> {
        todo!()
    }

    pub fn handleMessage4(&mut self, tlv: TLV) -> Result<TLV, OTRError> {
        todo!()
    }
}

// FIXME is there a nicer (more fluent) way to make the second mpi optional?
fn hash(version: u8, mpi1: BigUint, mpi2: Option<BigUint>) -> [u8; 32] {
    let mut data = vec![version];
    let mut encoder = OTREncoder::new();
    encoder.write_mpi(&mpi1);
    // TODO not very elegant to abuse pure-functional construct for side-effectful code.
    mpi2.map(|v| encoder.write_mpi(&v));
    data.extend(encoder.to_vec());
    SHA256::digest(&data)
}

fn compute_secret(initiator: &Fingerprint, responder: &Fingerprint, ssid: &SSID, secret: &[u8]) -> BigUint {
    let secret = SHA256::digest(&OTREncoder::new()
        .write_byte(1)
        .write_fingerprint(initiator)
        .write_fingerprint(responder)
        .write_ssid(ssid)
        // FIXME is 'data' the write serialization type for user-specified secret?
        .write_data(secret)
        .to_vec());
    BigUint::from_bytes_be(&secret)
}

enum SMPState {
    Expect1,
    Expect2{
        x: BigUint,
        a2: BigUint,
        a3: BigUint,
    },
    Expect3{
        g3a: BigUint,
        g2: BigUint,
        g3: BigUint,
        b3: BigUint,
        pb: BigUint,
        qb: BigUint,
    },
    Expect4,
}

#[derive(std::fmt::Debug)]
enum SMPError {
    AlreadyInProgress,
    ContentViolation(OTRError),
}

fn random() -> BigUint {
    let mut v = [0u8; 192];
    RAND.fill(&mut v)
        .expect("Failed to produce random bytes for random big unsigned integer value.");
    // FIXME already perform modulo for efficiency?
    BigUint::from_bytes_be(&v)
}

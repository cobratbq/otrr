use std::ops::{Sub};

use num::{
    integer::{Integer},
    FromPrimitive,
};
use num_bigint::BigUint;
use ring::rand::{SecureRandom, SystemRandom};

use crate::{
    crypto::{CryptoError, DH, SHA256},
    encoding::{encodeBigUint, Fingerprint, OTRDecoder, OTREncoder, SSID},
    OTRError, TLV,
};
use DH::{MODULUS, MODULUS_MINUS_TWO};

/// TLV for initiating SMP
const TLV_TYPE_SMP_MESSAGE_1: u16 = 2u16;
const TLV_TYPE_SMP_MESSAGE_2: u16 = 3u16;
const TLV_TYPE_SMP_MESSAGE_3: u16 = 4u16;
const TLV_TYPE_SMP_MESSAGE_4: u16 = 5u16;
const TLV_TYPE_SMP_ABORT: u16 = 6u16;

/// TLV similar to message 1 but includes a user-specified question (null-terminated) in the payload.
const TLV_TYPE_SMP_MESSAGE_1Q: u16 = 7u16;

static RAND: SystemRandom = SystemRandom::new();
// FIXME verify correct modulus is used in all D-value calculations (Q i.s.o. DH::MODULUS)
// "D values are calculated modulo `q = (p - 1) / 2`"
// FIXME why should we clone this value??????
static Q: BigUint = MODULUS.clone().sub(BigUint::from_u8(1).unwrap()) / BigUint::from_u8(2).unwrap();

pub struct SMPContext {
    /// fingerprint of the other party
    fingerprint: Fingerprint,
    smp: SMPState,
    rand: SystemRandom,
}

// FIXME handle for each message SMP state machine being in wrong state having to discard message and reset.
impl SMPContext {
    pub fn new(fingerprint: Fingerprint) -> SMPContext {
        SMPContext {
            fingerprint,
            smp: SMPState::Expect1,
            rand: SystemRandom::new(),
        }
    }

    /// Initiate SMP. Produces SMPError::AlreadyInProgress if SMP is in progress.
    pub fn initiate(
        &mut self,
        ssid: &[u8; 8],
        question: &[u8],
        secret: &[u8],
    ) -> Result<TLV, OTRError> {
        if let SMPState::Expect1 = self.smp {
            // SMP in initial state, initiation can proceed without interrupting in-progress SMP.
        } else {
            return Err(OTRError::SMPInProgress);
        }
        let g1 = *DH::GENERATOR;
        let initiator: Fingerprint;
        let x = compute_secret(&initiator, &self.fingerprint, ssid, secret);
        let (a2, a3) = (random(), random());
        let g2a = g1.modpow(&a2, &MODULUS);
        let g3a = g1.modpow(&a3, &MODULUS);
        let (r2, r3) = (random(), random());

        // FIXME should we strip prefix zeroes for public keys when serializing?
        // FIXME perform modulation?
        let c2 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(
            1,
            &OTREncoder::new()
                .write_mpi(&g1.modpow(&r2, &MODULUS))
                .to_vec(),
        ));
        let D2: BigUint = (&r2 - &a2 * &c2).mod_floor(&Q);
        let c3 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(
            2,
            &OTREncoder::new()
                .write_mpi(&g1.modpow(&r3, &MODULUS))
                .to_vec(),
        ));
        let D3: BigUint = (&r3 - &a3 * &c3).mod_floor(&Q);

        let mut encoder = OTREncoder::new();
        let typ = if question.is_empty() {
            TLV_TYPE_SMP_MESSAGE_1
        } else {
            encoder.write_bytes_null_terminated(question);
            TLV_TYPE_SMP_MESSAGE_1Q
        };
        let payload = encoder
            .write_mpi_sequence(&[&g2a, &c2, &D2, &g3a, &c3, &D3])
            .to_vec();
        self.smp = SMPState::Expect2 { x, a2, a3 };
        Ok(TLV(typ, payload))
    }

    /// Indiscriminately reset SMP state to StateExpect1. Returns TLV with SMP Abort-payload.
    pub fn abort(&mut self) -> TLV {
        self.smp = SMPState::Expect1;
        TLV(TLV_TYPE_SMP_ABORT, Vec::new())
    }

    // FIXME still need to handle question embedded in TLV record.
    pub fn handleMessage1(
        &mut self,
        tlv: TLV,
        ssid: &SSID,
        question: &[u8],
        secret: &[u8],
    ) -> Result<TLV, OTRError> {
        assert!(tlv.0 == TLV_TYPE_SMP_MESSAGE_1 || tlv.0 == TLV_TYPE_SMP_MESSAGE_1Q);
        if let SMPState::Expect1 = &self.smp {
            // SMP in expected state. TLV processing can proceed.
        } else {
            self.smp = SMPState::Expect1;
            return Err(OTRError::SMPAborted(TLV(TLV_TYPE_SMP_ABORT, Vec::new())));
        }
        // FIXME what is the exact format, where is the question embedded?
        let g1 = *DH::GENERATOR;
        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 6 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values",
            ));
        }
        let D3 = mpis.pop().unwrap();
        let c3 = mpis.pop().unwrap();
        let g3a = mpis.pop().unwrap();
        let D2 = mpis.pop().unwrap();
        let c2 = mpis.pop().unwrap();
        let g2a = mpis.pop().unwrap();

        // "Verify Alice's zero-knowledge proofs for g2a and g3a:"
        // "1. Check that both g2a and g3a are >= 2 and <= modulus-2."
        DH::verify_public_key(&g2a).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        DH::verify_public_key(&g3a).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        // "2. Check that c2 = SHA256(1, g1D2 g2ac2)."
        let expected_c2 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(
            1,
            &OTREncoder::new()
                .write_mpi(
                    &(g1.modpow(&D2, &MODULUS) * g2a.modpow(&c2, &MODULUS)).mod_floor(&MODULUS),
                )
                .to_vec(),
        ));
        DH::verify(&expected_c2, &c2).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        // "3. Check that c3 = SHA256(2, g1D3 g3ac3)."
        let expected_c3 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(
            2,
            &OTREncoder::new()
                .write_mpi(
                    &(g1.modpow(&D3, &MODULUS) * g3a.modpow(&c3, &MODULUS)).mod_floor(&MODULUS),
                )
                .to_vec(),
        ));
        DH::verify(&expected_c3, &c3).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        let our_fingerprint: Fingerprint;

        // "Create a type 3 TLV (SMP message 2) and send it to Alice: "
        // "1. Determine Bob's secret input y, which is to be compared to Alice's secret x."
        let y = compute_secret(&self.fingerprint, &our_fingerprint, ssid, secret);
        // "2. Pick random exponents b2 and b3. These will used during the DH exchange to pick
        // generators."
        let (b2, b3) = (random(), random());
        // "3. Pick random exponents r2, r3, r4, r5 and r6. These will be used to add a blinding
        // factor to the final results, and to generate zero-knowledge proofs that this message was
        // created honestly."
        let (r2, r3, r4, r5, r6) = (random(), random(), random(), random(), random());
        // "4. Compute g2b = g1b2 and g3b = g1b3"
        let g2b = g1.modpow(&b2, &MODULUS);
        let g3b = g1.modpow(&b3, &MODULUS);
        // "5. Generate a zero-knowledge proof that the exponent `b2` is known by setting
        // `c2 = SHA256(3, g1r2)` and `D2 = r2 - b2 c2 mod q`. In the zero-knowledge proofs the `D`
        // values are calculated modulo `q = (p - 1) / 2`, where `p` is the same 1536-bit prime as
        // elsewhere. The random exponents are 1536-bit numbers."
        let c2 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(
            3u8,
            &OTREncoder::new()
                .write_mpi(&g1.modpow(&r2, &MODULUS))
                .to_vec(),
        ));
        let D2 = (&r2 - &b2 * &c2).mod_floor(&Q);
        // "6. Generate a zero-knowledge proof that the exponent b3 is known by setting
        // `c3 = SHA256(4, g1r3)` and `D3 = r3 - b3 c3 mod q`."
        let c3 = BigUint::from_bytes_be(&SHA256::digest_with_prefix(
            4u8,
            &OTREncoder::new()
                .write_mpi(&g1.modpow(&r3, &MODULUS))
                .to_vec(),
        ));
        let D3 = (&r3 - &b3 * &c3).mod_floor(&Q);
        // "7. Compute `g2 = g2ab2` and `g3 = g3ab3`"
        let g2 = g2a.modpow(&b2, &MODULUS);
        let g3 = g3a.modpow(&b3, &MODULUS);
        // "8. Compute `Pb = g3r4` and `Qb = g1r4 g2y`"
        let pb = g3.modpow(&r4, &MODULUS);
        let qb = (g1.modpow(&r4, &MODULUS) * g2.modpow(&y, &MODULUS)).mod_floor(&MODULUS);
        // "9. Generate a zero-knowledge proof that `Pb` and `Qb` were created according to the
        // protocol by setting `cP = SHA256(5, g3r5, g1r5 g2r6)`, `D5 = r5 - r4 cP mod q` and
        // `D6 = r6 - y cP mod q`."
        let cp = BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            5,
            &encodeBigUint(&g3.modpow(&r5, &MODULUS)),
            &encodeBigUint(
                &(g1.modpow(&r5, &MODULUS) * g2.modpow(&r6, &MODULUS)).mod_floor(&MODULUS),
            ),
        ));
        let D5 = (&r5 - &r4 * &cp).mod_floor(&Q);
        let D6 = (&r6 - &y * &cp).mod_floor(&Q);

        let payload = OTREncoder::new()
            .write_mpi_sequence(&[&g2b, &c2, &D2, &g3b, &c3, &D3, &pb, &qb, &cp, &D5, &D6])
            .to_vec();
        self.smp = SMPState::Expect3 {
            g3a,
            g2,
            g3,
            b3,
            pb,
            qb,
        };
        Ok(TLV(TLV_TYPE_SMP_MESSAGE_2, payload))
    }

    pub fn handleMessage2(&mut self, tlv: TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_2);
        // "SMP message 2 is sent by Bob to complete the DH exchange to determine the new
        //  generators, `g2` and `g3`. It also begins the construction of the values used in the final
        //  comparison of the protocol."
        let x: BigUint;
        let a2: BigUint;
        let a3: BigUint;
        if let SMPState::Expect2 {
            x: _x,
            a2: _a2,
            a3: _a3,
        } = &self.smp
        {
            x = _x.to_owned();
            a2 = _a2.to_owned();
            a3 = _a3.to_owned();
        } else {
            // "If smpstate is not `SMPSTATE_EXPECT2`:
            //    Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (`SMP abort`) to Bob."
            self.smp = SMPState::Expect1;
            return Err(OTRError::SMPAborted(TLV(TLV_TYPE_SMP_ABORT, Vec::new())));
        }
        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 11 {
            self.smp = SMPState::Expect1;
            return Err(OTRError::SMPProtocolViolation);
        }
        // "It contains the following mpi values:
        //  `cP`, `D5`, `D6`: A zero-knowledge proof that Pb and Qb were created according to the
        //  protcol given above."
        let D6 = mpis.pop().unwrap();
        let D5 = mpis.pop().unwrap();
        let cp = mpis.pop().unwrap();
        // "`Pb`, `Qb`: These values are used in the final comparison to determine if Alice and Bob
        //  share the same secret."
        let qb = mpis.pop().unwrap();
        let pb = mpis.pop().unwrap();
        // "`c3`, `D3`: A zero-knowledge proof that Bob knows the exponent associated with his
        //  transmitted value g3b."
        let D3 = mpis.pop().unwrap();
        let c3 = mpis.pop().unwrap();
        // "`g3b`: Bob's half of the DH exchange to determine g3."
        let g3b = mpis.pop().unwrap();
        // "`c2`, `D2`: A zero-knowledge proof that Bob knows the exponent associated with his
        //  transmitted value g2b."
        let D2 = mpis.pop().unwrap();
        let c2 = mpis.pop().unwrap();
        // "`g2b`: Bob's half of the DH exchange to determine g2."
        let g2b = mpis.pop().unwrap();

        let g1 = *DH::GENERATOR;
        // "Check that `g2b`, `g3b`, `Pb` and `Qb` are `>= 2 and <= modulus-2`."
        DH::verify_public_key(&g2b).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        DH::verify_public_key(&g3b).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        DH::verify_public_key(&pb).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        DH::verify_public_key(&qb).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        // "Check that `c2 = SHA256(3, g1D2 g2bc2)`."
        let c2_expected = BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            3,
            &OTREncoder::new()
                .write_mpi(&g1.modpow(&D2, &MODULUS))
                .to_vec(),
            &OTREncoder::new()
                .write_mpi(&g2b.modpow(&c2, &MODULUS))
                .to_vec(),
        ));
        DH::verify(&c2_expected, &c2).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        // "Check that `c3 = SHA256(4, g1D3 g3bc3)`."
        let c3_expected = BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            4,
            &OTREncoder::new()
                .write_mpi(&g1.modpow(&D3, &MODULUS))
                .to_vec(),
            &OTREncoder::new()
                .write_mpi(&g3b.modpow(&c3, &MODULUS))
                .to_vec(),
        ));
        DH::verify(&c3_expected, &c3).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        // "Check that `cP = SHA256(5, g3D5 PbcP, g1D5 g2D6 QbcP)`."
        let cp_expected = BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            5,
            &OTREncoder::new()
                .write_mpi(
                    &(&g3.modpow(&D5, &MODULUS) * &pb.modpow(&cp, &MODULUS)).mod_floor(&MODULUS),
                )
                .to_vec(),
            &OTREncoder::new()
                .write_mpi(
                    &(&g1.modpow(&D5, &MODULUS)
                        * &g2.modpow(&D6, &MODULUS)
                        * &qb.modpow(&cp, &MODULUS))
                        .mod_floor(&MODULUS),
                )
                .to_vec(),
        ));
        DH::verify(&cp_expected, &cp).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;

        // "Create a type 4 TLV (SMP message 3) and send it to Bob:
        //  Pick random exponents `r4`, `r5`, `r6` and `r7`. These will be used to add a blinding
        //  factor to the final results, and to generate zero-knowledge proofs that this message
        //  was created honestly."
        let r4 = random();
        let r5 = random();
        let r6 = random();
        let r7 = random();
        // "Compute `g2 = g2ba2` and `g3 = g3ba3`"
        let g2 = g2b.modpow(&a2, &MODULUS);
        let g3 = g3b.modpow(&a3, &MODULUS);
        // "Compute `Pa = g3r4` and `Qa = g1r4 g2x`"
        let pa = g3.modpow(&r4, &MODULUS);
        let qa = (&g1.modpow(&r4, &MODULUS) * &g2.modpow(&x, &MODULUS)).mod_floor(&MODULUS);
        // "Generate a zero-knowledge proof that Pa and Qa were created according to the protocol
        //  by setting `cP = SHA256(6, g3r5, g1r5 g2r6)`, ..."
        let cp = BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            6,
            &OTREncoder::new()
                .write_mpi(&g3.modpow(&r5, &MODULUS))
                .to_vec(),
            &OTREncoder::new()
                .write_mpi(
                    &(&g1.modpow(&r5, &MODULUS) * &g2.modpow(&r6, &MODULUS).mod_floor(&MODULUS)),
                )
                .to_vec(),
        ));
        // "... `D5 = r5 - r4 cP mod q`, and ..."
        let D5 = (r5 - r4 * cp).mod_floor(&Q);
        // "... `D6 = r6 - x cP mod q`."
        let D6 = (r6 - x * cp).mod_floor(&Q);
        // "Compute `Ra = (Qa / Qb) a3`"
        let ra = (qa / qb).modpow(&a3, &MODULUS);
        // "Generate a zero-knowledge proof that Ra was created according to the protocol by
        //  setting `cR = SHA256(7, g1r7, (Qa / Qb)r7)` and ..."
        let cr: BigUint;
        // "... `D7 = r7 - a3 cR mod q`."
        let D7 = (r7 - a3 * cr).mod_floor(&Q);
        /*
           Store the values of g3b, (Pa / Pb), (Qa / Qb) and a3 for use later in the protocol.
           Send Bob a type 4 TLV (SMP message 3) containing Pa, Qa, cP, D5, D6, Ra, cR and D7 in that order.
        */
        let tlv = TLV(
            TLV_TYPE_SMP_MESSAGE_3,
            OTREncoder::new()
                .write_mpi_sequence(&[&pa, &qa, &cp, &D5, &D6, &ra, &cr, &D7])
                .to_vec(),
        );
        // FIXME probably requires use of modular inverse? (no support, needs different crate)
        let padivpb: BigUint;
        let qadivqb: BigUint;
        // "Set smpstate to SMPSTATE_EXPECT4."
        self.smp = SMPState::Expect4 {
            a3,
            g3b,
            padivpb,
            qadivqb,
        };
        Ok(tlv)
    }

    pub fn handleMessage3(&mut self, tlv: TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_3);
        // When Bob receives this TLV he should do:
        //
        // If smpstate is not SMPSTATE_EXPECT3:
        //     Set smpstate to SMPSTATE_EXPECT1 and send a type 6 TLV (SMP abort) to Bob.

        // FIXME: do we handle the bad case here, or is it handled by the caller before reaching here?

        // If smpstate is SMPSTATE_EXPECT3:
        let g3a: BigUint;
        let g2: BigUint;
        let g3: BigUint;
        let b3: BigUint;
        let pb: BigUint;
        let qb: BigUint;
        if let SMPState::Expect3 {
            g3a: _g3a,
            g2: _g2,
            g3: _g3,
            b3: _b3,
            pb: _pb,
            qb: _qb,
        } = &self.smp
        {
            g3a = _g3a.to_owned();
            g2 = _g2.to_owned();
            g3 = _g3.to_owned();
            b3 = _b3.to_owned();
            pb = _pb.to_owned();
            qb = _qb.to_owned();
        } else {
            self.smp = SMPState::Expect1;
            return Err(OTRError::SMPAborted(TLV(TLV_TYPE_SMP_ABORT, Vec::new())));
        }

        // SMP message 3 is Alice's final message in the SMP exchange. It has the last of the information required by Bob to determine if x = y. It contains the following mpi values:

        // Pa, Qa
        //     These values are used in the final comparison to determine if Alice and Bob share the same secret.
        // cP, D5, D6
        //     A zero-knowledge proof that Pa and Qa were created according to the protcol given above.
        // Ra
        //     This value is used in the final comparison to determine if Alice and Bob share the same secret.
        // cR, D7
        //     A zero-knowledge proof that Ra was created according to the protcol given above.
        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 8 {
            self.smp = SMPState::Expect1;
            return Err(OTRError::SMPProtocolViolation);
        }
        let D7 = mpis.pop().unwrap();
        let cr = mpis.pop().unwrap();
        let ra = mpis.pop().unwrap();
        let D6 = mpis.pop().unwrap();
        let D5 = mpis.pop().unwrap();
        let cp = mpis.pop().unwrap();
        let qa = mpis.pop().unwrap();
        let pa = mpis.pop().unwrap();

        // Verify Alice's zero-knowledge proofs for Pa, Qa and Ra:

        // Check that Pa, Qa and Ra are >= 2 and <= modulus-2.
        if pa < BigUint::from_u8(2).unwrap() || pa > *MODULUS_MINUS_TWO {
            return Err(OTRError::CryptographicViolation(
                CryptoError::VerificationFailure("illegal value for Pa"),
            ));
        }

        let g1 = *DH::GENERATOR;
        // Check that cP = SHA256(6, g3^D5 Pa^cP, g1^D5 g2^D6 Qa^cP).
        let cp_part1 = (g3.modpow(&D5, &MODULUS) * pa.modpow(&cp, &MODULUS)).mod_floor(&MODULUS);
        let cp_part2 =
            (g1.modpow(&D5, &MODULUS) * g2.modpow(&D6, &MODULUS) * qa.modpow(&cp, &MODULUS))
                .mod_floor(&MODULUS);
        if cp != BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            6u8,
            &OTREncoder::new().write_mpi(&cp_part1).to_vec(),
            &OTREncoder::new().write_mpi(&cp_part2).to_vec(),
        )) {
            return Err(OTRError::CryptographicViolation(CryptoError::VerificationFailure("failed to verify cR")))
        }

        // Check that cR = SHA256(7, g1D7 g3acR, (Qa / Qb)D7 RacR).

        /*

           Create a type 5 TLV (SMP message 4) and send it to Alice:

               Pick a random exponent r7. This will be used to generate Bob's final zero-knowledge proof that this message was created honestly.
               Compute Rb = (Qa / Qb) b3
               Generate a zero-knowledge proof that Rb was created according to the protocol by setting cR = SHA256(8, g1r7, (Qa / Qb)r7) and D7 = r7 - b3 cR mod q.
               Send Alice a type 5 TLV (SMP message 4) containing Rb, cR and D7 in that order.

           Check whether the protocol was successful:

               Compute Rab = Rab3.
               Determine if x = y by checking the equivalent condition that (Pa / Pb) = Rab.

           Set smpstate to SMPSTATE_EXPECT1, as no more messages are expected from Alice.
        */
        todo!()
    }

    pub fn handleMessage4(&mut self, tlv: TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_4);
        let g3b: BigUint;
        let padivpb: BigUint;
        let qadivqb: BigUint;
        let a3: BigUint;
        if let SMPState::Expect4 {
            g3b: _g3b,
            padivpb: _padivpb,
            qadivqb: _qadivqb,
            a3: _a3,
        } = &self.smp
        {
            g3b = _g3b.to_owned();
            padivpb = _padivpb.to_owned();
            qadivqb = _qadivqb.to_owned();
            a3 = _a3.to_owned();
        } else {
            self.smp = SMPState::Expect1;
            return Err(OTRError::SMPAborted(TLV(TLV_TYPE_SMP_ABORT, Vec::new())));
        }
        // FIXME verify state and reset if unexpected
        let g1 = *DH::GENERATOR;
        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 3 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values.",
            ));
        }
        let D7 = mpis.pop().unwrap();
        let cR = mpis.pop().unwrap();
        let Rb = mpis.pop().unwrap();

        let Qa: BigUint;
        let Qb: BigUint;

        DH::verify_public_key(&Rb).or_else(|err| Err(OTRError::CryptographicViolation(err)))?;
        let expected_cR = BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
            8u8,
            &OTREncoder::new()
                .write_mpi(&(g1.modpow(&D7, &MODULUS) * g3b.modpow(&cR, &MODULUS)))
                .to_vec(),
            &OTREncoder::new()
                .write_mpi(
                    &((&Qa / &Qb).modpow(&D7, &MODULUS) * (&Rb.modpow(&cR, &MODULUS)))
                        .mod_floor(&MODULUS),
                )
                .to_vec(),
        ));

        /*
        SMP message 4 is Bob's final message in the SMP exchange. It has the last of the information required by Alice to determine if x = y. It contains the following mpi values:

        Rb
            This value is used in the final comparison to determine if Alice and Bob share the same secret.
        cR, D7
            A zero-knowledge proof that Rb was created according to the protcol given above.

        When Alice receives this TLV she should do:

        If smpstate is not SMPSTATE_EXPECT4:
            Set smpstate to SMPSTATE_EXPECT1 and send a type 6 TLV (SMP abort) to Bob.
        If smpstate is SMPSTATE_EXPECT4:
            Verify Bob's zero-knowledge proof for Rb:

                Check that Rb is >= 2 and <= modulus-2.
                Check that cR = SHA256(8, g1D7 g3bcR, (Qa / Qb)D7 RbcR).

            Check whether the protocol was successful:

                Compute Rab = Rba3.
                Determine if x = y by checking the equivalent condition that (Pa / Pb) = Rab.

            Set smpstate to SMPSTATE_EXPECT1, as no more messages are expected from Bob.
         */

        self.smp = SMPState::Expect1;
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

fn compute_secret(
    initiator: &Fingerprint,
    responder: &Fingerprint,
    ssid: &SSID,
    secret: &[u8],
) -> BigUint {
    let secret = SHA256::digest(
        &OTREncoder::new()
            .write_byte(1)
            .write_fingerprint(initiator)
            .write_fingerprint(responder)
            .write_ssid(ssid)
            // FIXME is 'data' the write serialization type for user-specified secret?
            .write_data(secret)
            .to_vec(),
    );
    BigUint::from_bytes_be(&secret)
}

enum SMPState {
    Expect1,
    Expect2 {
        x: BigUint,
        a2: BigUint,
        a3: BigUint,
    },
    Expect3 {
        g3a: BigUint,
        g2: BigUint,
        g3: BigUint,
        b3: BigUint,
        pb: BigUint,
        qb: BigUint,
    },
    Expect4 {
        g3b: BigUint,
        padivpb: BigUint,
        qadivqb: BigUint,
        a3: BigUint,
    },
}

fn random() -> BigUint {
    let mut v = [0u8; 192];
    RAND.fill(&mut v)
        .expect("Failed to produce random bytes for random big unsigned integer value.");
    // FIXME already perform modulo for efficiency?
    BigUint::from_bytes_be(&v)
}

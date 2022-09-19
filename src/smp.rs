use std::rc::Rc;

use num_bigint::BigUint;
use num_integer::Integer;
use once_cell::sync::Lazy;
use ring::rand::{SecureRandom, SystemRandom};

use crate::{
    crypto::{DH, OTR, SHA256},
    encoding::{Fingerprint, OTRDecoder, OTREncoder, SSID},
    Host, OTRError, TLVType, TLV,
};

pub fn any_smp_tlv(tlvs: &[TLV]) -> bool {
    tlvs.iter().any(is_smp_tlv)
}

pub fn is_smp_tlv(tlv: &TLV) -> bool {
    TLV_TYPES.contains(&tlv.0)
}

const TLV_TYPES: [u16; 6] = [
    TLV_TYPE_SMP_MESSAGE_1,
    TLV_TYPE_SMP_MESSAGE_1Q,
    TLV_TYPE_SMP_MESSAGE_2,
    TLV_TYPE_SMP_MESSAGE_3,
    TLV_TYPE_SMP_MESSAGE_4,
    TLV_TYPE_SMP_ABORT,
];

/// TLV for initiating SMP
const TLV_TYPE_SMP_MESSAGE_1: TLVType = 2u16;
const TLV_TYPE_SMP_MESSAGE_2: TLVType = 3u16;
const TLV_TYPE_SMP_MESSAGE_3: TLVType = 4u16;
const TLV_TYPE_SMP_MESSAGE_4: TLVType = 5u16;
const TLV_TYPE_SMP_ABORT: TLVType = 6u16;
/// TLV similar to message 1 but includes a user-specified question (null-terminated) in the payload.
const TLV_TYPE_SMP_MESSAGE_1Q: TLVType = 7u16;

static RAND: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);

pub struct SMPContext {
    status: SMPStatus,
    state: SMPState,
    ssid: SSID,
    our_fingerprint: Fingerprint,
    their_fingerprint: Fingerprint,
    host: Rc<dyn Host>,
}

// TODO check values within boundaries, for `modulus` and `q` (>2, <order)
// TODO review proper checking of public keys using verification functions
// TODO log control flow change "abort"?
// FIXME need to handle any of the values received from the TLV. (e.g. verification of D# values)
#[allow(non_snake_case)]
impl SMPContext {
    // TODO provide way to check outcome of SMP, positive (validated) or negative (failure/reset/abort)

    pub fn new(
        host: Rc<dyn Host>,
        ssid: SSID,
        our_fingerprint: Fingerprint,
        their_fingerprint: Fingerprint,
    ) -> Self {
        Self {
            status: SMPStatus::Initial,
            state: SMPState::Expect1,
            host,
            ssid,
            our_fingerprint,
            their_fingerprint,
        }
    }

    pub fn status(&self) -> SMPStatus {
        // TODO is cloning the most efficient solution here? (it seems overkill)
        self.status.clone()
    }

    /// Initiate SMP. Produces SMPError::AlreadyInProgress if SMP is in progress.
    pub fn initiate(&mut self, secret: &[u8], question: &[u8]) -> Result<TLV, OTRError> {
        if let SMPState::Expect1 = self.state {
            // SMP in initial state, initiation can proceed without interrupting in-progress SMP.
            self.status = SMPStatus::InProgress;
        } else {
            // "SMP is already underway. If you wish to restart SMP, send a type 6 TLV (SMP
            //  abort) to the other party and then proceed as if smpstate was SMPSTATE_EXPECT1.
            //  Otherwise, you may simply continue the current SMP instance."
            return Err(OTRError::SMPInProgress);
        }
        let x = compute_secret(
            &self.our_fingerprint,
            &self.their_fingerprint,
            &self.ssid,
            secret,
        );

        let MOD = DH::modulus();
        let q = DH::q();
        let g1 = DH::generator();

        let (a2, a3) = (random(), random());
        let g2a = g1.modpow(&a2, MOD);
        let g3a = g1.modpow(&a3, MOD);

        let (r2, r3) = (random(), random());
        let c2 = hash_1_mpi(1, &g1.modpow(&r2, MOD));
        let D2 = (&r2 - &a2 * &c2).mod_floor(q);
        let c3 = hash_1_mpi(2, &g1.modpow(&r3, MOD));
        let D3 = (&r3 - &a3 * &c3).mod_floor(q);

        let mut encoder = OTREncoder::new();
        let typ = if question.is_empty() {
            TLV_TYPE_SMP_MESSAGE_1
        } else {
            encoder.write_bytes_null_terminated(question);
            TLV_TYPE_SMP_MESSAGE_1Q
        };
        encoder.write_mpi_sequence(&[&g2a, &c2, &D2, &g3a, &c3, &D3]);
        let tlv = TLV(typ, encoder.to_vec());
        self.state = SMPState::Expect2 { x, a2, a3 };
        Ok(tlv)
    }

    /// `handle` handles the SMP TLVs that are received as payload in OTR Data messages.
    ///
    /// Design considerations:
    /// a)  in case an unexpected TLV (compared to the current state) is received, we silently reset
    ///     the state to EXPECT1. Returning an error is not very useful as the SMP TLVs are payload
    ///     of Data messages, meaning that confidentiality and authenticity are already guaranteed.
    ///     This essentially means that very little can go wrong under normal circumstances, even if
    ///     some message manipulation is taken into account.
    pub fn handle(&mut self, tlv: &TLV) -> Option<TLV> {
        // TODO add some assertions for state corresponding to status, for sanity-checking.
        match self.dispatch(tlv) {
            Ok(tlv) => Some(tlv),
            Err(OTRError::SMPSuccess(response)) => {
                self.status = SMPStatus::Success;
                response
            }
            Err(OTRError::SMPAborted(needs_abort_tlv)) => {
                self.state = SMPState::Expect1;
                if needs_abort_tlv {
                    self.status = SMPStatus::Aborted(Vec::from("Aborted by user"));
                    Some(TLV(TLV_TYPE_SMP_ABORT, Vec::new()))
                } else {
                    self.status = SMPStatus::Aborted(Vec::from("SMP Abort TLV received"));
                    None
                }
            }
            Err(OTRError::ProtocolViolation(msg)) => {
                self.state = SMPState::Expect1;
                self.status = SMPStatus::Aborted(Vec::from(format!("Protocol violation: {}", msg)));
                Some(TLV(TLV_TYPE_SMP_ABORT, Vec::new()))
            }
            Err(OTRError::IncompleteMessage) => {
                self.state = SMPState::Expect1;
                self.status = SMPStatus::Aborted(Vec::from(
                    "Protocol violation: message contents missing or malformed.",
                ));
                Some(TLV(TLV_TYPE_SMP_ABORT, Vec::new()))
            }
            Err(OTRError::CryptographicViolation(error)) => {
                self.state = SMPState::Expect1;
                self.status = SMPStatus::Aborted(Vec::from(format!(
                    "Protocol violation: cryptographic failure: {:?}",
                    &error
                )));
                Some(TLV(TLV_TYPE_SMP_ABORT, Vec::new()))
            }
            Err(_) => {
                // Unrecognized error case: this case should not occur.
                self.state = SMPState::Expect1;
                self.status = SMPStatus::Aborted(Vec::from(
                    "BUG: unexpected failure: reached default error case, used to mitigate for control flow.",
                ));
                panic!("BUG: default-case for error control flow. This is likely a missed error.")
            }
        }
    }

    fn dispatch(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        match tlv {
            tlv @ TLV(TLV_TYPE_SMP_MESSAGE_1, _) | tlv @ TLV(TLV_TYPE_SMP_MESSAGE_1Q, _) => {
                self.handleMessage1(tlv)
            }
            tlv @ TLV(TLV_TYPE_SMP_MESSAGE_2, _) => self.handleMessage2(tlv),
            tlv @ TLV(TLV_TYPE_SMP_MESSAGE_3, _) => self.handleMessage3(tlv),
            tlv @ TLV(TLV_TYPE_SMP_MESSAGE_4, _) => self.handleMessage4(tlv),
            TLV(TLV_TYPE_SMP_ABORT, _) => Err(OTRError::SMPAborted(false)),
            _ => panic!("BUG: incorrect TLV type: {}", tlv.0),
        }
    }

    fn handleMessage1(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert!(tlv.0 == TLV_TYPE_SMP_MESSAGE_1 || tlv.0 == TLV_TYPE_SMP_MESSAGE_1Q);
        if let SMPState::Expect1 = &self.state {
            // SMP in expected state. TLV processing can proceed.
            self.status = SMPStatus::InProgress;
        } else {
            return Err(OTRError::ProtocolViolation(
                "SMP message type 1 was expected.",
            ));
        }

        let mut decoder = OTRDecoder::new(&tlv.1);
        let received_question = if tlv.0 == TLV_TYPE_SMP_MESSAGE_1Q {
            decoder.read_bytes_null_terminated()?
        } else {
            Vec::new()
        };
        let mut mpis = decoder.read_mpi_sequence()?;
        if mpis.len() != 6 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values in SMP message 1 TLV",
            ));
        }
        let D3 = mpis.pop().unwrap();
        let c3 = mpis.pop().unwrap();
        let g3a = mpis.pop().unwrap();
        let D2 = mpis.pop().unwrap();
        let c2 = mpis.pop().unwrap();
        let g2a = mpis.pop().unwrap();
        assert_eq!(mpis.len(), 0);

        // "Verify Alice's zero-knowledge proofs for g2a and g3a:"
        // "1. Check that both g2a and g3a are >= 2 and <= modulus-2."
        DH::verify_public_key(&g2a).map_err(OTRError::CryptographicViolation)?;
        DH::verify_public_key(&g3a).map_err(OTRError::CryptographicViolation)?;

        let MOD = DH::modulus();
        let q = DH::q();
        let g1 = DH::generator();

        // "2. Check that c2 = SHA256(1, g1D2 g2ac2)."
        let expected_c2 = hash_1_mpi(
            1,
            &(g1.modpow(&D2, MOD) * g2a.modpow(&c2, MOD)).mod_floor(MOD),
        );
        DH::verify(&expected_c2, &c2).map_err(OTRError::CryptographicViolation)?;

        // "3. Check that c3 = SHA256(2, g1D3 g3ac3)."
        let expected_c3 = hash_1_mpi(
            2,
            &(g1.modpow(&D3, MOD) * g3a.modpow(&c3, MOD)).mod_floor(MOD),
        );
        DH::verify(&expected_c3, &c3).map_err(OTRError::CryptographicViolation)?;

        // "Create a type 3 TLV (SMP message 2) and send it to Alice: "
        // "1. Determine Bob's secret input y, which is to be compared to Alice's secret x."
        // TODO querying the host for the secret is synchronous, so it will hold up the SMP message processing. Would this be a problem in client implementation or can we keep it as simple as this?
        let answer = self.host.query_smp_secret(&received_question);
        if answer.is_none() {
            // Abort SMP because user has cancelled query for their secret.
            return Err(OTRError::SMPAborted(true));
        }
        let y = compute_secret(
            &self.their_fingerprint,
            &self.our_fingerprint,
            &self.ssid,
            &answer.unwrap(),
        );
        // "2. Pick random exponents b2 and b3. These will used during the DH exchange to pick
        // generators."
        let (b2, b3) = (random(), random());
        // "3. Pick random exponents r2, r3, r4, r5 and r6. These will be used to add a blinding
        // factor to the final results, and to generate zero-knowledge proofs that this message was
        // created honestly."
        let (r2, r3, r4, r5, r6) = (random(), random(), random(), random(), random());
        // "4. Compute g2b = g1b2 and g3b = g1b3"
        let g2b = g1.modpow(&b2, MOD);
        let g3b = g1.modpow(&b3, MOD);
        // "5. Generate a zero-knowledge proof that the exponent `b2` is known by setting
        // `c2 = SHA256(3, g1r2)` and `D2 = r2 - b2 c2 mod q`. In the zero-knowledge proofs the `D`
        // values are calculated modulo `q = (p - 1) / 2`, where `p` is the same 1536-bit prime as
        // elsewhere. The random exponents are 1536-bit numbers."
        let c2 = hash_1_mpi(3, &g1.modpow(&r2, MOD));
        let D2 = (&r2 - &b2 * &c2).mod_floor(q);
        // "6. Generate a zero-knowledge proof that the exponent b3 is known by setting
        // `c3 = SHA256(4, g1r3)` and `D3 = r3 - b3 c3 mod q`."
        let c3 = hash_1_mpi(4, &g1.modpow(&r3, MOD));
        let D3 = (&r3 - &b3 * &c3).mod_floor(q);
        // "7. Compute `g2 = g2ab2` and `g3 = g3ab3`"
        let g2 = g2a.modpow(&b2, MOD);
        let g3 = g3a.modpow(&b3, MOD);
        // "8. Compute `Pb = g3r4` and `Qb = g1r4 g2y`"
        let Pb = g3.modpow(&r4, MOD);
        let Qb = (g1.modpow(&r4, MOD) * g2.modpow(&y, MOD)).mod_floor(MOD);
        // "9. Generate a zero-knowledge proof that `Pb` and `Qb` were created according to the
        // protocol by setting `cP = SHA256(5, g3r5, g1r5 g2r6)`, `D5 = r5 - r4 cP mod q` and
        // `D6 = r6 - y cP mod q`."
        let cP = hash_2_mpi(
            5,
            &g3.modpow(&r5, MOD),
            &(g1.modpow(&r5, MOD) * g2.modpow(&r6, MOD)).mod_floor(MOD),
        );
        let D5 = (&r5 - &r4 * &cP).mod_floor(q);
        let D6 = (&r6 - &y * &cP).mod_floor(q);

        let payload = OTREncoder::new()
            .write_mpi_sequence(&[&g2b, &c2, &D2, &g3b, &c3, &D3, &Pb, &Qb, &cP, &D5, &D6])
            .to_vec();
        self.state = SMPState::Expect3 {
            g3a,
            g2,
            g3,
            b3,
            Pb,
            Qb,
        };
        Ok(TLV(TLV_TYPE_SMP_MESSAGE_2, payload))
    }

    fn handleMessage2(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
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
        } = &self.state
        {
            x = _x.to_owned();
            a2 = _a2.to_owned();
            a3 = _a3.to_owned();
        } else {
            return Err(OTRError::ProtocolViolation(
                "SMP message type 2 was expected.",
            ));
        }

        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 11 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values in SMP message 2 TLV",
            ));
        }
        // "It contains the following mpi values:
        //  `cP`, `D5`, `D6`: A zero-knowledge proof that Pb and Qb were created according to the
        //  protcol given above."
        let D6 = mpis.pop().unwrap();
        let D5 = mpis.pop().unwrap();
        let cP = mpis.pop().unwrap();
        // "`Pb`, `Qb`: These values are used in the final comparison to determine if Alice and Bob
        //  share the same secret."
        let Qb = mpis.pop().unwrap();
        let Pb = mpis.pop().unwrap();
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
        assert_eq!(mpis.len(), 0);

        // "Check that `g2b`, `g3b`, `Pb` and `Qb` are `>= 2 and <= modulus-2`."
        DH::verify_public_key(&g2b).map_err(OTRError::CryptographicViolation)?;
        DH::verify_public_key(&g3b).map_err(OTRError::CryptographicViolation)?;
        DH::verify_public_key(&Pb).map_err(OTRError::CryptographicViolation)?;
        DH::verify_public_key(&Qb).map_err(OTRError::CryptographicViolation)?;

        let MOD = DH::modulus();
        let q = DH::q();
        let g1 = DH::generator();

        // "Check that `c2 = SHA256(3, g1D2 g2bc2)`."
        let c2_expected = hash_1_mpi(
            3,
            &(&g1.modpow(&D2, MOD) * &g2b.modpow(&c2, MOD)).mod_floor(MOD),
        );
        DH::verify(&c2_expected, &c2).map_err(OTRError::CryptographicViolation)?;

        // "Check that `c3 = SHA256(4, g1D3 g3bc3)`."
        let c3_expected = hash_1_mpi(
            4,
            &(&g1.modpow(&D3, MOD) * &g3b.modpow(&c3, MOD)).mod_floor(MOD),
        );
        DH::verify(&c3_expected, &c3).map_err(OTRError::CryptographicViolation)?;

        // "Compute `g2 = g2ba2` and `g3 = g3ba3`"
        let g2 = g2b.modpow(&a2, MOD);
        let g3 = g3b.modpow(&a3, MOD);

        // "Check that `cP = SHA256(5, g3D5 PbcP, g1D5 g2D6 QbcP)`."
        let cP_expected = hash_2_mpi(
            5,
            &(&g3.modpow(&D5, MOD) * &Pb.modpow(&cP, MOD)).mod_floor(MOD),
            &(&g1.modpow(&D5, MOD) * &g2.modpow(&D6, MOD) * &Qb.modpow(&cP, MOD)).mod_floor(MOD),
        );
        DH::verify(&cP_expected, &cP).map_err(OTRError::CryptographicViolation)?;

        // "Create a type 4 TLV (SMP message 3) and send it to Bob:
        //  Pick random exponents `r4`, `r5`, `r6` and `r7`. These will be used to add a blinding
        //  factor to the final results, and to generate zero-knowledge proofs that this message
        //  was created honestly."
        let (r4, r5, r6, r7) = (random(), random(), random(), random());
        // "Compute `Pa = g3r4` and `Qa = g1r4 g2x`"
        let Pa = g3.modpow(&r4, MOD);
        let Qa = (&g1.modpow(&r4, MOD) * &g2.modpow(&x, MOD)).mod_floor(MOD);
        // "Generate a zero-knowledge proof that Pa and Qa were created according to the protocol
        //  by setting `cP = SHA256(6, g3r5, g1r5 g2r6)`, ..."
        let cP = hash_2_mpi(
            6,
            &g3.modpow(&r5, MOD),
            &(&g1.modpow(&r5, MOD) * &g2.modpow(&r6, MOD)).mod_floor(MOD),
        );
        // "... `D5 = r5 - r4 cP mod q`, and ..."
        let D5 = (&r5 - r4 * &cP).mod_floor(q);
        // "... `D6 = r6 - x cP mod q`."
        let D6 = (&r6 - x * &cP).mod_floor(q);
        // "Compute `Ra = (Qa / Qb) a3`"
        let QadivQb = (&Qa * OTR::mod_inv(&Qb, MOD)).mod_floor(MOD);
        let Ra = QadivQb.modpow(&a3, MOD);
        // "Generate a zero-knowledge proof that Ra was created according to the protocol by
        //  setting `cR = SHA256(7, g1r7, (Qa / Qb)r7)` and ..."
        let cR = hash_2_mpi(7, &g1.modpow(&r7, MOD), &QadivQb.modpow(&r7, MOD));
        // "... `D7 = r7 - a3 cR mod q`."
        let D7 = (&r7 - &a3 * &cR).mod_floor(q);
        /*
           Store the values of g3b, (Pa / Pb), (Qa / Qb) and a3 for use later in the protocol.
           Send Bob a type 4 TLV (SMP message 3) containing Pa, Qa, cP, D5, D6, Ra, cR and D7 in that order.
        */
        let tlv = TLV(
            TLV_TYPE_SMP_MESSAGE_3,
            OTREncoder::new()
                .write_mpi_sequence(&[&Pa, &Qa, &cP, &D5, &D6, &Ra, &cR, &D7])
                .to_vec(),
        );
        let PadivPb = (&Pa * OTR::mod_inv(&Pb, MOD)).mod_floor(MOD);
        // "Set smpstate to SMPSTATE_EXPECT4."
        self.state = SMPState::Expect4 {
            a3,
            g3b,
            PadivPb,
            QadivQb,
        };
        Ok(tlv)
    }

    fn handleMessage3(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_3);
        let g3a: BigUint;
        let g2: BigUint;
        let g3: BigUint;
        let b3: BigUint;
        let Pb: BigUint;
        let Qb: BigUint;
        if let SMPState::Expect3 {
            g3a: _g3a,
            g2: _g2,
            g3: _g3,
            b3: _b3,
            Pb: _pb,
            Qb: _qb,
        } = &self.state
        {
            // "If smpstate is SMPSTATE_EXPECT3:"
            g3a = _g3a.to_owned();
            g2 = _g2.to_owned();
            g3 = _g3.to_owned();
            b3 = _b3.to_owned();
            Pb = _pb.to_owned();
            Qb = _qb.to_owned();
        } else {
            return Err(OTRError::ProtocolViolation(
                "SMP message type 3 was expected.",
            ));
        }

        // "SMP message 3 is Alice's final message in the SMP exchange. It has the last of the information required by Bob to determine if x = y. It contains the following mpi values:
        //  Pa, Qa
        //      These values are used in the final comparison to determine if Alice and Bob share the same secret.
        //  cP, D5, D6
        //      A zero-knowledge proof that Pa and Qa were created according to the protcol given above.
        //  Ra
        //      This value is used in the final comparison to determine if Alice and Bob share the same secret.
        //  cR, D7
        //      A zero-knowledge proof that Ra was created according to the protcol given above."
        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 8 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values in SMP message 3 TLV",
            ));
        }
        let D7 = mpis.pop().unwrap();
        let cR = mpis.pop().unwrap();
        let Ra = mpis.pop().unwrap();
        let D6 = mpis.pop().unwrap();
        let D5 = mpis.pop().unwrap();
        let cP = mpis.pop().unwrap();
        let Qa = mpis.pop().unwrap();
        let Pa = mpis.pop().unwrap();
        assert_eq!(mpis.len(), 0);

        // Verify Alice's zero-knowledge proofs for Pa, Qa and Ra:

        // Check that Pa, Qa and Ra are >= 2 and <= modulus-2.
        DH::verify_public_key(&Pa).map_err(OTRError::CryptographicViolation)?;
        DH::verify_public_key(&Qa).map_err(OTRError::CryptographicViolation)?;
        DH::verify_public_key(&Ra).map_err(OTRError::CryptographicViolation)?;

        let MOD = DH::modulus();
        let q = DH::q();
        let g1 = DH::generator();

        // Check that cP = SHA256(6, g3^D5 Pa^cP, g1^D5 g2^D6 Qa^cP).
        let expected_cP = hash_2_mpi(
            6,
            &(g3.modpow(&D5, MOD) * Pa.modpow(&cP, MOD)).mod_floor(MOD),
            &(g1.modpow(&D5, MOD) * g2.modpow(&D6, MOD) * Qa.modpow(&cP, MOD)).mod_floor(MOD),
        );
        DH::verify(&cP, &expected_cP).map_err(OTRError::CryptographicViolation)?;

        let QadivQb = (&Qa * &OTR::mod_inv(&Qb, MOD)).mod_floor(MOD);
        // Check that cR = SHA256(7, g1**D7 g3a**cR, (Qa / Qb)**D7 Ra**cR).
        let expected_cR = hash_2_mpi(
            7,
            &(&g1.modpow(&D7, MOD) * &g3a.modpow(&cR, MOD)).mod_floor(MOD),
            &(&QadivQb.modpow(&D7, MOD) * &Ra.modpow(&cR, MOD)).mod_floor(MOD),
        );
        DH::verify(&cR, &expected_cR).map_err(OTRError::CryptographicViolation)?;

        // Pick a random exponent r7. This will be used to generate Bob's final zero-knowledge proof
        // that this message was created honestly.
        let r7 = random();

        // Compute Rb = (Qa / Qb) b3
        let Rb = &QadivQb.modpow(&b3, MOD);

        // Generate a zero-knowledge proof that Rb was created according to the protocol by setting
        // cR = SHA256(8, g1r7, (Qa / Qb)r7) and D7 = r7 - b3 cR mod q.
        let cR = hash_2_mpi(8, &g1.modpow(&r7, MOD), &QadivQb.modpow(&r7, MOD));
        let D7 = (&r7 - &b3 * &cR).mod_floor(q);

        // Check whether the protocol was successful:
        // Compute Rab = Rab3.
        let Rab = Ra.modpow(&b3, MOD);
        // Determine if x = y by checking the equivalent condition that (Pa / Pb) = Rab.
        let PadivPb = (&Pa * OTR::mod_inv(&Pb, MOD)).mod_floor(MOD);
        // FIXME use DH::verify for other expected_xx comparisons.
        DH::verify(&PadivPb, &Rab).map_err(OTRError::CryptographicViolation)?;
        // TODO need to signal successful finishing protocol with positive/negative result. Also, always send TLV to Alice, even if failure?
        // Send Alice a type 5 TLV (SMP message 4) containing Rb, cR and D7 in that order.
        let tlv = OTREncoder::new()
            .write_mpi_sequence(&[Rb, &cR, &D7])
            .to_vec();
        // Set smpstate to SMPSTATE_EXPECT1, as no more messages are expected from Alice.
        self.state = SMPState::Expect1;
        Err(OTRError::SMPSuccess(Some(TLV(TLV_TYPE_SMP_MESSAGE_4, tlv))))
    }

    /// handleMessage4 handles the 4th SMP message.
    ///
    /// SMP message 4 is Bob's final message in the SMP exchange. It has the last of the information
    /// required by Alice to determine if x = y.
    fn handleMessage4(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_4);
        let g3b: BigUint;
        let PadivPb: BigUint;
        let QadivQb: BigUint;
        let a3: BigUint;
        if let SMPState::Expect4 {
            g3b: _g3b,
            PadivPb: _padivpb,
            QadivQb: _qadivqb,
            a3: _a3,
        } = &self.state
        {
            g3b = _g3b.to_owned();
            PadivPb = _padivpb.to_owned();
            QadivQb = _qadivqb.to_owned();
            a3 = _a3.to_owned();
        } else {
            return Err(OTRError::ProtocolViolation(
                "SMP message type 4 was expected.",
            ));
        }

        let mut mpis = OTRDecoder::new(&tlv.1).read_mpi_sequence()?;
        if mpis.len() != 3 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values in SMP message 4 TLV",
            ));
        }

        // It contains the following mpi values:
        // Rb
        //    This value is used in the final comparison to determine if Alice and Bob share the same secret.
        // cR, D7
        //    A zero-knowledge proof that Rb was created according to the protcol given above.
        let D7 = mpis.pop().unwrap();
        let cR = mpis.pop().unwrap();
        let Rb = mpis.pop().unwrap();
        assert_eq!(mpis.len(), 0);

        let MOD = DH::modulus();
        let g1 = DH::generator();

        // Verify Bob's zero-knowledge proof for Rb:
        // Check that Rb is >= 2 and <= modulus-2.
        DH::verify_public_key(&Rb).map_err(OTRError::CryptographicViolation)?;

        // Check that cR = SHA256(8, g1D7 g3bcR, (Qa / Qb)D7 RbcR).
        let expected_cR = hash_2_mpi(
            8,
            &(g1.modpow(&D7, MOD) * g3b.modpow(&cR, MOD)).mod_floor(MOD),
            &(&QadivQb.modpow(&D7, MOD) * (&Rb.modpow(&cR, MOD))).mod_floor(MOD),
        );
        DH::verify(&expected_cR, &cR).map_err(OTRError::CryptographicViolation)?;

        // Compute Rab = Rba3.
        let Rab = Rb.modpow(&a3, MOD);
        // Determine if x = y by checking the equivalent condition that (Pa / Pb) = Rab.
        DH::verify(&PadivPb, &Rab).map_err(OTRError::CryptographicViolation)?;
        self.state = SMPState::Expect1;
        Err(OTRError::SMPSuccess(None))
    }

    /// Indiscriminately reset SMP state to StateExpect1. Returns TLV with SMP Abort-payload.
    pub fn abort(&mut self) -> TLV {
        self.state = SMPState::Expect1;
        self.status = SMPStatus::Aborted(Vec::from("Aborted by user"));
        TLV(TLV_TYPE_SMP_ABORT, Vec::new())
    }
}

#[allow(non_snake_case)]
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
        Pb: BigUint,
        Qb: BigUint,
    },
    Expect4 {
        g3b: BigUint,
        PadivPb: BigUint,
        QadivQb: BigUint,
        a3: BigUint,
    },
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum SMPStatus {
    /// Initial status: no SMP session, no activity.
    Initial,
    /// SMP currently in progress, i.e. awaiting next message.
    InProgress,
    /// SMP deliberately aborted, either by local user action, or through received abort-TLV.
    Aborted(Vec<u8>),
    /// SMP process succeeded.
    Success,
}

const SMP_VERSION: u8 = 1;

fn compute_secret(
    initiator: &Fingerprint,
    responder: &Fingerprint,
    ssid: &SSID,
    secret: &[u8],
) -> BigUint {
    let mut buffer = Vec::<u8>::new();
    buffer.push(SMP_VERSION);
    buffer.extend_from_slice(initiator);
    buffer.extend_from_slice(responder);
    buffer.extend_from_slice(ssid);
    buffer.extend_from_slice(secret);
    BigUint::from_bytes_be(&SHA256::digest(&buffer))
}

fn random() -> BigUint {
    let mut v = [0u8; 192];
    (&*RAND)
        .fill(&mut v)
        .expect("Failed to produce random bytes for random big unsigned integer value.");
    BigUint::from_bytes_be(&v).mod_floor(DH::modulus())
}

fn hash_1_mpi(version: u8, mpi1: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&SHA256::digest_with_prefix(
        version,
        &OTREncoder::new().write_mpi(mpi1).to_vec(),
    ))
}

fn hash_2_mpi(version: u8, mpi1: &BigUint, mpi2: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&SHA256::digest_2_with_prefix(
        version,
        &OTREncoder::new().write_mpi(mpi1).to_vec(),
        &OTREncoder::new().write_mpi(mpi2).to_vec(),
    ))
}

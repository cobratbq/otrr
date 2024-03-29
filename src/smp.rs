// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;
use num_integer::Integer;
use ring::rand::SecureRandom;
use zeroize::Zeroize;

use crate::{
    crypto::{dh, otr, sha256, CryptoError},
    encoding::{OTRDecoder, OTREncoder, FINGERPRINT_LEN},
    utils, Host, OTRError, TLVType, SSID, TLV,
};

pub fn is_smp_tlv(tlv: &TLV) -> bool {
    tlv.0 == TLV_TYPE_SMP_MESSAGE_1
        || tlv.0 == TLV_TYPE_SMP_MESSAGE_1Q
        || tlv.0 == TLV_TYPE_SMP_MESSAGE_2
        || tlv.0 == TLV_TYPE_SMP_MESSAGE_3
        || tlv.0 == TLV_TYPE_SMP_MESSAGE_4
        || tlv.0 == TLV_TYPE_SMP_ABORT
}

/// TLV for initiating SMP
const TLV_TYPE_SMP_MESSAGE_1: TLVType = 2;
const TLV_TYPE_SMP_MESSAGE_2: TLVType = 3;
const TLV_TYPE_SMP_MESSAGE_3: TLVType = 4;
const TLV_TYPE_SMP_MESSAGE_4: TLVType = 5;
const TLV_TYPE_SMP_ABORT: TLVType = 6;
/// TLV similar to message 1 but includes a user-specified question (null-terminated) in the payload.
const TLV_TYPE_SMP_MESSAGE_1Q: TLVType = 7;
pub struct SMPContext {
    status: SMPStatus,
    state: SMPState,
    ssid: SSID,
    their_fingerprint: [u8; FINGERPRINT_LEN],
    host: Rc<dyn Host>,
}

impl Drop for SMPContext {
    fn drop(&mut self) {
        self.ssid.fill(0);
    }
}

// TODO improve on the extra addition of `q` that is now used to avoid negative values? (All D# values)
#[allow(non_snake_case)]
impl SMPContext {
    pub fn new(host: Rc<dyn Host>, ssid: SSID, their_fingerprint: [u8; FINGERPRINT_LEN]) -> Self {
        Self {
            status: SMPStatus::Initial,
            state: SMPState::Expect1,
            host,
            ssid,
            their_fingerprint,
        }
    }

    pub fn status(&self) -> SMPStatus {
        self.status.clone()
    }

    pub fn ssid(&self) -> SSID {
        self.ssid
    }

    /// Initiate SMP. Produces `SMPError::AlreadyInProgress` if SMP is in progress.
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
            &otr::fingerprint(
                &self
                    .host
                    .keypair()
                    .expect("BUG: in OTR3 SMP the (legacy) DSA keypair must be available.")
                    .public_key(),
            ),
            &self.their_fingerprint,
            &self.ssid,
            secret,
        );

        let MOD = dh::modulus();
        let q = dh::q();
        let g1 = dh::generator();

        let (a2, a3) = (random(), random());
        let g2a = g1.modpow(&a2, MOD);
        let g3a = g1.modpow(&a3, MOD);

        let (r2, r3) = (random(), random());
        let c2 = hash_1_mpi(1, &g1.modpow(&r2, MOD));
        let D2 = (&r2 + q - (&a2 * &c2).mod_floor(q)).mod_floor(q);
        let c3 = hash_1_mpi(2, &g1.modpow(&r3, MOD));
        let D3 = (&r3 + q - (&a3 * &c3).mod_floor(q)).mod_floor(q);

        let mut encoder = OTREncoder::new();
        let typ: TLVType = if question.is_empty() {
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
        match self.dispatch(tlv) {
            Ok(tlv) => Some(tlv),
            Err(OTRError::SMPSuccess(response)) => {
                self.state = SMPState::Expect1;
                self.status = SMPStatus::Completed;
                response
            }
            Err(OTRError::SMPFailed(response)) => {
                self.state = SMPState::Expect1;
                self.status = SMPStatus::Aborted(Vec::from("Secret failed verification."));
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
                self.status = SMPStatus::Aborted(Vec::from(format!("Protocol violation: {msg}")));
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
            tlv @ TLV(tlvtype, _)
                if *tlvtype == TLV_TYPE_SMP_MESSAGE_1 || *tlvtype == TLV_TYPE_SMP_MESSAGE_1Q =>
            {
                self.handle_message_1(tlv)
            }
            tlv @ TLV(tlvtype, _) if *tlvtype == TLV_TYPE_SMP_MESSAGE_2 => {
                self.handle_message_2(tlv)
            }
            tlv @ TLV(tlvtype, _) if *tlvtype == TLV_TYPE_SMP_MESSAGE_3 => {
                self.handle_message_3(tlv)
            }
            tlv @ TLV(tlvtype, _) if *tlvtype == TLV_TYPE_SMP_MESSAGE_4 => {
                self.handle_message_4(tlv)
            }
            TLV(tlvtype, _) if *tlvtype == TLV_TYPE_SMP_ABORT => Err(OTRError::SMPAborted(false)),
            _ => panic!("BUG: incorrect TLV type: {}", tlv.0),
        }
    }

    #[allow(clippy::similar_names)]
    fn handle_message_1(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
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
            decoder.read_bytes_null_terminated()
        } else {
            Vec::new()
        };
        let mut mpis = decoder.read_mpi_sequence()?;
        if mpis.len() != 6 {
            return Err(OTRError::ProtocolViolation(
                "Unexpected number of MPI values in SMP message 1 TLV",
            ));
        }
        decoder.done()?;
        let D3 = mpis.pop().unwrap();
        let c3 = mpis.pop().unwrap();
        let g3a = mpis.pop().unwrap();
        let D2 = mpis.pop().unwrap();
        let c2 = mpis.pop().unwrap();
        let g2a = mpis.pop().unwrap();
        assert!(mpis.is_empty());

        dh::verify_exponent(&D2).map_err(OTRError::CryptographicViolation)?;
        dh::verify_exponent(&D3).map_err(OTRError::CryptographicViolation)?;

        // "Verify Alice's zero-knowledge proofs for g2a and g3a:"
        // "1. Check that both g2a and g3a are >= 2 and <= modulus-2."
        dh::verify_public_key(&g2a).map_err(OTRError::CryptographicViolation)?;
        dh::verify_public_key(&g3a).map_err(OTRError::CryptographicViolation)?;

        let MOD = dh::modulus();
        let q = dh::q();
        let g1 = dh::generator();

        // "2. Check that c2 = SHA256(1, g1D2 g2ac2)."
        let expected_c2 = hash_1_mpi(
            1,
            &(g1.modpow(&D2, MOD) * g2a.modpow(&c2, MOD)).mod_floor(MOD),
        );
        dh::verify(&expected_c2, &c2).map_err(OTRError::CryptographicViolation)?;

        // "3. Check that c3 = SHA256(2, g1D3 g3ac3)."
        let expected_c3 = hash_1_mpi(
            2,
            &(g1.modpow(&D3, MOD) * g3a.modpow(&c3, MOD)).mod_floor(MOD),
        );
        dh::verify(&expected_c3, &c3).map_err(OTRError::CryptographicViolation)?;

        // "Create a type 3 TLV (SMP message 2) and send it to Alice: "
        // "1. Determine Bob's secret input y, which is to be compared to Alice's secret x."
        let answer = self.host.query_smp_secret(&received_question);
        if answer.is_none() {
            // Abort SMP because user has cancelled query for their secret.
            return Err(OTRError::SMPAborted(true));
        }
        let y = compute_secret(
            &self.their_fingerprint,
            &otr::fingerprint(
                &self
                    .host
                    .keypair()
                    .expect("BUG: in OTR3 SMP the (legacy) DSA keypair must be available.")
                    .public_key(),
            ),
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
        let D2 = (&r2 + q - (&b2 * &c2).mod_floor(q)).mod_floor(q);
        // "6. Generate a zero-knowledge proof that the exponent b3 is known by setting
        // `c3 = SHA256(4, g1r3)` and `D3 = r3 - b3 c3 mod q`."
        let c3 = hash_1_mpi(4, &g1.modpow(&r3, MOD));
        let D3 = (&r3 + q - (&b3 * &c3).mod_floor(q)).mod_floor(q);
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
        let D5 = (&r5 + q - (&r4 * &cP).mod_floor(q)).mod_floor(q);
        let D6 = (&r6 + q - (&y * &cP).mod_floor(q)).mod_floor(q);

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

    fn handle_message_2(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_2);
        // "SMP message 2 is sent by Bob to complete the DH exchange to determine the new
        //  generators, `g2` and `g3`. It also begins the construction of the values used in the final
        //  comparison of the protocol."
        let x: BigUint;
        let a2: BigUint;
        let a3: BigUint;
        if let SMPState::Expect2 {
            x: x_,
            a2: a2_,
            a3: a3_,
        } = &self.state
        {
            x = x_.clone();
            a2 = a2_.clone();
            a3 = a3_.clone();
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
        assert!(mpis.is_empty());

        dh::verify_exponent(&D2).map_err(OTRError::CryptographicViolation)?;
        dh::verify_exponent(&D3).map_err(OTRError::CryptographicViolation)?;
        dh::verify_exponent(&D5).map_err(OTRError::CryptographicViolation)?;
        dh::verify_exponent(&D6).map_err(OTRError::CryptographicViolation)?;

        // "Check that `g2b`, `g3b`, `Pb` and `Qb` are `>= 2 and <= modulus-2`."
        dh::verify_public_key(&g2b).map_err(OTRError::CryptographicViolation)?;
        dh::verify_public_key(&g3b).map_err(OTRError::CryptographicViolation)?;
        dh::verify_public_key(&Pb).map_err(OTRError::CryptographicViolation)?;
        dh::verify_public_key(&Qb).map_err(OTRError::CryptographicViolation)?;

        let MOD = dh::modulus();
        let q = dh::q();
        let g1 = dh::generator();

        // "Check that `c2 = SHA256(3, g1D2 g2bc2)`."
        let c2_expected = hash_1_mpi(
            3,
            &(&g1.modpow(&D2, MOD) * &g2b.modpow(&c2, MOD)).mod_floor(MOD),
        );
        dh::verify(&c2_expected, &c2).map_err(OTRError::CryptographicViolation)?;

        // "Check that `c3 = SHA256(4, g1D3 g3bc3)`."
        let c3_expected = hash_1_mpi(
            4,
            &(&g1.modpow(&D3, MOD) * &g3b.modpow(&c3, MOD)).mod_floor(MOD),
        );
        dh::verify(&c3_expected, &c3).map_err(OTRError::CryptographicViolation)?;

        // "Compute `g2 = g2ba2` and `g3 = g3ba3`"
        let g2 = g2b.modpow(&a2, MOD);
        let g3 = g3b.modpow(&a3, MOD);

        // "Check that `cP = SHA256(5, g3D5 PbcP, g1D5 g2D6 QbcP)`."
        let cP_expected = hash_2_mpi(
            5,
            &(&g3.modpow(&D5, MOD) * &Pb.modpow(&cP, MOD)).mod_floor(MOD),
            &(&g1.modpow(&D5, MOD) * &g2.modpow(&D6, MOD) * &Qb.modpow(&cP, MOD)).mod_floor(MOD),
        );
        dh::verify(&cP_expected, &cP).map_err(OTRError::CryptographicViolation)?;

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
        let D5 = (&r5 + q - (&r4 * &cP).mod_floor(q)).mod_floor(q);
        // "... `D6 = r6 - x cP mod q`."
        let D6 = (&r6 + q - (&x * &cP).mod_floor(q)).mod_floor(q);
        // "Compute `Ra = (Qa / Qb) a3`"
        let QadivQb = (&Qa * otr::mod_inv(&Qb, MOD)).mod_floor(MOD);
        let Ra = QadivQb.modpow(&a3, MOD);
        // "Generate a zero-knowledge proof that Ra was created according to the protocol by
        //  setting `cR = SHA256(7, g1r7, (Qa / Qb)r7)` and ..."
        let cR = hash_2_mpi(7, &g1.modpow(&r7, MOD), &QadivQb.modpow(&r7, MOD));
        // "... `D7 = r7 - a3 cR mod q`."
        let D7 = (&r7 + q - (&a3 * &cR).mod_floor(q)).mod_floor(q);
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
        let PadivPb = (&Pa * otr::mod_inv(&Pb, MOD)).mod_floor(MOD);
        // "Set smpstate to SMPSTATE_EXPECT4."
        self.state = SMPState::Expect4 {
            a3,
            g3b,
            PadivPb,
            QadivQb,
        };
        Ok(tlv)
    }

    fn handle_message_3(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_3);
        let g3a: BigUint;
        let g2: BigUint;
        let g3: BigUint;
        let b3: BigUint;
        let Pb: BigUint;
        let Qb: BigUint;
        if let SMPState::Expect3 {
            g3a: g3a_,
            g2: g2_,
            g3: g3_,
            b3: b3_,
            Pb: pb_,
            Qb: qb_,
        } = &self.state
        {
            // "If smpstate is SMPSTATE_EXPECT3:"
            g3a = g3a_.clone();
            g2 = g2_.clone();
            g3 = g3_.clone();
            b3 = b3_.clone();
            Pb = pb_.clone();
            Qb = qb_.clone();
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
        assert!(mpis.is_empty());

        dh::verify_exponent(&D5).map_err(OTRError::CryptographicViolation)?;
        dh::verify_exponent(&D6).map_err(OTRError::CryptographicViolation)?;
        dh::verify_exponent(&D7).map_err(OTRError::CryptographicViolation)?;

        // Verify Alice's zero-knowledge proofs for Pa, Qa and Ra:

        // Check that Pa, Qa and Ra are >= 2 and <= modulus-2.
        dh::verify_public_key(&Pa).map_err(OTRError::CryptographicViolation)?;
        dh::verify_public_key(&Qa).map_err(OTRError::CryptographicViolation)?;
        dh::verify_public_key(&Ra).map_err(OTRError::CryptographicViolation)?;

        let MOD = dh::modulus();
        let q = dh::q();
        let g1 = dh::generator();

        // Check that cP = SHA256(6, g3^D5 Pa^cP, g1^D5 g2^D6 Qa^cP).
        let expected_cP = hash_2_mpi(
            6,
            &(g3.modpow(&D5, MOD) * Pa.modpow(&cP, MOD)).mod_floor(MOD),
            &(g1.modpow(&D5, MOD) * g2.modpow(&D6, MOD) * Qa.modpow(&cP, MOD)).mod_floor(MOD),
        );
        dh::verify(&cP, &expected_cP).map_err(OTRError::CryptographicViolation)?;

        let QadivQb = (&Qa * &otr::mod_inv(&Qb, MOD)).mod_floor(MOD);
        // Check that cR = SHA256(7, g1**D7 g3a**cR, (Qa / Qb)**D7 Ra**cR).
        let expected_cR = hash_2_mpi(
            7,
            &(&g1.modpow(&D7, MOD) * &g3a.modpow(&cR, MOD)).mod_floor(MOD),
            &(&QadivQb.modpow(&D7, MOD) * &Ra.modpow(&cR, MOD)).mod_floor(MOD),
        );
        dh::verify(&cR, &expected_cR).map_err(OTRError::CryptographicViolation)?;

        // Pick a random exponent r7. This will be used to generate Bob's final zero-knowledge proof
        // that this message was created honestly.
        let r7 = random();

        // Compute Rb = (Qa / Qb) b3
        let Rb = &QadivQb.modpow(&b3, MOD);

        // Generate a zero-knowledge proof that Rb was created according to the protocol by setting
        // cR = SHA256(8, g1r7, (Qa / Qb)r7) and D7 = r7 - b3 cR mod q.
        let cR = hash_2_mpi(8, &g1.modpow(&r7, MOD), &QadivQb.modpow(&r7, MOD));
        let D7 = (&r7 + q - (&b3 * &cR).mod_floor(q)).mod_floor(q);

        // Check whether the protocol was successful:
        // Compute Rab = Rab3.
        let Rab = Ra.modpow(&b3, MOD);
        // Determine if x = y by checking the equivalent condition that (Pa / Pb) = Rab.
        let PadivPb = (&Pa * otr::mod_inv(&Pb, MOD)).mod_floor(MOD);

        // Send Alice a type 5 TLV (SMP message 4) containing Rb, cR and D7 in that order.
        let tlv = TLV(
            TLV_TYPE_SMP_MESSAGE_4,
            OTREncoder::new()
                .write_mpi_sequence(&[Rb, &cR, &D7])
                .to_vec(),
        );
        match dh::verify(&PadivPb, &Rab) {
            Ok(()) => Err(OTRError::SMPSuccess(Some(tlv))),
            Err(CryptoError::VerificationFailure(_)) => Err(OTRError::SMPFailed(Some(tlv))),
        }
    }

    /// handleMessage4 handles the 4th SMP message.
    ///
    /// SMP message 4 is Bob's final message in the SMP exchange. It has the last of the information
    /// required by Alice to determine if x = y.
    fn handle_message_4(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_TYPE_SMP_MESSAGE_4);
        let g3b: BigUint;
        let PadivPb: BigUint;
        let QadivQb: BigUint;
        let a3: BigUint;
        if let SMPState::Expect4 {
            g3b: g3b_,
            PadivPb: padivpb_,
            QadivQb: qadivqb_,
            a3: a3_,
        } = &self.state
        {
            g3b = g3b_.clone();
            PadivPb = padivpb_.clone();
            QadivQb = qadivqb_.clone();
            a3 = a3_.clone();
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
        assert!(mpis.is_empty());

        dh::verify_exponent(&D7).map_err(OTRError::CryptographicViolation)?;

        let MOD = dh::modulus();
        let g1 = dh::generator();

        // Verify Bob's zero-knowledge proof for Rb:
        // Check that Rb is >= 2 and <= modulus-2.
        dh::verify_public_key(&Rb).map_err(OTRError::CryptographicViolation)?;

        // Check that cR = SHA256(8, g1D7 g3bcR, (Qa / Qb)D7 RbcR).
        let expected_cR = hash_2_mpi(
            8,
            &(g1.modpow(&D7, MOD) * g3b.modpow(&cR, MOD)).mod_floor(MOD),
            &(&QadivQb.modpow(&D7, MOD) * (&Rb.modpow(&cR, MOD))).mod_floor(MOD),
        );
        dh::verify(&expected_cR, &cR).map_err(OTRError::CryptographicViolation)?;

        // Compute Rab = Rba3.
        let Rab = Rb.modpow(&a3, MOD);
        // Determine if x = y by checking the equivalent condition that (Pa / Pb) = Rab.
        match dh::verify(&PadivPb, &Rab) {
            Ok(()) => Err(OTRError::SMPSuccess(None)),
            Err(CryptoError::VerificationFailure(_)) => Err(OTRError::SMPFailed(None)),
        }
    }

    /// Indiscriminately reset SMP state to `StateExpect1`. Returns TLV with SMP Abort-payload.
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

impl Drop for SMPState {
    fn drop(&mut self) {
        match self {
            Self::Expect1 => {}
            Self::Expect2 { x, a2, a3 } => {
                x.zeroize();
                a2.zeroize();
                a3.zeroize();
            }
            Self::Expect3 {
                g3a,
                g2,
                g3,
                b3,
                Pb,
                Qb,
            } => {
                g3a.zeroize();
                g2.zeroize();
                g3.zeroize();
                b3.zeroize();
                Pb.zeroize();
                Qb.zeroize();
            }
            Self::Expect4 {
                g3b,
                PadivPb,
                QadivQb,
                a3,
            } => {
                g3b.zeroize();
                PadivPb.zeroize();
                QadivQb.zeroize();
                a3.zeroize();
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SMPStatus {
    /// Initial status: no SMP session, no activity.
    Initial,
    /// SMP currently in progress, i.e. awaiting next message.
    InProgress,
    /// SMP deliberately aborted, either by local user action, or through received abort-TLV.
    Aborted(Vec<u8>),
    /// SMP process completed.
    Completed,
}

const SMP_VERSION: u8 = 1;

#[allow(clippy::trivially_copy_pass_by_ref)]
fn compute_secret(
    initiator: &[u8; FINGERPRINT_LEN],
    responder: &[u8; FINGERPRINT_LEN],
    ssid: &SSID,
    secret: &[u8],
) -> BigUint {
    // allocate Vec with precise capacity to avoid reallocation/relocation
    let mut buffer =
        Vec::<u8>::with_capacity(1 + initiator.len() + responder.len() + ssid.len() + secret.len());
    buffer.push(SMP_VERSION);
    buffer.extend_from_slice(initiator);
    buffer.extend_from_slice(responder);
    buffer.extend_from_slice(ssid);
    buffer.extend_from_slice(secret);
    let value = BigUint::from_bytes_be(&sha256::digest(&buffer));
    buffer.zeroize();
    value
}

fn random() -> BigUint {
    let mut v = [0u8; 192];
    (*utils::random::RANDOM)
        .fill(&mut v)
        .expect("Failed to produce random bytes for random big unsigned integer value.");
    BigUint::from_bytes_be(&v).mod_floor(dh::q())
}

fn hash_1_mpi(version: u8, mpi1: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&sha256::digest_with_prefix(
        version,
        &OTREncoder::new().write_mpi(mpi1).to_vec(),
    ))
}

fn hash_2_mpi(version: u8, mpi1: &BigUint, mpi2: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&sha256::digest_2_with_prefix(
        version,
        &OTREncoder::new().write_mpi(mpi1).to_vec(),
        &OTREncoder::new().write_mpi(mpi2).to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use crate::{
        crypto::{dsa, otr},
        smp::SMPStatus,
        Host, SSID,
    };

    use super::SMPContext;

    #[test]
    fn test_my_first_smp() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret: Vec<u8> = Vec::from("World");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> = Rc::new(TestHost(keypair_a, question.clone(), secret.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, question.clone(), secret.clone()));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // Alice: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = alice.initiate(&secret, &question).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());

        // Bob: respond to init
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: finish on Alice's reply
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Completed, bob.status());

        // Alice: finish on Bob's reply
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Completed, bob.status());
        assert!(alice.handle(&reply).is_none());
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::Completed, bob.status());
    }

    #[test]
    fn test_successful_smp_symmetric() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret: Vec<u8> = Vec::from("World");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> = Rc::new(TestHost(keypair_a, question.clone(), secret.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, question.clone(), secret.clone()));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // Bob: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.initiate(&secret, &question).unwrap();
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Follow up on Alice
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        assert!(bob.handle(&reply).is_none());
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::Completed, bob.status());
    }

    #[test]
    fn test_successful_smp_no_question() {
        let secret: Vec<u8> = Vec::from("A different, longer secret to be verified");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> = Rc::new(TestHost(keypair_a, Vec::new(), secret.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, Vec::new(), secret.clone()));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // Bob: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.initiate(&secret, &[]).unwrap();
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Follow up on Alice
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        assert!(bob.handle(&reply).is_none());
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::Completed, bob.status());
    }

    #[test]
    fn test_repeated_successes() {
        let secret: Vec<u8> = Vec::from("A different, longer secret to be verified");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> = Rc::new(TestHost(keypair_a, Vec::new(), secret.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, Vec::new(), secret.clone()));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // Bob: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.initiate(&secret, &[]).unwrap();
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Follow up on Alice
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        assert!(bob.handle(&reply).is_none());
        assert_eq!(SMPStatus::Completed, alice.status());
        assert_eq!(SMPStatus::Completed, bob.status());

        for i in 1..3 {
            println!("iteration {:}", i + 1);

            // Bob: initiate SMP
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::Completed, bob.status());
            let reply = bob.initiate(&secret, &[]).unwrap();
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Alice: Follow up on Bob
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = alice.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Bob: Follow up on Alice
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = bob.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Alice: Follow up on Bob
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = alice.handle(&reply).unwrap();
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Bob: Finish on Alice's reply
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            assert!(bob.handle(&reply).is_none());
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::Completed, bob.status());
        }
    }

    #[test]
    fn test_failing_smp() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret_alice: Vec<u8> = Vec::from("Alice's secret");
        let secret_bob: Vec<u8> = Vec::from("Bob's secret");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> =
            Rc::new(TestHost(keypair_a, question.clone(), secret_alice.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, question.clone(), secret_bob));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // Alice: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = alice.initiate(&secret_alice, &question).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());

        // Bob: respond to init
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
        assert!(alice.handle(&reply).is_none());
        assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
    }

    #[test]
    fn test_failing_smp_symmetric() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret_alice: Vec<u8> = Vec::from("Alice's secret");
        let secret_bob: Vec<u8> = Vec::from("Bob's secret");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> = Rc::new(TestHost(keypair_a, question.clone(), secret_alice));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> =
            Rc::new(TestHost(keypair_b, question.clone(), secret_bob.clone()));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // Bob: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.initiate(&secret_bob, &question).unwrap();
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Follow up on Alice
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
        assert_eq!(SMPStatus::InProgress, bob.status());
        assert!(bob.handle(&reply).is_none());
        assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
    }

    #[test]
    fn test_bad_ssid() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret_alice: Vec<u8> = Vec::from("Alice's secret");
        let secret_bob: Vec<u8> = Vec::from("Bob's secret");

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> =
            Rc::new(TestHost(keypair_a, question.clone(), secret_alice.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, question.clone(), secret_bob));

        let mut alice =
            SMPContext::new(Rc::clone(&host_a), [1, 1, 1, 1, 1, 1, 1, 1], fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), [9, 9, 9, 9, 9, 9, 9, 9], fingerprint_a);

        // Alice: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = alice.initiate(&secret_alice, &question).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());

        // Bob: respond to init
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
        assert!(alice.handle(&reply).is_none());
        assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
    }

    #[test]
    fn test_false_fingerprints() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret_alice: Vec<u8> = Vec::from("Alice's secret");
        let secret_bob: Vec<u8> = Vec::from("Bob's secret");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let false_fingerprint = otr::fingerprint(&dsa::Keypair::generate().public_key());

        let keypair_a = dsa::Keypair::generate();
        let host_a: Rc<dyn Host> =
            Rc::new(TestHost(keypair_a, question.clone(), secret_alice.clone()));
        let keypair_b = dsa::Keypair::generate();
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, question.clone(), secret_bob));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, false_fingerprint);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, false_fingerprint);

        // Alice: initiate SMP
        assert_eq!(SMPStatus::Initial, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = alice.initiate(&secret_alice, &question).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());

        // Bob: respond to init
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::Initial, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = alice.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());

        // Bob: Finish on Alice's reply
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert_eq!(SMPStatus::InProgress, bob.status());
        let reply = bob.handle(&reply).unwrap();
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));

        // Alice: Follow up on Bob
        assert_eq!(SMPStatus::InProgress, alice.status());
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
        assert!(alice.handle(&reply).is_none());
        assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
        assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
    }

    #[test]
    fn test_success_after_fail() {
        let question: Vec<u8> = Vec::from("Hello");
        let secret: Vec<u8> = Vec::from("The shared secret answer!");
        let ssid: SSID = [1, 2, 3, 4, 5, 6, 7, 8];

        let keypair_a = dsa::Keypair::generate();
        let fingerprint_a = otr::fingerprint(&keypair_a.public_key());
        let host_a: Rc<dyn Host> = Rc::new(TestHost(keypair_a, question.clone(), secret.clone()));
        let keypair_b = dsa::Keypair::generate();
        let fingerprint_b = otr::fingerprint(&keypair_b.public_key());
        let host_b: Rc<dyn Host> = Rc::new(TestHost(keypair_b, question.clone(), secret.clone()));

        let mut alice = SMPContext::new(Rc::clone(&host_a), ssid, fingerprint_b);
        let mut bob = SMPContext::new(Rc::clone(&host_b), ssid, fingerprint_a);

        // First attempt.
        {
            // Bob: initiate SMP
            assert_eq!(SMPStatus::Initial, alice.status());
            assert_eq!(SMPStatus::Initial, bob.status());
            let reply = bob
                .initiate(b"Bob provides the wrong secret", &question)
                .unwrap();
            assert_eq!(SMPStatus::Initial, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Alice: Follow up on Bob
            assert_eq!(SMPStatus::Initial, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = alice.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Bob: Follow up on Alice
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = bob.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Alice: Follow up on Bob
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = alice.handle(&reply).unwrap();
            assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Bob: Finish on Alice's reply
            assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
            assert_eq!(SMPStatus::InProgress, bob.status());
            assert!(bob.handle(&reply).is_none());
            assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
            assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
        }

        // Second attempt.
        {
            // Alice: initiate SMP
            assert!(matches!(alice.status(), SMPStatus::Aborted(_)));
            assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
            let reply = alice.initiate(&secret, &question).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert!(matches!(bob.status(), SMPStatus::Aborted(_)));

            // Bob: respond to init
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert!(matches!(bob.status(), SMPStatus::Aborted(_)));
            let reply = bob.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Alice: follow up on Bob
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = alice.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());

            // Bob: finish on Alice's reply
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::InProgress, bob.status());
            let reply = bob.handle(&reply).unwrap();
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::Completed, bob.status());

            // Alice: finish on Bob's reply
            assert_eq!(SMPStatus::InProgress, alice.status());
            assert_eq!(SMPStatus::Completed, bob.status());
            assert!(alice.handle(&reply).is_none());
            assert_eq!(SMPStatus::Completed, alice.status());
            assert_eq!(SMPStatus::Completed, bob.status());
        }
    }

    struct TestHost(dsa::Keypair, Vec<u8>, Vec<u8>);

    impl Host for TestHost {
        fn inject(&self, _: &[u8], _: &[u8]) {
            unimplemented!("not necessary for tests")
        }

        fn keypair(&self) -> Option<&dsa::Keypair> {
            Some(&self.0)
        }

        fn keypair_identity(&self) -> &crate::crypto::ed448::EdDSAKeyPair {
            unimplemented!("OTRv4 identity keypair is not necessary for tests")
        }

        fn keypair_forging(&self) -> &crate::crypto::ed448::EdDSAKeyPair {
            unimplemented!("OTRv4 forging keypair is not necessary for tests")
        }

        fn query_smp_secret(&self, question: &[u8]) -> Option<Vec<u8>> {
            assert_eq!(&self.1, question);
            Some(self.2.clone())
        }

        fn client_profile(&self) -> Vec<u8> {
            unimplemented!("client profile is not necessary for tests")
        }

        fn update_client_profile(&self, _: Vec<u8>) {
            unimplemented!("client profile is not necessary for tests")
        }
    }
}

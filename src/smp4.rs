// SPDX-License-Identifier: LGPL-3.0-only

use std::rc::Rc;

use num_bigint::BigUint;
use num_integer::Integer;
use zeroize::Zeroize;

use crate::{
    crypto::{constant, ed448, otr4},
    encoding::{OTRDecoder, OTREncoder, TLV},
    utils, Host, OTRError, TLVType, SSID,
};

pub fn is_smp_tlv(tlv: &TLV) -> bool {
    tlv.0 == TLV_SMP_MESSAGE_1
        || tlv.0 == TLV_SMP_MESSAGE_2
        || tlv.0 == TLV_SMP_MESSAGE_3
        || tlv.0 == TLV_SMP_MESSAGE_4
        || tlv.0 == TLV_SMP_ABORT
}

// TODO ensure `Drop` implementation is up-to-date after fully implementing SMP4.
pub struct SMP4Context {
    state: State,
    status: SMP4Status,
    host: Rc<dyn Host>,
    initiator: [u8; 56],
    responder: [u8; 56],
    ssid: SSID,
}

impl Drop for SMP4Context {
    fn drop(&mut self) {
        self.initiator.fill(0);
        self.responder.fill(0);
        utils::bytes::clear(&mut self.ssid);
    }
}

const TLV_SMP_MESSAGE_1: TLVType = 2;
const TLV_SMP_MESSAGE_2: TLVType = 3;
const TLV_SMP_MESSAGE_3: TLVType = 4;
const TLV_SMP_MESSAGE_4: TLVType = 5;
const TLV_SMP_ABORT: TLVType = 6;

// TODO ensure any produced error is followed by an abort and reset to ExpectSMP1.
// FIXME needs unit tests
// TODO SMP processing is very slow.
#[allow(non_snake_case)]
impl SMP4Context {
    pub fn new(
        host: Rc<dyn Host>,
        initiator: otr4::Fingerprint,
        responder: otr4::Fingerprint,
        ssid: SSID,
    ) -> SMP4Context {
        Self {
            state: State::ExpectSMP1,
            status: SMP4Status::Initial,
            host,
            initiator,
            responder,
            ssid,
        }
    }

    pub fn status(&self) -> SMP4Status {
        self.status.clone()
    }

    /// `initiate` initiates a new Socialist Millionaire's Protocol conversation for OTRv4.
    pub fn initiate(&mut self, secret: &[u8], question: &[u8]) -> Result<TLV, OTRError> {
        self.status = SMP4Status::InProgress;
        let result = self.initiate0(secret, question);
        if result.is_err() {
            self.status = SMP4Status::Aborted(Vec::from("Failed to initiate."));
        }
        result
    }

    fn initiate0(&mut self, secret: &[u8], question: &[u8]) -> Result<TLV, OTRError> {
        let G = ed448::generator();
        let q = ed448::prime_order();
        let a2 = ed448::random_in_Zq();
        let a3 = ed448::random_in_Zq();
        let r2 = ed448::random_in_Zq();
        let r3 = ed448::random_in_Zq();
        let c2 = ed448::hash_point_to_scalar(0x01, &(G * &r2));
        let d2 = (q + r2 - &(&a2 * &c2).mod_floor(q)).mod_floor(q);
        let c3 = ed448::hash_point_to_scalar(0x02, &(G * &r3));
        let d3 = (q + r3 - &(&a3 * &c3).mod_floor(q)).mod_floor(q);
        let G2a = G * &a2;
        ed448::verify(&G2a).map_err(OTRError::CryptographicViolation)?;
        let G3a = G * &a3;
        ed448::verify(&G3a).map_err(OTRError::CryptographicViolation)?;
        let smp1 = OTREncoder::new()
            .write_data(question)
            .write_ed448_point(&G2a)
            .write_ed448_scalar(&c2)
            .write_ed448_scalar(&d2)
            .write_ed448_point(&G3a)
            .write_ed448_scalar(&c3)
            .write_ed448_scalar(&d3)
            .to_vec();
        self.state = State::ExpectSMP2 {
            x: self.compute_secret(secret),
            a2,
            a3,
        };
        Ok(TLV(TLV_SMP_MESSAGE_1, smp1))
    }

    // TODO we can probably extract a common trait for both SMPContext and SMP4Context.
    pub fn handle(&mut self, tlv: &TLV) -> Option<TLV> {
        match self.dispatch(tlv) {
            Err(_) => {
                self.state = State::ExpectSMP1;
                // FIXME need description for abort
                self.status = SMP4Status::Aborted(Vec::from("Error"));
                None
            }
            Ok(response) => response,
        }
    }

    fn dispatch(&mut self, tlv: &TLV) -> Result<Option<TLV>, OTRError> {
        // TODO issue with early update of status is that you lose your 'completed' status very quickly with any incoming smp tlv
        self.status = SMP4Status::InProgress;
        match tlv.0 {
            TLV_SMP_ABORT => Ok(Some(self.abort())),
            TLV_SMP_MESSAGE_1 => self.handle_message_1(tlv).map(Option::Some),
            TLV_SMP_MESSAGE_2 => self.handle_message_2(tlv).map(Option::Some),
            TLV_SMP_MESSAGE_3 => self.handle_message_3(tlv).map(Option::Some),
            TLV_SMP_MESSAGE_4 => {
                self.handle_message_4(tlv)?;
                Ok(Option::None)
            }
            _ => panic!("BUG: unsupported TLV passed to SMP4"),
        }
    }

    /// `handle_message_1` handles the TLV containing SMP message 1 (with or without question).
    fn handle_message_1(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_SMP_MESSAGE_1);
        if let State::ExpectSMP1 = self.state {
            // No need to extract any data.
        } else {
            return Err(OTRError::ProtocolViolation(
                "Expected to receive SMP message 1",
            ));
        }
        let mut dec = OTRDecoder::new(&tlv.1);
        // TODO we need to split up processing TLV and responding, as we need the question to ask the user for their answer (secret).
        let question = dec.read_data()?;
        let G2a = dec.read_ed448_point()?;
        ed448::verify(&G2a).map_err(OTRError::CryptographicViolation)?;
        let c2 = dec.read_ed448_scalar()?;
        let d2 = dec.read_ed448_scalar()?;
        let G3a = dec.read_ed448_point()?;
        ed448::verify(&G3a).map_err(OTRError::CryptographicViolation)?;
        let c3 = dec.read_ed448_scalar()?;
        let d3 = dec.read_ed448_scalar()?;
        dec.done()?;
        // verify and process data from TLV.
        let G = ed448::generator();
        let q = ed448::prime_order();
        let c2_expected = ed448::hash_point_to_scalar(0x01, &(&(G * &d2) + &(&G2a * &c2)));
        constant::compare_scalars_distinct(&c2_expected, &c2)
            .map_err(OTRError::CryptographicViolation)?;
        let c3_expected = ed448::hash_point_to_scalar(0x02, &(&(G * &d3) + &(&G3a * &c3)));
        constant::compare_scalars_distinct(&c3_expected, &c3)
            .map_err(OTRError::CryptographicViolation)?;
        // Generate Bob's counterparts to random secret data for the SMP.
        let secret = self
            .host
            .query_smp_secret(&question)
            .ok_or(OTRError::SMPAborted(true))?;
        let b2 = ed448::random_in_Zq();
        let b3 = ed448::random_in_Zq();
        let r2 = ed448::random_in_Zq();
        let r3 = ed448::random_in_Zq();
        let r4 = ed448::random_in_Zq();
        let r5 = ed448::random_in_Zq();
        let r6 = ed448::random_in_Zq();
        let G2b = G * &b2;
        let G3b = G * &b3;
        let c2 = ed448::hash_point_to_scalar(0x03, &(G * &r2));
        let d2 = (q + &r2 - &(&b2 * &c2).mod_floor(q)).mod_floor(q);
        let c3 = ed448::hash_point_to_scalar(0x04, &(G * &r3));
        let d3 = (q + &r3 - &(&b3 * &c3).mod_floor(q)).mod_floor(q);
        // Prepare state for next message.
        let G2 = &G2a * &b2;
        ed448::verify(&G2).map_err(OTRError::CryptographicViolation)?;
        let G3 = &G3a * &b3;
        ed448::verify(&G3).map_err(OTRError::CryptographicViolation)?;
        let y = self.compute_secret(&secret);
        let Pb = &G3 * &r4;
        ed448::verify(&Pb).map_err(OTRError::CryptographicViolation)?;
        let Qb = &(G * &r4) + &(&G2 * &y);
        ed448::verify(&Qb).map_err(OTRError::CryptographicViolation)?;
        let cp = ed448::hash_point_to_scalar2(0x05, &(&G3 * &r5), &(&(G * &r5) + &(&G2 * &r6)));
        let d5 = (q + &r5 - (&r4 * &cp).mod_floor(q)).mod_floor(q);
        let d6 = (q + &r6 - (&y * &cp).mod_floor(q)).mod_floor(q);
        let smp2 = OTREncoder::new()
            .write_ed448_point(&G2b)
            .write_ed448_scalar(&c2)
            .write_ed448_scalar(&d2)
            .write_ed448_point(&G3b)
            .write_ed448_scalar(&c3)
            .write_ed448_scalar(&d3)
            .write_ed448_point(&Pb)
            .write_ed448_point(&Qb)
            .write_ed448_scalar(&cp)
            .write_ed448_scalar(&d5)
            .write_ed448_scalar(&d6)
            .to_vec();
        self.state = State::ExpectSMP3 {
            G3a,
            G2,
            G3,
            b3,
            Pb,
            Qb,
        };
        Ok(TLV(TLV_SMP_MESSAGE_2, smp2))
    }

    /// `handle_message_2` handles TLV payload for SMP message 2.
    fn handle_message_2(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_SMP_MESSAGE_2);
        let q = ed448::prime_order();
        let x: BigUint;
        let a2: BigUint;
        let a3: BigUint;
        if let State::ExpectSMP2 {
            x: x_,
            a2: a2_,
            a3: a3_,
        } = &self.state
        {
            x = x_.mod_floor(q);
            a2 = a2_.clone();
            a3 = a3_.clone();
        } else {
            return Err(OTRError::ProtocolViolation(
                "Expected to receive SMP message 2",
            ));
        }
        let mut dec = OTRDecoder::new(&tlv.1);
        let G2b = dec.read_ed448_point()?;
        let c2 = dec.read_ed448_scalar()?;
        let d2 = dec.read_ed448_scalar()?;
        let G3b = dec.read_ed448_point()?;
        let c3 = dec.read_ed448_scalar()?;
        let d3 = dec.read_ed448_scalar()?;
        let Pb = dec.read_ed448_point()?;
        let Qb = dec.read_ed448_point()?;
        let cp = dec.read_ed448_scalar()?;
        let d5 = dec.read_ed448_scalar()?;
        let d6 = dec.read_ed448_scalar()?;
        dec.done()?;
        // Verify received data.
        let G = ed448::generator();
        ed448::verify(&G2b).map_err(OTRError::CryptographicViolation)?;
        ed448::verify(&G3b).map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars_distinct(
            &c2,
            &ed448::hash_point_to_scalar(0x03, &(&(G * &d2) + &(&G2b * &c2))),
        )
        .map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars_distinct(
            &c3,
            &ed448::hash_point_to_scalar(0x04, &(&(G * &d3) + &(&G3b * &c3))),
        )
        .map_err(OTRError::CryptographicViolation)?;
        let G2 = &G2b * &a2;
        ed448::verify(&G2).map_err(OTRError::CryptographicViolation)?;
        let G3 = &G3b * &a3;
        ed448::verify(&G3).map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars_distinct(
            &cp,
            &ed448::hash_point_to_scalar2(
                0x05,
                &(&(&G3 * &d5) + &(&Pb * &cp)),
                &(&(&(G * &d5) + &(&G2 * &d6)) + &(&Qb * &cp)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        // Process data and produce response TLV.
        let r4 = ed448::random_in_Zq();
        let r5 = ed448::random_in_Zq();
        let r6 = ed448::random_in_Zq();
        let r7 = ed448::random_in_Zq();
        let Pa = &G3 * &r4;
        let DeltaPaPb = &Pa + &-&Pb;
        let G = ed448::generator();
        let Qa = &(G * &r4) + &(&G2 * &x);
        let DeltaQaQb = &Qa + &-&Qb;
        let cp = ed448::hash_point_to_scalar2(0x06, &(&G3 * &r5), &(&(G * &r5) + &(&G2 * &r6)));
        let d5 = (q + &r5 - (&r4 * &cp).mod_floor(q)).mod_floor(q);
        let d6 = (q + &r6 - (&x * &cp).mod_floor(q)).mod_floor(q);
        let Ra = &DeltaQaQb * &a3;
        let cr = ed448::hash_point_to_scalar2(0x07, &(G * &r7), &(&DeltaQaQb * &r7));
        let d7 = (q + &r7 - (&a3 * &cr).mod_floor(q)).mod_floor(q);
        let smp3 = OTREncoder::new()
            .write_ed448_point(&Pa)
            .write_ed448_point(&Qa)
            .write_ed448_scalar(&cp)
            .write_ed448_scalar(&d5)
            .write_ed448_scalar(&d6)
            .write_ed448_point(&Ra)
            .write_ed448_scalar(&cr)
            .write_ed448_scalar(&d7)
            .to_vec();
        self.state = State::ExpectSMP4 {
            G3b,
            DeltaPaPb,
            DeltaQaQb,
            a3,
        };
        Ok(TLV(TLV_SMP_MESSAGE_3, smp3))
    }

    /// `handle_message_3` handles the TLV payload for SMP message 3. It returns a tuple
    /// `(success, TLV)` with `success` indicating successful completion of the protocol, and `TLV`
    /// being the response TLV to send to Alice.
    fn handle_message_3(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_SMP_MESSAGE_3);
        let G3a: ed448::Point;
        let G2: ed448::Point;
        let G3: ed448::Point;
        let b3: BigUint;
        let Pb: ed448::Point;
        let Qb: ed448::Point;
        if let State::ExpectSMP3 {
            G3a: G3a_,
            G2: G2_,
            G3: G3_,
            b3: b3_,
            Pb: Pb_,
            Qb: Qb_,
        } = &self.state
        {
            G3a = G3a_.clone();
            G2 = G2_.clone();
            G3 = G3_.clone();
            b3 = b3_.clone();
            Pb = Pb_.clone();
            Qb = Qb_.clone();
        } else {
            return Err(OTRError::ProtocolViolation(
                "Expected to receive SMP message 3",
            ));
        }
        // read and decode input from TLV
        let mut dec = OTRDecoder::new(&tlv.1);
        let Pa = dec.read_ed448_point()?;
        let Qa = dec.read_ed448_point()?;
        let cp = dec.read_ed448_scalar()?;
        let d5 = dec.read_ed448_scalar()?;
        let d6 = dec.read_ed448_scalar()?;
        let Ra = dec.read_ed448_point()?;
        let cr = dec.read_ed448_scalar()?;
        let d7 = dec.read_ed448_scalar()?;
        dec.done()?;
        // Verify received data.
        let G = ed448::generator();
        ed448::verify(&Pa).map_err(OTRError::CryptographicViolation)?;
        ed448::verify(&Qa).map_err(OTRError::CryptographicViolation)?;
        ed448::verify(&Ra).map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars_distinct(
            &cp,
            &ed448::hash_point_to_scalar2(
                0x06,
                &(&(&G3 * &d5) + &(&Pa * &cp)),
                &(&(&(G * &d5) + &(&G2 * &d6)) + &(&Qa * &cp)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        let DeltaQaQb = &Qa + &-&Qb;
        constant::compare_scalars_distinct(
            &cr,
            &ed448::hash_point_to_scalar2(
                0x07,
                &(&(G * &d7) + &(&G3a * &cr)),
                &(&(&DeltaQaQb * &d7) + &(&Ra * &cr)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        // Produce SMP-type 4 message.
        let r7 = ed448::random_in_Zq();
        let Rb = &DeltaQaQb * &b3;
        let cr = ed448::hash_point_to_scalar2(0x08, &(G * &r7), &(&DeltaQaQb * &r7));
        let q = ed448::prime_order();
        let d7 = (q + &r7 - (&b3 * &cr).mod_floor(q)).mod_floor(q);
        let smp4 = OTREncoder::new()
            .write_ed448_point(&Rb)
            .write_ed448_scalar(&cr)
            .write_ed448_scalar(&d7)
            .to_vec();
        // Conclude the protocol by verifying if the secret is equal.
        self.state = State::ExpectSMP1;
        if constant::compare_points_distinct(&(Ra * b3), &(Pa + -&Pb)).is_ok() {
            self.status = SMP4Status::Completed;
        } else {
            self.status = SMP4Status::Aborted(Vec::from("Secrets proved not equal."));
        }
        Ok(TLV(TLV_SMP_MESSAGE_4, smp4))
    }

    /// `handle_message_4` handles TLV payload for SMP message 4. The result indicates successful
    /// completion of the protocol.
    fn handle_message_4(&mut self, tlv: &TLV) -> Result<(), OTRError> {
        assert_eq!(tlv.0, TLV_SMP_MESSAGE_4);
        let G3b: ed448::Point;
        let DeltaPaPb: ed448::Point;
        let DeltaQaQb: ed448::Point;
        let a3: BigUint;
        if let State::ExpectSMP4 {
            G3b: G3b_,
            DeltaPaPb: DeltaPaPb_,
            DeltaQaQb: DeltaQaQb_,
            a3: a3_,
        } = &self.state
        {
            G3b = G3b_.clone();
            DeltaPaPb = DeltaPaPb_.clone();
            DeltaQaQb = DeltaQaQb_.clone();
            a3 = a3_.clone();
        } else {
            return Err(OTRError::ProtocolViolation(
                "Expected to receive SMP message 4",
            ));
        }
        // read and decode input from TLV
        let mut dec = OTRDecoder::new(&tlv.1);
        let Rb = dec.read_ed448_point()?;
        let cr = dec.read_ed448_scalar()?;
        let d7 = dec.read_ed448_scalar()?;
        dec.done()?;
        // Verify received data.
        let G = ed448::generator();
        ed448::verify(&Rb).map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars_distinct(
            &cr,
            &ed448::hash_point_to_scalar2(
                0x08,
                &(&(G * &d7) + &(&G3b * &cr)),
                &(&(&DeltaQaQb * &d7) + &(&Rb * &cr)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        // Process data and verify.
        constant::compare_points_distinct(&(&Rb * &a3), &DeltaPaPb)
            .map_err(OTRError::CryptographicViolation)?;
        self.state = State::ExpectSMP1;
        self.status = SMP4Status::Completed;
        Ok(())
    }

    /// `abort` aborts an in-progress protocol execution by resetting state to initial state.
    pub fn abort(&mut self) -> TLV {
        self.state = State::ExpectSMP1;
        self.status = SMP4Status::Aborted(Vec::from("Aborted by user"));
        TLV(TLV_SMP_ABORT, Vec::new())
    }

    fn compute_secret(&self, secret: &[u8]) -> BigUint {
        let secretbytes = OTREncoder::new()
            .write_u8(1)
            .write_ed448_fingerprint(&self.initiator)
            .write_ed448_fingerprint(&self.responder)
            .write_ssid(&self.ssid)
            .write_data(secret)
            .to_vec();
        let mut digest = otr4::hwc::<57>(otr4::USAGE_SMP_SECRET, &secretbytes);
        ed448::prune(&mut digest);
        BigUint::from_bytes_le(&digest)
    }
}

/// `SMP4Status` indicates the current status of an SMP4 session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SMP4Status {
    /// `Initial` status: no SMP4 session, no activity.
    Initial,
    /// `InProgress` SMP4 process.
    InProgress,
    /// `Aborted` status indicates an SMP4 session not successfully completed.
    Aborted(Vec<u8>),
    /// `Completed` status indicates an SMP4 session that is successfully completed.
    Completed,
}

#[allow(non_snake_case)]
enum State {
    ExpectSMP1,
    ExpectSMP2 {
        x: BigUint,
        a2: BigUint,
        a3: BigUint,
    },
    ExpectSMP3 {
        G3a: ed448::Point,
        G2: ed448::Point,
        G3: ed448::Point,
        b3: BigUint,
        Pb: ed448::Point,
        Qb: ed448::Point,
    },
    ExpectSMP4 {
        G3b: ed448::Point,
        DeltaPaPb: ed448::Point,
        DeltaQaQb: ed448::Point,
        a3: BigUint,
    },
}

impl Drop for State {
    fn drop(&mut self) {
        match self {
            Self::ExpectSMP1 => {}
            Self::ExpectSMP2 { x, a2, a3 } => {
                x.zeroize();
                a2.zeroize();
                a3.zeroize();
            }
            Self::ExpectSMP3 {
                G3a: _,
                G2: _,
                G3: _,
                b3,
                Pb: _,
                Qb: _,
            } => {
                b3.zeroize();
            }
            Self::ExpectSMP4 {
                G3b: _,
                DeltaPaPb: _,
                DeltaQaQb: _,
                a3,
            } => {
                a3.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{rc::Rc, time::Instant};

    use crate::{
        crypto,
        utils::{self, random},
        Host, smp4::SMP4Status,
    };

    use super::SMP4Context;

    #[test]
    fn test_basic_process() {
        let initiator = random::secure_bytes::<56>();
        let responder = random::secure_bytes::<56>();
        let ssid = random::secure_bytes::<8>();
        let secret = Vec::from("It's a secret :-P");
        let question = Vec::from("What is your great great great great great great great great grandmother's maiden name?");
        let host: Rc<dyn Host> = Rc::new(TestHost(question.clone(), secret.clone()));
        let mut alice_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        assert!(matches!(alice_smp.status(), SMP4Status::Initial));
        let mut bob_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        assert!(matches!(bob_smp.status(), SMP4Status::Initial));

        let before_initiate = Instant::now();
        assert!(matches!(alice_smp.status(), SMP4Status::Initial));
        let init_tlv = alice_smp.initiate(&secret, &question).unwrap();
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        dbg!(before_initiate.elapsed());

        let before_smp1 = Instant::now();
        assert!(matches!(bob_smp.status(), SMP4Status::Initial));
        let tlv2 = bob_smp.handle(&init_tlv).unwrap();
        assert!(matches!(bob_smp.status(), SMP4Status::InProgress));
        dbg!(before_smp1.elapsed());

        let before_smp2 = Instant::now();
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        let tlv3 = alice_smp.handle(&tlv2).unwrap();
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        dbg!(before_smp2.elapsed());

        let before_smp3 = Instant::now();
        assert!(matches!(bob_smp.status(), SMP4Status::InProgress));
        let tlv4 = bob_smp.handle(&tlv3).unwrap();
        assert!(matches!(bob_smp.status(), SMP4Status::Completed));
        dbg!(before_smp3.elapsed());

        let before_smp4 = Instant::now();
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        assert!(alice_smp.handle(&tlv4).is_none());
        assert!(matches!(alice_smp.status(), SMP4Status::Completed));
        dbg!(before_smp4.elapsed());
    }

    #[test]
    fn test_bad_secret() {
        let initiator = random::secure_bytes::<56>();
        let responder = random::secure_bytes::<56>();
        let ssid = random::secure_bytes::<8>();
        let question = Vec::from("What is the best artist of all time?");
        let host: Rc<dyn Host> = Rc::new(TestHost(question.clone(), Vec::from("DragonForce")));
        let mut alice_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let mut bob_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let init_tlv = alice_smp.initiate(b"Nightwish", &question).unwrap();
        let tlv2 = bob_smp.handle(&init_tlv).unwrap();
        let tlv3 = alice_smp.handle(&tlv2).unwrap();
        assert!(matches!(bob_smp.status(), SMP4Status::InProgress));
        let tlv4 = bob_smp.handle(&tlv3).unwrap();
        assert!(matches!(bob_smp.status(), crate::smp4::SMP4Status::Aborted(_)));
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        assert!(alice_smp.handle(&tlv4).is_none());
        assert!(matches!(alice_smp.status(), SMP4Status::Aborted(_)));
    }

    #[test]
    fn test_bad_data_smp1() {
        let initiator = random::secure_bytes::<56>();
        let responder = random::secure_bytes::<56>();
        let ssid = random::secure_bytes::<8>();
        let question = Vec::from("What is the best artist of all time?");
        let secret = Vec::from("DragonForce");
        let host: Rc<dyn Host> = Rc::new(TestHost(question.clone(), secret.clone()));
        let mut alice_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let mut bob_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let mut init_tlv = alice_smp.initiate(&secret, &question).unwrap();
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        utils::random::fill_secure_bytes(&mut init_tlv.1);
        assert!(matches!(bob_smp.status(), SMP4Status::Initial));
        assert!(bob_smp.handle(&init_tlv).is_none());
        assert!(matches!(bob_smp.status(), SMP4Status::Aborted(_)));
    }

    #[test]
    fn test_bad_data_smp2() {
        let initiator = random::secure_bytes::<56>();
        let responder = random::secure_bytes::<56>();
        let ssid = random::secure_bytes::<8>();
        let question = Vec::from("What is the best artist of all time?");
        let secret = Vec::from("Nightwish");
        let host: Rc<dyn Host> = Rc::new(TestHost(question.clone(), secret.clone()));
        let mut alice_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let mut bob_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let init_tlv = alice_smp.initiate(&secret, &question).unwrap();
        let mut tlv2 = bob_smp.handle(&init_tlv).unwrap();
        assert!(matches!(bob_smp.status(), SMP4Status::InProgress));
        utils::random::fill_secure_bytes(&mut tlv2.1);
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        assert!(alice_smp.handle(&tlv2).is_none());
        assert!(matches!(alice_smp.status(), SMP4Status::Aborted(_)));
    }

    #[test]
    fn test_bad_data_smp3() {
        let initiator = random::secure_bytes::<56>();
        let responder = random::secure_bytes::<56>();
        let ssid = random::secure_bytes::<8>();
        let question = Vec::from("What is the best artist of all time?");
        let secret = Vec::from("Sonata Arctica");
        let host: Rc<dyn Host> = Rc::new(TestHost(question.clone(), secret.clone()));
        let mut alice_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let mut bob_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let init_tlv = alice_smp.initiate(&secret, &question).unwrap();
        let tlv2 = bob_smp.handle(&init_tlv).unwrap();
        let mut tlv3 = alice_smp.handle(&tlv2).unwrap();
        utils::random::fill_secure_bytes(&mut tlv3.1);
        assert!(matches!(bob_smp.status(), SMP4Status::InProgress));
        assert!(bob_smp.handle(&tlv3).is_none());
        assert!(matches!(bob_smp.status(), SMP4Status::Aborted(_)));
    }

    #[test]
    fn test_bad_data_smp4() {
        let initiator = random::secure_bytes::<56>();
        let responder = random::secure_bytes::<56>();
        let ssid = random::secure_bytes::<8>();
        let question = Vec::from("What is the best artist of all time?");
        let secret = Vec::from("Sonata Arctica");
        let host: Rc<dyn Host> = Rc::new(TestHost(question.clone(), secret.clone()));
        let mut alice_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let mut bob_smp = SMP4Context::new(Rc::clone(&host), initiator, responder, ssid);
        let init_tlv = alice_smp.initiate(&secret, &question).unwrap();
        let tlv2 = bob_smp.handle(&init_tlv).unwrap();
        let tlv3 = alice_smp.handle(&tlv2).unwrap();
        let mut tlv4 = bob_smp.handle(&tlv3).unwrap();
        assert_eq!(SMP4Status::Completed, bob_smp.status());
        utils::random::fill_secure_bytes(&mut tlv4.1);
        assert!(matches!(alice_smp.status(), SMP4Status::InProgress));
        assert!(alice_smp.handle(&tlv4).is_none());
        assert!(matches!(alice_smp.status(), SMP4Status::Aborted(_)));
    }

    struct TestHost(Vec<u8>, Vec<u8>);

    impl Host for TestHost {
        fn inject(&self, _address: &[u8], _message: &[u8]) {
            unimplemented!("message injection is not necessary for tests")
        }

        fn keypair(&self) -> &crypto::dsa::Keypair {
            unimplemented!("DSA keypair is not necessary for tests")
        }

        fn keypair_identity(&self) -> &crypto::ed448::EdDSAKeyPair {
            // FIXME implement: keypair_identity function for testing
            todo!("implement: keypair_identity function for testing")
        }

        fn keypair_forging(&self) -> &crypto::ed448::EdDSAKeyPair {
            // FIXME implement: keypair_forging function for testing
            todo!("implement: keypair_forging function for testing")
        }

        fn query_smp_secret(&self, question: &[u8]) -> Option<Vec<u8>> {
            assert_eq!(&self.0, question);
            Some(self.1.clone())
        }

        fn client_profile(&self) -> Vec<u8> {
            unimplemented!("client profile is not necessary for tests")
        }

        fn update_client_profile(&self, encoded_payload: &[u8]) {
            unimplemented!("client profile is not necessary for tests")
        }
    }
}

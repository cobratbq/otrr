use num_bigint::BigUint;
use num_integer::Integer;
use once_cell::sync::Lazy;
use ring::rand::SystemRandom;

use crate::{
    crypto::{
        self, constant,
        ed448::{self, hash_to_scalar},
        otr4, shake256,
    },
    encoding::{OTRDecoder, OTREncoder, TLV},
    OTRError, TLVType,
};

pub static RAND: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);

pub struct SMP4Context {
    state: State,
    initiator: Vec<u8>,
    responder: Vec<u8>,
    ssid: [u8; 8],
}

impl Drop for SMP4Context {
    fn drop(&mut self) {
        todo!()
    }
}

const TLV_SMP_MESSAGE_1: TLVType = 2;
const TLV_SMP_MESSAGE_2: TLVType = 3;
const TLV_SMP_MESSAGE_3: TLVType = 4;
const TLV_SMP_MESSAGE_4: TLVType = 5;
const TLV_SMP_ABORT: TLVType = 6;

// TODO ensure any produced error is followed by an abort and reset to ExpectSMP1.
// FIXME needs unit tests
#[allow(non_snake_case)]
impl SMP4Context {
    pub fn new(initiator: &[u8], responder: &[u8], ssid: [u8; 8]) -> SMP4Context {
        SMP4Context {
            state: State::ExpectSMP1,
            initiator: Vec::from(initiator),
            responder: Vec::from(responder),
            ssid,
        }
    }

    pub fn initiate(&mut self, secret: &[u8], question: &[u8]) -> Result<TLV, OTRError> {
        let x = self.generateSecret(secret);
        let G = ed448::generator();
        let a2 = ed448::random_in_Zq();
        let a3 = ed448::random_in_Zq();
        let r2 = ed448::random_in_Zq();
        let r3 = ed448::random_in_Zq();
        let c2 = ed448::hash_to_scalar(0x01, &(G * &r2));
        let d2 = r2 - &a2 * &c2;
        let c3 = ed448::hash_to_scalar(0x02, &(G * &r3));
        let d3 = r3 - &a3 * &c3;
        let G2a = G * &a2;
        ed448::verify(&G2a).map_err(OTRError::CryptographicViolation)?;
        let G3a = G * &a3;
        ed448::verify(&G3a).map_err(OTRError::CryptographicViolation)?;
        let smp1 = OTREncoder::new()
            .write_bytes_null_terminated(question)
            .write_ed448_point(&G2a)
            .write_ed448_scalar(&c2)
            .write_ed448_scalar(&d2)
            .write_ed448_point(&G3a)
            .write_ed448_scalar(&c3)
            .write_ed448_scalar(&d3)
            .to_vec();
        self.state = State::ExpectSMP2 { x, a2, a3 };
        Ok(TLV(TLV_SMP_MESSAGE_1, smp1))
    }

    pub fn handle_message_1(&mut self, tlv: &TLV, secret: &[u8]) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_SMP_MESSAGE_1);
        if let State::ExpectSMP1 = self.state {
            // No need to do anything.
        } else {
            return Err(OTRError::ProtocolViolation(
                "Expected to receive SMP message 1",
            ));
        }
        let mut dec = OTRDecoder::new(&tlv.1);
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
        let c2_expected = hash_to_scalar(0x01, &(&(G * &d2) + &(&G2a * &c2)));
        constant::compare_scalars(&c2_expected, &c2).map_err(OTRError::CryptographicViolation)?;
        let c3_expected = hash_to_scalar(0x02, &(&(G * &d3) + &(&G3a * &c3)));
        constant::compare_scalars(&c3_expected, &c3).map_err(OTRError::CryptographicViolation)?;
        // Generate Bob's counterparts to random secret data for the SMP.
        let b2 = ed448::random_in_Zq();
        let b3 = ed448::random_in_Zq();
        let r2 = ed448::random_in_Zq();
        let r3 = ed448::random_in_Zq();
        let r4 = ed448::random_in_Zq();
        let r5 = ed448::random_in_Zq();
        let r6 = ed448::random_in_Zq();
        let Q = ed448::modulus();
        let G2b = G * &b2;
        let G3b = G * &b3;
        let c2 = hash_to_scalar(0x03, &(G * &r2));
        let d2 = (&r2 - &b2 * &c2).mod_floor(Q);
        let c3 = ed448::hash_to_scalar(0x04, &(G * &r3));
        let d3 = (&r3 - &b3 * &c3).mod_floor(Q);
        // Prepare state for next message.
        let G2 = &G2a * &b2;
        ed448::verify(&G2).map_err(OTRError::CryptographicViolation)?;
        let G3 = &G3a * &b3;
        ed448::verify(&G3).map_err(OTRError::CryptographicViolation)?;
        // FIXME need to split function so we can independently respond with a secret answer.
        let y = self.generateSecret(secret);
        let Pb = &G3 * &r4;
        ed448::verify(&Pb).map_err(OTRError::CryptographicViolation)?;
        let Qb = &(G * &r4) + &(&G2 * &y);
        ed448::verify(&Qb).map_err(OTRError::CryptographicViolation)?;
        let cp = ed448::hash_to_scalar2(0x05, &(&G3 * &r5), &(&(G * &r5) + &(&G2 * &r6)));
        let d5 = (&r5 - &r4 * &cp).mod_floor(Q);
        let d6 = (&r6 - &y * &cp).mod_floor(Q);
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

    pub fn handle_message_2(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
        assert_eq!(tlv.0, TLV_SMP_MESSAGE_2);
        let Q = ed448::prime_order();
        let x: BigUint;
        let a2: BigUint;
        let a3: BigUint;
        if let State::ExpectSMP2 {
            x: x_,
            a2: a2_,
            a3: a3_,
        } = &self.state
        {
            x = x_.mod_floor(Q);
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
        constant::compare_scalars(
            &c2,
            &ed448::hash_to_scalar(0x03, &(&(G * &d2) + &(&G2b * &c2))),
        )
        .map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars(
            &c3,
            &ed448::hash_to_scalar(0x04, &(&(G * &d3) + &(&G3b * &c3))),
        )
        .map_err(OTRError::CryptographicViolation)?;
        let G2 = &G2b * &a2;
        ed448::verify(&G2).map_err(OTRError::CryptographicViolation)?;
        let G3 = &G3b * &a3;
        ed448::verify(&G3).map_err(OTRError::CryptographicViolation)?;
        constant::compare_scalars(
            &cp,
            &ed448::hash_to_scalar2(
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
        let DeltaPaPb = &Pa + &-Pb;
        let G = ed448::generator();
        let Qa = &(G * &r4) + &(&G2 * &x);
        let DeltaQaQb = &Qa + &-Qb;
        let cp = ed448::hash_to_scalar2(0x06, &(&G3 * &r5), &(&(G * &r5) + &(&G2 * &r6)));
        let d5 = &r5 - &r4 * &cp;
        let d6 = (&r6 - &x * &cp).mod_floor(Q);
        let Ra = &DeltaQaQb * &a3;
        let cr = ed448::hash_to_scalar2(0x07, &(G * &r7), &(&DeltaQaQb * &r7));
        let d7 = &r7 - &a3 * &cr;
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

    pub fn handle_message_3(&mut self, tlv: &TLV) -> Result<TLV, OTRError> {
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
        constant::compare_scalars(
            &cp,
            &ed448::hash_to_scalar2(
                0x06,
                &(&(&G3 * &d5) + &(&Pa * &cp)),
                &(&(&(G * &d5) + &(&G2 * &d6)) + &(&Qa * &cp)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        let DeltaQaQb = &Qa + &-Qb;
        constant::compare_scalars(
            &cr,
            &ed448::hash_to_scalar2(
                0x07,
                &(&(G * &d7) + &(&G3a * &cr)),
                &(&(&DeltaQaQb * &d7) + &(&Ra * &cr)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        // Produce SMP-type 4 message.
        let r7 = ed448::random_in_Zq();
        let Rb = &DeltaQaQb * &b3;
        let cr = ed448::hash_to_scalar2(0x08, &(G * &r7), &(&DeltaQaQb * &r7));
        let d7 = &r7 - &b3 * &cr;
        let smp4 = OTREncoder::new()
            .write_ed448_point(&Rb)
            .write_ed448_scalar(&cr)
            .write_ed448_scalar(&d7)
            .to_vec();
        // Conclude the protocol by verifying if the secret is equal.
        constant::compare_points(&(&Ra * &b3), &(&Pa + &-Pb))
            .map_err(OTRError::CryptographicViolation)?;
        // TODO we should respond with TLV even if verification fails for us.
        self.state = State::ExpectSMP1;
        Ok(TLV(TLV_SMP_MESSAGE_4, smp4))
    }

    pub fn handle_message_4(&mut self, tlv: &TLV) -> Result<(), OTRError> {
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
        constant::compare_scalars(
            &cr,
            &ed448::hash_to_scalar2(
                0x08,
                &(&(G * &d7) + &(&G3b * &cr)),
                &(&(&DeltaQaQb * &d7) + &(&Rb * &cr)),
            ),
        )
        .map_err(OTRError::CryptographicViolation)?;
        // Process data and verify.
        constant::compare_points(&(&Rb * &a3), &DeltaPaPb)
            .map_err(OTRError::CryptographicViolation)?;
        self.state = State::ExpectSMP1;
        Ok(())
    }

    pub fn abort(&mut self) -> TLV {
        self.state = State::ExpectSMP1;
        TLV(TLV_SMP_ABORT, Vec::new())
    }

    fn generateSecret(&self, secret: &[u8]) -> BigUint {
        let mut secretbytes = [0u8; 57];
        shake256::digest(
            &mut secretbytes,
            &OTREncoder::new()
                .write_u8(1)
                .write_ed448_fingerprint(&self.initiator)
                .write_ed448_fingerprint(&self.responder)
                .write_ssid(&self.ssid)
                .write_data(secret)
                .to_vec(),
        );
        let mut x_bytes = [0u8; 57];
        crypto::otr4::hwc(&mut x_bytes, otr4::UsageID::SMPSecret, &secretbytes);
        BigUint::from_bytes_le(&x_bytes)
    }
}

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
        todo!("implement drop support for SMP4State")
    }
}

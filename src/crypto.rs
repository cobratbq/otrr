// SPDX-License-Identifier: LGPL-3.0-only

use std::fmt::Debug;

use once_cell::sync::Lazy;
use ring::rand::SystemRandom;

static RAND: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);

#[allow(non_snake_case)]
pub mod DH {

    use once_cell::sync::Lazy;

    use num_bigint::BigUint;
    use ring::rand::SecureRandom;

    use crate::utils;

    use super::{CryptoError, RAND};

    /// GENERATOR (g): 2
    static GENERATOR: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u8));

    /// Modulus
    static MODULUS: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_bytes_be(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68,
            0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08,
            0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A,
            0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
            0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51,
            0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
            0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38,
            0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63,
            0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8,
            0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62,
            0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
            0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23,
            0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ])
    });

    /// Modulus - 2
    static MODULUS_MINUS_TWO: Lazy<BigUint> = Lazy::new(|| &*MODULUS - utils::biguint::two());

    // "D values are calculated modulo `q = (p - 1) / 2`"
    static Q: Lazy<BigUint> =
        Lazy::new(|| (&*MODULUS - utils::biguint::one()) / utils::biguint::two());

    pub fn generator() -> &'static BigUint {
        &*GENERATOR
    }

    pub fn modulus() -> &'static BigUint {
        &*MODULUS
    }

    pub fn q() -> &'static BigUint {
        &*Q
    }

    pub fn verify_public_key(public_key: &BigUint) -> Result<(), CryptoError> {
        if public_key >= &*GENERATOR && public_key <= &*MODULUS_MINUS_TWO {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "DH public key fails verification.",
            ))
        }
    }

    pub fn verify_exponent(component: &BigUint) -> Result<(), CryptoError> {
        if component >= utils::biguint::one() && component < &*Q {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "DH exponent for zero-knowledge proof fails verification.",
            ))
        }
    }

    #[derive(Clone)]
    pub struct Keypair {
        private: BigUint,
        pub public: BigUint,
    }

    impl Keypair {
        pub fn generate() -> Self {
            // OTR-spec: "When starting a private conversation with a correspondent, generate two DH
            //   key pairs for yourself, and set our_keyid = 2. Note that all DH key pairs should
            //   have a private part that is at least 320 bits long."
            let mut v = [0u8; 192];
            (*RAND)
                .fill(&mut v)
                .expect("Failed to produce random bytes for random big unsigned integer value.");
            assert!(utils::bytes::any_nonzero(&v));
            Self::new(BigUint::from_bytes_be(&v))
        }

        pub fn new(private: BigUint) -> Self {
            Self::new_custom(&*GENERATOR, private)
        }

        pub fn new_custom(generator: &BigUint, private: BigUint) -> Self {
            let public = generator.modpow(&private, &*MODULUS);
            Self { private, public }
        }

        pub fn generate_shared_secret(&self, public_key: &BigUint) -> SharedSecret {
            public_key.modpow(&self.private, &*MODULUS)
        }
    }

    pub type SharedSecret = BigUint;

    pub fn verify(expected: &BigUint, actual: &BigUint) -> Result<(), CryptoError> {
        assert!(
            !core::ptr::eq(expected, actual),
            "BUG: references provided for verification must be different."
        );
        if expected == actual {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "Provided values are not equal.",
            ))
        }
    }
}

#[allow(non_snake_case)]
pub mod OTR {
    use num_bigint::{BigUint, ModInverse, ToBigInt};
    use num_integer::Integer;

    use crate::encoding::OTREncoder;

    use super::{AES128, DSA, SHA1, SHA256};

    pub struct AKESecrets {
        pub ssid: [u8; 8],
        pub c: AES128::Key,
        pub cp: AES128::Key,
        pub m1: [u8; 32],
        pub m1p: [u8; 32],
        pub m2: [u8; 32],
        pub m2p: [u8; 32],
    }

    impl Drop for AKESecrets {
        fn drop(&mut self) {
            self.ssid = [0u8; 8];
            self.m1 = [0u8; 32];
            self.m1p = [0u8; 32];
            self.m2 = [0u8; 32];
            self.m2p = [0u8; 32];
        }
    }

    impl AKESecrets {
        /// Derive the shared secrets used by OTR version 3 that are based on the shared secret from the DH key exchange.
        pub fn derive(secbytes: &[u8]) -> AKESecrets {
            let h2secret0 = h2(0x00, secbytes);
            let h2secret1 = h2(0x01, secbytes);
            AKESecrets {
                ssid: h2secret0[..8].try_into().unwrap(),
                c: AES128::Key(h2secret1[..16].try_into().unwrap()),
                cp: AES128::Key(h2secret1[16..].try_into().unwrap()),
                m1: h2(0x02, secbytes),
                m2: h2(0x03, secbytes),
                m1p: h2(0x04, secbytes),
                m2p: h2(0x05, secbytes),
            }
        }
    }

    pub struct DataSecrets {
        sendkey: AES128::Key,
        recvkey: AES128::Key,
    }

    impl DataSecrets {
        pub fn derive(our_key: &BigUint, their_key: &BigUint, secbytes: &[u8]) -> DataSecrets {
            // testing keys for equality as this should be virtually impossible
            assert_eq!(our_key, their_key);
            let (sendbyte, recvbyte) = if our_key > their_key {
                (1u8, 2u8)
            } else {
                (2u8, 1u8)
            };
            // "For a given byte b, define h1(b) to be the 160-bit output of the SHA-1 hash of the
            // (5+len) bytes consisting of the byte b, followed by secbytes."
            let mut sendkey = [0u8; 16];
            sendkey.copy_from_slice(&h1(sendbyte, secbytes)[..16]);
            let mut recvkey = [0u8; 16];
            recvkey.copy_from_slice(&h1(recvbyte, secbytes)[..16]);
            DataSecrets {
                sendkey: AES128::Key(sendkey),
                recvkey: AES128::Key(recvkey),
            }
        }

        pub fn sender_crypt_key(&self) -> &AES128::Key {
            &self.sendkey
        }

        pub fn sender_mac_key(&self) -> [u8; 20] {
            SHA1::digest(&self.sendkey.0)
        }

        pub fn receiver_crypt_key(&self) -> &AES128::Key {
            &self.recvkey
        }

        pub fn receiver_mac_key(&self) -> [u8; 20] {
            SHA1::digest(&self.recvkey.0)
        }
    }

    fn h1(b: u8, secbytes: &[u8]) -> [u8; 20] {
        let mut bytes = vec![b];
        bytes.extend_from_slice(secbytes);
        SHA1::digest(&bytes)
    }

    fn h2(b: u8, secbytes: &[u8]) -> [u8; 32] {
        let mut bytes = vec![b];
        bytes.extend_from_slice(secbytes);
        SHA256::digest(&bytes)
    }

    pub fn fingerprint(pk: &DSA::PublicKey) -> [u8; 20] {
        // "The fingerprint is calculated by taking the SHA-1 hash of the byte-level representation
        //  of the public key. However, there is an exception for backwards compatibility: if the
        //  pubkey type is 0x0000, those two leading 0x00 bytes are omitted from the data to be
        //  hashed. The encoding assures that, assuming the hash function itself has no useful
        //  collisions, and DSA keys have length less than 524281 bits (500 times larger than most
        //  DSA keys), no two public keys will have the same fingerprint."
        SHA1::digest(&OTREncoder::new().write_public_key(pk).to_vec()[2..])
    }

    /// `mod_inv` is a modular-inverse implementation.
    /// `value` and `modulus` are required to be relatively prime.
    pub fn mod_inv(value: &BigUint, modulus: &BigUint) -> BigUint {
        value
            .mod_inverse(modulus)
            .unwrap()
            .mod_floor(&modulus.to_bigint().unwrap())
            .to_biguint()
            .unwrap()
    }
}

#[allow(non_snake_case)]
pub mod AES128 {
    use aes_ctr::{
        cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher},
        Aes128Ctr,
    };

    use ring::rand::SecureRandom;
    use std::ops::Drop;

    use super::RAND;

    const KEY_LENGTH: usize = 16;

    type Nonce = [u8; 16];

    #[derive(Clone)]
    pub struct Key(pub [u8; KEY_LENGTH]);

    impl Key {
        pub fn generate() -> Self {
            let mut key = [0u8; 16];
            RAND.fill(&mut key)
                .expect("BUG: Failed to acquire random bytes. (This was not anticipated to fail.)");
            Key(key)
        }

        pub fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            self.crypt(nonce, data)
        }

        pub fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            self.crypt(nonce, data)
        }

        /// crypt provides both encrypting and decrypting logic.
        fn crypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            let mut result = Vec::from(data);
            let key = GenericArray::from_slice(&self.0);
            let nonce = GenericArray::from_slice(nonce);
            let mut cipher = Aes128Ctr::new(key, nonce);
            cipher.apply_keystream(result.as_mut_slice());
            result
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            self.0.fill(0);
        }
    }
}

#[allow(non_snake_case)]
pub mod DSA {
    use std::rc::Rc;

    use dsa::{signature::rand_core::OsRng, Components, KeySize, SigningKey, VerifyingKey};
    use num_bigint::BigUint;

    use super::CryptoError;

    /// Signature type represents a DSA signature in IEEE-P1363 representation.
    const PARAM_Q_LENGTH: usize = 20;

    pub struct Keypair {
        sk: SigningKey,
        pk: Rc<VerifyingKey>,
    }

    pub struct PublicKey(Rc<VerifyingKey>);

    impl Keypair {
        #[allow(deprecated)]
        pub fn generate() -> Self {
            let components = Components::generate(&mut OsRng, KeySize::DSA_1024_160);
            let sk = SigningKey::generate(&mut OsRng, components);
            let pk = Rc::new(sk.verifying_key().clone());
            Self { sk, pk }
        }

        pub fn public_key(&self) -> PublicKey {
            PublicKey(Rc::clone(&self.pk))
        }

        pub fn sign(&self, digest_bytes: &[u8; 32]) -> Signature {
            // FIXME DSA needs proper implementation but `sign_prehashed` is not accessible (internal use only)
            println!("WARNING: NOOP implementation of DSA signatures for testing purposes only.");
            Signature(dsa::Signature::from_components(
                BigUint::from(0u8),
                BigUint::from(0u8),
            ))
        }
    }

    impl PublicKey {
        pub fn from_components(
            p: BigUint,
            q: BigUint,
            g: BigUint,
            y: BigUint,
        ) -> Result<Self, CryptoError> {
            if q.bits() != PARAM_Q_LENGTH {
                return Err(CryptoError::VerificationFailure(
                    "Number of bits in component Q does not correspond to prescribed length of 20.",
                ));
            }
            let components = Components::from_components(p, q, g).or(Err(
                CryptoError::VerificationFailure("illegal values for DSA public components"),
            ))?;
            Ok(Self(Rc::new(
                VerifyingKey::from_components(components, y).or(Err(
                    CryptoError::VerificationFailure(
                        "illegal value for public key component y or its shared components",
                    ),
                ))?,
            )))
        }

        pub fn verify(&self, signature: &Signature, digest: &[u8]) -> Result<(), CryptoError> {
            // FIXME DSA needs proper implementation but `sign_prehashed` is not accessible (internal use only)
            println!("WARNING: NOOP implementation of DSA signatures for testing purposes only.");
            Ok(())
        }

        pub fn p(&self) -> &BigUint {
            self.0.components().p()
        }

        pub fn q(&self) -> &BigUint {
            self.0.components().q()
        }

        pub fn g(&self) -> &BigUint {
            self.0.components().g()
        }

        pub fn y(&self) -> &BigUint {
            self.0.y()
        }
    }

    pub struct Signature(dsa::Signature);

    impl Signature {
        pub const fn size() -> usize {
            2 * PARAM_Q_LENGTH
        }

        pub const fn parameter_size() -> usize {
            PARAM_Q_LENGTH
        }

        pub fn from_components(r: BigUint, s: BigUint) -> Self {
            Self(dsa::Signature::from_components(r, s))
        }

        pub fn r(&self) -> &BigUint {
            self.0.r()
        }

        pub fn s(&self) -> &BigUint {
            self.0.s()
        }
    }
}

#[allow(non_snake_case)]
pub mod SHA1 {
    type Digest = [u8; 20];

    pub fn digest(data: &[u8]) -> Digest {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        let mut result: Digest = [0u8; 20];
        result.clone_from_slice(digest.as_ref());
        result
    }

    pub fn hmac(mk: &[u8], data: &[u8]) -> Digest {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, mk);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 20];
        result.clone_from_slice(digest.as_ref());
        result
    }
}

#[allow(non_snake_case)]
pub mod SHA256 {
    type Digest = [u8; 32];

    pub fn digest_with_prefix(b: u8, data: &[u8]) -> Digest {
        let mut payload: Vec<u8> = Vec::with_capacity(data.len() + 1);
        payload.push(b);
        payload.extend_from_slice(data);
        digest(&payload)
    }

    pub fn digest_2_with_prefix(b: u8, data: &[u8], data2: &[u8]) -> Digest {
        let mut payload: Vec<u8> = Vec::with_capacity(1 + data.len() + data2.len());
        payload.push(b);
        payload.extend_from_slice(data);
        payload.extend_from_slice(data2);
        digest(&payload)
    }

    /// digest calculates the SHA256 digest value.
    pub fn digest(data: &[u8]) -> Digest {
        let digest = ring::digest::digest(&ring::digest::SHA256, data);
        let mut result = [0u8; 32];
        result.clone_from_slice(digest.as_ref());
        result
    }

    /// hmac calculates the SHA256-HMAC value, using key 'm1' as documented in OTR version 3 spec.
    pub fn hmac(m1: &[u8], data: &[u8]) -> Digest {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m1);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 32];
        result.clone_from_slice(digest.as_ref());
        result
    }

    /// hmac160 calculates the first 160 bits of the SHA256-HMAC value, using key 'm2' as documented in OTR version 3 spec.
    pub fn hmac160(m2: &[u8], data: &[u8]) -> [u8; 20] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m2);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 20];
        result.clone_from_slice(&digest.as_ref()[..20]);
        result
    }
}

pub mod constant {
    use crate::utils;

    use super::CryptoError;

    pub fn verify(mac1: &[u8], mac2: &[u8]) -> Result<(), CryptoError> {
        assert!(utils::bytes::any_nonzero(mac1));
        assert!(utils::bytes::any_nonzero(mac2));
        ring::constant_time::verify_slices_are_equal(mac1, mac2).or(Err(
            CryptoError::VerificationFailure("mac verification failed"),
        ))
    }
}

#[derive(Debug)]
pub enum CryptoError {
    VerificationFailure(&'static str),
}

#[cfg(test)]
mod tests {
    use crate::utils;
    use num_bigint::BigUint;

    use super::{constant, DH};

    #[test]
    fn test_dh_verify_homogenous() {
        let v1 = BigUint::from(7u8);
        let v2 = BigUint::from(7u8);
        let v3 = BigUint::from(9u8);
        assert!(DH::verify(&v1, &v2).is_ok());
        assert!(DH::verify(&v2, &v1).is_ok());
        assert!(DH::verify(&v1, &v3).is_err());
        assert!(DH::verify(&v2, &v3).is_err());
        assert!(DH::verify(&v3, &v1).is_err());
        assert!(DH::verify(&v3, &v2).is_err());
    }

    #[test]
    fn test_dh_verify_heterogenous() {
        let v1 = BigUint::from(7u8);
        let v2 = BigUint::from(7u16);
        assert!(DH::verify(&v1, &v2).is_ok());
        assert!(DH::verify(&v2, &v1).is_ok());
    }

    #[test]
    #[should_panic]
    #[allow(unused_must_use)]
    fn test_dh_verify_panic_on_same() {
        let v1 = BigUint::from(7u8);
        DH::verify(&v1, &v1);
    }

    #[test]
    fn test_dh_general_expectations() {
        assert_eq!(DH::generator(), DH::generator());
        assert_eq!(DH::modulus(), DH::modulus());
        assert_eq!(DH::q(), DH::q());
        let k1 = DH::Keypair::generate();
        assert!(DH::verify_public_key(&k1.public).is_ok());
        let k2 = DH::Keypair::generate();
        assert!(DH::verify_public_key(&k2.public).is_ok());
        let k3 = DH::Keypair::generate();
        assert!(DH::verify_public_key(&k3.public).is_ok());
        let k4 = DH::Keypair::generate();
        assert!(DH::verify_public_key(&k4.public).is_ok());
        let k5 = DH::Keypair::generate();
        assert!(DH::verify_public_key(&k5.public).is_ok());
        assert_ne!(k1.public, k2.public);
        assert_ne!(k2.public, k3.public);
        assert_ne!(k3.public, k4.public);
        assert_ne!(k4.public, k5.public);
        assert_eq!(
            k1.generate_shared_secret(&k2.public),
            k2.generate_shared_secret(&k1.public)
        );
        assert_eq!(
            k2.generate_shared_secret(&k3.public),
            k3.generate_shared_secret(&k2.public)
        );
        assert_eq!(
            k4.generate_shared_secret(&k3.public),
            k3.generate_shared_secret(&k4.public)
        );
        assert_eq!(
            k4.generate_shared_secret(&k5.public),
            k5.generate_shared_secret(&k4.public)
        );
        assert_eq!(
            k1.generate_shared_secret(&k5.public),
            k5.generate_shared_secret(&k1.public)
        );
        assert_eq!(
            k2.generate_shared_secret(&k4.public),
            k4.generate_shared_secret(&k2.public)
        );
        assert_eq!(
            k3.generate_shared_secret(&k3.public),
            k3.generate_shared_secret(&k3.public)
        );
        assert!(DH::verify_public_key(utils::biguint::zero()).is_err());
        assert!(DH::verify_public_key(utils::biguint::one()).is_err());
        assert!(DH::verify_public_key(utils::biguint::two()).is_ok());
        assert!(DH::verify_public_key(&(DH::modulus() - utils::biguint::two())).is_ok());
        assert!(DH::verify_public_key(&(DH::modulus() - utils::biguint::one())).is_err());
        assert!(DH::verify_public_key(DH::modulus()).is_err());
        assert!(DH::verify_public_key(&(DH::modulus() + utils::biguint::one())).is_err());
        assert!(DH::verify_exponent(utils::biguint::zero()).is_err());
        assert!(DH::verify_exponent(utils::biguint::one()).is_ok());
        assert!(DH::verify_exponent(utils::biguint::two()).is_ok());
        assert!(DH::verify_exponent(&(DH::q() - utils::biguint::one())).is_ok());
        assert!(DH::verify_exponent(DH::q()).is_err());
        assert!(DH::verify_exponent(&(DH::q() + utils::biguint::one())).is_err());
    }

    #[test]
    #[should_panic]
    fn test_zero_length_slices() {
        constant::verify(&[], &[]).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_zero_slices() {
        constant::verify(&[0, 0, 0, 0], &[0, 0, 0, 0]).unwrap();
    }

    #[test]
    fn test_same_length_slices() {
        constant::verify(b"Hello world", b"Hello world").unwrap();
    }

    #[test]
    fn test_different_content() {
        assert!(constant::verify(b"Hello!", b"Yo!").is_err());
    }

    #[test]
    fn test_differing_length_slices() {
        assert!(constant::verify(b"Hello!", b"Hello").is_err());
    }
}

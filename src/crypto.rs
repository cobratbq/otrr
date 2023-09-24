// SPDX-License-Identifier: LGPL-3.0-only

use std::fmt::Debug;

use once_cell::sync::Lazy;
use ring::rand::SystemRandom;

use crate::utils;

static RAND: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);

// TODO double-check all big-endian/little-endian use. (generate ECDH uses little-endian)
// TODO check on if/how to clear/drop BigUint values after use.

#[allow(non_snake_case)]
pub mod dh {

    use once_cell::sync::Lazy;

    use num_bigint::BigUint;
    use ring::rand::SecureRandom;
    use zeroize::Zeroize;

    use crate::utils::{
        self,
        biguint::{ONE, TWO},
    };

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
    static MODULUS_MINUS_TWO: Lazy<BigUint> = Lazy::new(|| &*MODULUS - &*TWO);

    // "D values are calculated modulo `q = (p - 1) / 2`"
    static Q: Lazy<BigUint> = Lazy::new(|| (&*MODULUS - &*ONE) / &*TWO);

    /// `generator` returns the generator (`g`)
    #[must_use]
    pub fn generator() -> &'static BigUint {
        &GENERATOR
    }

    /// `modulus` returns the  modulus.
    #[must_use]
    pub fn modulus() -> &'static BigUint {
        &MODULUS
    }

    /// `q` returns the prime order.
    #[must_use]
    pub fn q() -> &'static BigUint {
        &Q
    }

    /// `verify_public_key` verifies the provided public key.
    ///
    /// # Errors
    /// `CryptError` in case public key is illegal..
    pub fn verify_public_key(public_key: &BigUint) -> Result<(), CryptoError> {
        if public_key >= &*GENERATOR && public_key <= &*MODULUS_MINUS_TWO {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "DH public key fails verification.",
            ))
        }
    }

    /// `verify_exponent` verifies a MPI value to be used as exponent.
    ///
    /// # Errors
    /// `CryptError` in case the provided MPI value is illegal.
    pub fn verify_exponent(component: &BigUint) -> Result<(), CryptoError> {
        if component >= &*ONE && component < &*Q {
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
        public: BigUint,
    }

    impl Drop for Keypair {
        fn drop(&mut self) {
            self.private.zeroize();
            self.public.zeroize();
        }
    }

    impl Keypair {
        /// `generate` generates a new keypair from secure random data.
        ///
        /// # Panics
        /// In case we fail to produce random data.
        #[must_use]
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

        /// `new` constructs a new DH keypair from provided private scalar value.
        #[must_use]
        pub fn new(private: BigUint) -> Self {
            Self::new_custom(&GENERATOR, private)
        }

        /// `new_custom` creates a new keypair using provided custom generator value and private scalar.
        #[must_use]
        pub fn new_custom(generator: &BigUint, private: BigUint) -> Self {
            let public = generator.modpow(&private, &MODULUS);
            Self { private, public }
        }

        /// `public` returns the public component of the keypair.
        #[must_use]
        pub fn public(&self) -> &BigUint {
            &self.public
        }

        /// `generate_shared_secret` generates a shared secret from its own keypair and the provided public key.
        #[must_use]
        pub fn generate_shared_secret(&self, public_key: &BigUint) -> SharedSecret {
            public_key.modpow(&self.private, &MODULUS)
        }
    }

    pub type SharedSecret = BigUint;

    /// `verify` verifies provided MPI value against an (also provided) expected MPI value.
    ///
    /// # Errors
    /// `CryptError` in case of verification failure.
    ///
    /// # Panics
    /// In case expected and actual MPIs are same instance.
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
pub mod otr {
    use num_bigint::{BigUint, ModInverse};

    use crate::{encoding::OTREncoder, SSID};

    use super::{aes128, dsa, sha1, sha256};

    pub struct AKESecrets {
        pub ssid: SSID,
        pub c: aes128::Key,
        pub cp: aes128::Key,
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
        ///
        /// # Panics
        /// Panics if secret values cannot be coerced into 16-byte arrays (AES-key containers).
        #[must_use]
        pub fn derive(secbytes: &[u8]) -> AKESecrets {
            let h2secret0 = h2(0x00, secbytes);
            let h2secret1 = h2(0x01, secbytes);
            AKESecrets {
                ssid: h2secret0[..8].try_into().unwrap(),
                c: aes128::Key(h2secret1[..16].try_into().unwrap()),
                cp: aes128::Key(h2secret1[16..].try_into().unwrap()),
                m1: h2(0x02, secbytes),
                m2: h2(0x03, secbytes),
                m1p: h2(0x04, secbytes),
                m2p: h2(0x05, secbytes),
            }
        }
    }

    pub struct DataSecrets {
        sendkey: aes128::Key,
        recvkey: aes128::Key,
    }

    impl DataSecrets {
        /// `derive` derives the secret key material used in Data messages.
        ///
        /// The parameter `secbytes` represents the `4+len` OTR-encoded bytes value `s`.
        ///
        /// # Panics
        /// Panics if `our_key` and `their_key` are the same instance.
        #[must_use]
        pub fn derive(our_key: &BigUint, their_key: &BigUint, secbytes: &[u8]) -> DataSecrets {
            // testing keys for equality as this should be virtually impossible
            assert!(
                !core::ptr::eq(our_key, their_key),
                "BUG: our_key and their_key parameters are same reference."
            );
            assert_ne!(our_key, their_key, "Deriving Data-message secrets with both provided public keys being exactly the same. This is highly unlikely.");
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
                sendkey: aes128::Key(sendkey),
                recvkey: aes128::Key(recvkey),
            }
        }

        #[must_use]
        pub fn sender_crypt_key(&self) -> &aes128::Key {
            &self.sendkey
        }

        #[must_use]
        pub fn sender_mac_key(&self) -> [u8; 20] {
            sha1::digest(&self.sendkey.0)
        }

        #[must_use]
        pub fn receiver_crypt_key(&self) -> &aes128::Key {
            &self.recvkey
        }

        #[must_use]
        pub fn receiver_mac_key(&self) -> [u8; 20] {
            sha1::digest(&self.recvkey.0)
        }
    }

    fn h1(b: u8, secbytes: &[u8]) -> [u8; 20] {
        let mut bytes = vec![b];
        bytes.extend_from_slice(secbytes);
        sha1::digest(&bytes)
    }

    fn h2(b: u8, secbytes: &[u8]) -> [u8; 32] {
        let mut bytes = vec![b];
        bytes.extend_from_slice(secbytes);
        sha256::digest(&bytes)
    }

    #[must_use]
    pub fn fingerprint(pk: &dsa::PublicKey) -> [u8; 20] {
        // "The fingerprint is calculated by taking the SHA-1 hash of the byte-level representation
        //  of the public key. However, there is an exception for backwards compatibility: if the
        //  pubkey type is 0x0000, those two leading 0x00 bytes are omitted from the data to be
        //  hashed. The encoding assures that, assuming the hash function itself has no useful
        //  collisions, and DSA keys have length less than 524281 bits (500 times larger than most
        //  DSA keys), no two public keys will have the same fingerprint."
        sha1::digest(&OTREncoder::new().write_public_key(pk).to_vec()[2..])
    }

    /// `mod_inv` is a modular-inverse implementation.
    /// `value` and `modulus` are required to be relatively prime.
    ///
    /// # Panics
    /// Panics in case `BigUint` computations fail (not expected).
    #[must_use]
    pub fn mod_inv(value: &BigUint, modulus: &BigUint) -> BigUint {
        value.mod_inverse(modulus).unwrap().to_biguint().unwrap()
    }
}

#[allow(non_snake_case)]
pub mod aes128 {
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
        /// `generate` generates an AES-128 key.
        ///
        /// # Panics
        /// Panics if it fails to generate (sufficient) random data.
        pub fn generate() -> Self {
            let mut key = [0u8; 16];
            RAND.fill(&mut key)
                .expect("BUG: Failed to acquire random bytes. (This was not anticipated to fail.)");
            Key(key)
        }

        #[must_use]
        pub fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            self.crypt(nonce, data)
        }

        #[must_use]
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
pub mod dsa {
    use std::rc::Rc;

    use dsa::{
        signature::{
            hazmat::{PrehashSigner, PrehashVerifier},
            rand_core::OsRng,
        },
        Components, KeySize, SigningKey, VerifyingKey,
    };
    use num_bigint::BigUint;

    use super::CryptoError;

    /// Signature type represents a DSA signature in IEEE-P1363 representation.
    const PARAM_Q_LENGTH_BYTES: usize = 20;

    pub struct Keypair {
        sk: SigningKey,
        pk: Rc<VerifyingKey>,
    }

    impl Keypair {
        #[allow(deprecated)]
        pub fn generate() -> Self {
            let components = Components::generate(&mut OsRng, KeySize::DSA_1024_160);
            let sk = SigningKey::generate(&mut OsRng, components);
            let pk = Rc::new(sk.verifying_key().clone());
            Self { sk, pk }
        }

        #[must_use]
        pub fn public_key(&self) -> PublicKey {
            PublicKey(Rc::clone(&self.pk))
        }

        #[must_use]
        pub fn get_q(&self) -> &BigUint {
            self.pk.components().q()
        }

        /// `sign` signs a provided prehash value with the private key.
        ///
        /// # Panics
        /// Panics if result unexpectedly cannot be unpacked.
        #[must_use]
        pub fn sign(&self, prehash: &[u8; 20]) -> Signature {
            Signature(self.sk.sign_prehash(prehash).unwrap())
        }
    }

    #[derive(Clone)]
    pub struct PublicKey(Rc<VerifyingKey>);

    impl PublicKey {
        /// `from_components` recreates a DSA public key from individual components.
        ///
        /// # Errors
        /// `CryptError` in case it fails to recreate the public key, e.g. because of illegal values among the components.
        pub fn from_components(
            p: BigUint,
            q: BigUint,
            g: BigUint,
            y: BigUint,
        ) -> Result<Self, CryptoError> {
            if q.bits() != PARAM_Q_LENGTH_BYTES * 8 {
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

        /// `verify` verifies a signature using a prehash value as defined in FIPS-186 and specified in OTR 3 spec.
        ///
        /// # Errors
        /// `CryptError` in case signature verification fails, meaning either the signature or the prehash value is invalid. (Or the public key itself.)
        pub fn verify(&self, signature: &Signature, prehash: &[u8; 20]) -> Result<(), CryptoError> {
            self.0
                .verify_prehash(prehash, &signature.0)
                .or(Err(CryptoError::VerificationFailure(
                    "DSA signature or public key contains invalid data.",
                )))
        }

        #[must_use]
        pub fn p(&self) -> &BigUint {
            self.0.components().p()
        }

        #[must_use]
        pub fn q(&self) -> &BigUint {
            self.0.components().q()
        }

        #[must_use]
        pub fn g(&self) -> &BigUint {
            self.0.components().g()
        }

        #[must_use]
        pub fn y(&self) -> &BigUint {
            self.0.y()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Signature(dsa::Signature);

    impl Signature {
        #[must_use]
        pub const fn size() -> usize {
            2 * PARAM_Q_LENGTH_BYTES
        }

        #[must_use]
        pub const fn parameter_size() -> usize {
            PARAM_Q_LENGTH_BYTES
        }

        #[must_use]
        pub fn from_components(r: BigUint, s: BigUint) -> Self {
            Self(dsa::Signature::from_components(r, s))
        }

        #[must_use]
        pub fn r(&self) -> &BigUint {
            self.0.r()
        }

        #[must_use]
        pub fn s(&self) -> &BigUint {
            self.0.s()
        }
    }
}

#[allow(non_snake_case)]
pub mod sha1 {
    type Digest = [u8; 20];

    #[must_use]
    pub fn digest(data: &[u8]) -> Digest {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        let mut result: Digest = [0u8; 20];
        result.clone_from_slice(digest.as_ref());
        result
    }

    #[must_use]
    pub fn hmac(mk: &[u8], data: &[u8]) -> Digest {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, mk);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 20];
        result.clone_from_slice(digest.as_ref());
        result
    }
}

#[allow(non_snake_case)]
pub mod sha256 {
    type Digest = [u8; 32];

    #[must_use]
    pub fn digest_with_prefix(b: u8, data: &[u8]) -> Digest {
        let mut payload: Vec<u8> = Vec::with_capacity(data.len() + 1);
        payload.push(b);
        payload.extend_from_slice(data);
        digest(&payload)
    }

    #[must_use]
    pub fn digest_2_with_prefix(b: u8, data: &[u8], data2: &[u8]) -> Digest {
        let mut payload: Vec<u8> = Vec::with_capacity(1 + data.len() + data2.len());
        payload.push(b);
        payload.extend_from_slice(data);
        payload.extend_from_slice(data2);
        digest(&payload)
    }

    /// digest calculates the SHA256 digest value.
    #[must_use]
    pub fn digest(data: &[u8]) -> Digest {
        let digest = ring::digest::digest(&ring::digest::SHA256, data);
        let mut result = [0u8; 32];
        result.clone_from_slice(digest.as_ref());
        result
    }

    /// hmac calculates the SHA256-HMAC value, using key 'm1' as documented in OTR version 3 spec.
    #[must_use]
    pub fn hmac(m1: &[u8], data: &[u8]) -> Digest {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m1);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 32];
        result.clone_from_slice(digest.as_ref());
        result
    }

    /// hmac160 calculates the first 160 bits of the SHA256-HMAC value, using key 'm2' as documented in OTR version 3 spec.
    #[must_use]
    pub fn hmac160(m2: &[u8], data: &[u8]) -> [u8; 20] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m2);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 20];
        result.clone_from_slice(&digest.as_ref()[..20]);
        result
    }
}

pub mod otr4 {
    use num_bigint::BigUint;

    use crate::utils;

    use super::{dh3072, ed448, shake256, CryptoError};

    pub const K_LENGTH_BYTES: usize = 64;
    pub const ROOT_KEY_LENGTH_BYTES: usize = 64;
    const BRACE_KEY_LENGTH_BYTES: usize = 32;
    const CHAIN_KEY_LENGTH_BYTES: usize = 64;

    const USAGE_FINGERPRINT: u8 = 0x00;
    pub const USAGE_THIRD_BRACE_KEY: u8 = 0x01;
    const USAGE_BRACE_KEY: u8 = 0x02;
    const USAGE_SHARED_SECRET: u8 = 0x03;
    pub const USAGE_SSID: u8 = 0x04;
    pub const USAGE_AUTH_R_BOB_CLIENT_PROFILE: u8 = 0x05;
    pub const USAGE_AUTH_R_ALICE_CLIENT_PROFILE: u8 = 0x06;
    pub const USAGE_AUTH_R_PHI: u8 = 0x07;
    pub const USAGE_AUTH_I_BOB_CLIENT_PROFILE: u8 = 0x08;
    pub const USAGE_AUTH_I_ALICE_CLIENT_PROFILE: u8 = 0x09;
    pub const USAGE_AUTH_I_PHI: u8 = 0x0A;
    pub const USAGE_FIRST_ROOT_KEY: u8 = 0x0B;
    //const USAGE_TMP_KEY: u8 = 0x0C;
    //const USAGE_AUTH_MAC_KEY: u8 = 0x0D;
    //const USAGE_NONINT_AUTH_BOB_CLIENT_PROFILE: u8 = 0x0E;
    //const USAGE_NONINT_AUTH_ALICE_CLIENT_PROFILE: u8 = 0x0F;
    //const USAGE_NONINT_AUTH_PHI: u8 = 0x10;
    //const USAGE_AUTH_MAC: u8 = 0x11;
    const USAGE_ROOT_KEY: u8 = 0x12;
    const USAGE_CHAIN_KEY: u8 = 0x13;
    //const USAGE_NEXT_CHAIN_KEY: u8 = 0x14;
    //const USAGE_MESSAGE_KEY: u8 = 0x15;
    //const USAGE_MAC_KEY: u8 = 0x16;
    //const USAGE_EXTRA_SYMMETRIC_KEY: u8 = 0x17;
    //const USAGE_AUTHENTICATOR: u8 = 0x18;
    pub const USAGE_SMP_SECRET: u8 = 0x19;
    pub const USAGE_AUTH: u8 = 0x1A;

    const PREFIX: [u8; 5] = [b'O', b'T', b'R', b'v', b'4'];

    pub struct DoubleRatchet {
        shared_secret: MixedSharedSecret,
        root_key: [u8; 64],
        sender: Ratchet,
        receiver: Ratchet,
        next: Selector,
        i: u32,
        pn: u32,
    }

    impl DoubleRatchet {
        #[must_use]
        pub fn initialize(
            selector: &Selector,
            shared_secret: MixedSharedSecret,
            prev_root_key: [u8; ROOT_KEY_LENGTH_BYTES],
        ) -> Self {
            let k = shared_secret.k();
            let root_key = kdf_2::<ROOT_KEY_LENGTH_BYTES>(USAGE_ROOT_KEY, &prev_root_key, &k);
            // FIXME shouldn't use `k` here below again. Should be replaced.
            let (sender, receiver, next) = match selector {
                Selector::SENDER => (
                    Ratchet::new(&prev_root_key, &k),
                    Ratchet::dummy(),
                    Selector::RECEIVER,
                ),
                Selector::RECEIVER => (
                    Ratchet::dummy(),
                    Ratchet::new(&prev_root_key, &k),
                    Selector::SENDER,
                ),
            };
            Self {
                shared_secret,
                root_key,
                sender,
                receiver,
                next,
                i: 0,
                pn: 0,
            }
        }

        #[must_use]
        pub fn next(&self) -> &Selector {
            &self.next
        }
    }

    struct Ratchet {
        chain_key: [u8; CHAIN_KEY_LENGTH_BYTES],
        message_id: u32,
    }

    impl Ratchet {
        fn new(prev_root_key: &[u8; ROOT_KEY_LENGTH_BYTES], k: &[u8; K_LENGTH_BYTES]) -> Self {
            Self {
                chain_key: kdf_2(USAGE_CHAIN_KEY, prev_root_key, k),
                message_id: 0,
            }
        }

        fn dummy() -> Self {
            // TODO ensure that assertions for any non-zero bytes are in place.
            Self {
                chain_key: [0u8; CHAIN_KEY_LENGTH_BYTES],
                message_id: 0,
            }
        }
    }

    /// `Selector` is the selector for a specific ratchet, i.e. Sender or Receiver.
    pub enum Selector {
        SENDER,
        RECEIVER,
    }

    /// `MixedSharedSecret` represents the OTRv4 mixed shared secret value.
    pub struct MixedSharedSecret {
        ecdh: ed448::KeyPair,
        dh: dh3072::KeyPair,
        public_ecdh: ed448::Point,
        public_dh: BigUint,
        brace_key: [u8; BRACE_KEY_LENGTH_BYTES],
        k: [u8; K_LENGTH_BYTES],
    }

    impl MixedSharedSecret {
        /// `new` constructs the next rotation of the mixed shared secret.
        ///
        /// # Errors
        /// In case of invalid key material.
        pub fn new(
            ecdh0: ed448::KeyPair,
            dh0: dh3072::KeyPair,
            public_ecdh: ed448::Point,
            public_dh: BigUint,
        ) -> Result<Self, CryptoError> {
            Self::next(
                ecdh0,
                dh0,
                public_ecdh,
                public_dh,
                true,
                [0u8; BRACE_KEY_LENGTH_BYTES],
            )
        }

        fn next(
            ecdh: ed448::KeyPair,
            dh: dh3072::KeyPair,
            public_ecdh: ed448::Point,
            public_dh: BigUint,
            third: bool,
            brace_key_prev: [u8; BRACE_KEY_LENGTH_BYTES],
        ) -> Result<Self, CryptoError> {
            ed448::verify(&public_ecdh)?;
            dh3072::verify(&public_dh)?;
            // FIXME verification
            let secret_ecdh = ecdh.generate_shared_secret(&public_ecdh).encode();
            let brace_key = if third {
                let secret_dh =
                    utils::biguint::to_bytes_le_fixed::<57>(&dh.generate_shared_secret(&public_dh));
                kdf(USAGE_THIRD_BRACE_KEY, &secret_dh)
            } else {
                assert!(utils::bytes::any_nonzero(&brace_key_prev));
                kdf(USAGE_BRACE_KEY, &brace_key_prev)
            };
            let k = kdf_2::<K_LENGTH_BYTES>(USAGE_SHARED_SECRET, &secret_ecdh, &brace_key);
            // FIXME key material needs clearing/cleaning up
            Ok(Self {
                ecdh,
                dh,
                public_ecdh,
                public_dh,
                brace_key,
                k,
            })
        }

        #[must_use]
        pub fn k(&self) -> [u8; K_LENGTH_BYTES] {
            self.k
        }
    }

    #[must_use]
    pub fn fingerprint(public_key: &ed448::Point, forging_key: &ed448::Point) -> [u8; 56] {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&public_key.encode());
        buffer.extend_from_slice(&forging_key.encode());
        hwc::<56>(USAGE_FINGERPRINT, &buffer)
    }

    #[must_use]
    pub fn hwc<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        kdf::<N>(usage, data)
    }

    #[must_use]
    pub fn hcmac<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        kdf::<N>(usage, data)
    }

    #[must_use]
    pub fn kdf<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        let mut buffer = Vec::with_capacity(6 + data.len());
        buffer.extend_from_slice(&PREFIX);
        buffer.push(usage);
        buffer.extend_from_slice(data);
        shake256::digest::<N>(&buffer)
    }

    #[must_use]
    pub fn kdf_2<const N: usize>(usage: u8, data1: &[u8], data2: &[u8]) -> [u8; N] {
        let mut buffer = Vec::with_capacity(6 + data1.len() + data2.len());
        buffer.extend_from_slice(&PREFIX);
        buffer.push(usage);
        buffer.extend_from_slice(data1);
        buffer.extend_from_slice(data2);
        shake256::digest::<N>(&buffer)
    }
}

mod shake256 {
    use digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;

    /// digest hashes `data` and produces an output digest in `output`, taking into account the size
    /// of the buffer.
    #[must_use]
    pub fn digest<const N: usize>(data: &[u8]) -> [u8; N] {
        let mut hasher = Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; N];
        reader.read(&mut output);
        output
    }
}

// FIXME I am not fully confident that the changes made to avoid negative values are correct. Needs interop testing and/or review. (E.g. `D` -> `-39081 =?= P-39081`, holds for multiplication? -- likely yes)
pub mod ed448 {
    use std::{
        ops::{Add, Mul, Neg},
        str::FromStr,
    };

    use num_bigint::{BigInt, BigUint, ModInverse, ToBigInt};
    use num_integer::Integer;
    use once_cell::sync::Lazy;
    use zeroize::Zeroize;

    use crate::{
        crypto::otr4::{hwc, USAGE_AUTH},
        encoding::{OTRDecoder, OTREncodable, OTREncoder},
        utils::{self, bigint::ONE, bytes},
        OTRError,
    };

    use super::{constant, shake256, CryptoError};

    pub const LENGTH_BYTES: usize = 57;

    // G = (x=22458004029592430018760433409989603624678964163256413424612546168695
    //        0415467406032909029192869357953282578032075146446173674602635247710,
    //      y=29881921007848149267601793044393067343754404015408024209592824137233
    //        1506189835876003536878655418784733982303233503462500531545062832660)
    static G: Lazy<Point> = Lazy::new(|| {
        Point{
        x: BigUint::from_str("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710").unwrap(),
        y: BigUint::from_str("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660").unwrap(),
    }
    });

    /// `I` is the neutral element, or identity.
    static I: Lazy<Point> = Lazy::new(|| Point {
        x: (*utils::biguint::ZERO).clone(),
        y: (*utils::biguint::ONE).clone(),
    });

    /// p, the modulus
    static P: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_str("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439").unwrap()
    });

    /// q, the prime order
    static Q: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_str("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779").unwrap()
    });

    /// d, '-39081'
    static D: Lazy<BigUint> = Lazy::new(|| &*P - &BigUint::from_str("39081").unwrap());

    /// `generator` returns the Ed448 base-point.
    #[must_use]
    pub fn generator() -> &'static Point {
        &G
    }

    #[must_use]
    pub fn identity() -> &'static Point {
        &I
    }

    /// `modulus` returns the Ed448 modulus
    #[must_use]
    pub fn modulus() -> &'static BigUint {
        &P
    }

    /// `prime_order` provides the prime order value `q`.
    #[must_use]
    pub fn prime_order() -> &'static BigUint {
        &Q
    }

    #[derive(Clone)]
    pub struct PublicKey(Point);

    impl OTREncodable for PublicKey {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write_u16_le(0x0010);
            encoder.write_ed448_point(&self.0);
        }
    }

    impl PublicKey {
        /// `decode` decodes a public key from its OTR-encoding.
        ///
        /// # Errors
        /// In case of bad input data.
        pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
            if decoder.read_u16_le()? != 0x0010 {
                return Err(OTRError::ProtocolViolation(
                    "Expected public key type: 0x0010",
                ));
            }
            Ok(Self(decoder.read_ed448_point()?))
        }

        /// `from` extracts the public key from encoded point data.
        ///
        /// # Errors
        /// In case of bad input data.
        pub fn from(bytes: &[u8; 57]) -> Result<Self, OTRError> {
            Ok(Self(
                Point::decode(bytes).map_err(OTRError::CryptographicViolation)?,
            ))
        }

        #[must_use]
        pub fn point(&self) -> &Point {
            &self.0
        }
    }

    // NOTE: there is also the Ed448 Preshared PreKey (type 0x0011). Not yet implemented.

    pub struct ForgingKey(Point);

    impl OTREncodable for ForgingKey {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write_u16_le(0x0012);
            encoder.write_ed448_point(&self.0);
        }
    }

    impl ForgingKey {
        /// `from` extracts the forging key from encoded point data.
        ///
        /// # Errors
        /// In case of bad input data.
        pub fn from(data: &[u8; 57]) -> Result<Self, OTRError> {
            Ok(Self(
                Point::decode(data).map_err(OTRError::CryptographicViolation)?,
            ))
        }
    }

    #[derive(Clone)]
    pub struct Signature([u8; 2 * LENGTH_BYTES]);

    impl OTREncodable for Signature {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write(&self.0);
        }
    }

    impl Signature {
        #[must_use]
        pub fn from(data: [u8; 2 * LENGTH_BYTES]) -> Self {
            Self(data)
        }
    }

    /// `verify` checks the provided Point for correctness.
    ///
    /// # Errors
    /// Error in case point fails verification.
    pub fn verify(point: &Point) -> Result<(), CryptoError> {
        if point.is_identity()
            || point.x.cmp(&*P).is_ge()
            || point.y.cmp(&*P).is_ge()
            || !(point * &*Q).is_identity()
        {
            return Err(CryptoError::VerificationFailure(
                "Point does not satisfy required conditions",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn hash_point_to_scalar(purpose: u8, point: &Point) -> BigUint {
        hash_to_scalar(purpose, &point.encode())
    }

    #[must_use]
    pub fn hash_point_to_scalar2(purpose: u8, point1: &Point, point2: &Point) -> BigUint {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&point1.encode());
        buffer.extend_from_slice(&point2.encode());
        hash_to_scalar(purpose, &buffer)
    }

    // TODO pruning is not strictly necessary because the scalars resulting from hash_to_scalar are not used on the curve, merely as proofs.
    #[must_use]
    pub fn hash_to_scalar(purpose: u8, data: &[u8]) -> BigUint {
        decode_scalar(&hwc::<57>(purpose, data))
    }

    /// `decode_scalar` decodes an encoded scalar into `BigUint`.
    ///
    /// # Panics
    /// Panics if all bytes are zero. (sanity-check)
    #[must_use]
    pub fn decode_scalar(encoded: &[u8; 57]) -> BigUint {
        assert!(utils::bytes::any_nonzero(encoded));
        BigUint::from_bytes_le(encoded).mod_floor(&*Q)
    }

    // TODO currently cloning the keypair to re-obtain ownership. Is there a way to avoid that without too much borrow checker complexity?
    #[derive(Clone)]
    pub struct KeyPair(BigUint, Point);

    impl KeyPair {
        /// `generate` generates a key pair for Ed448 ECDH.
        #[must_use]
        pub fn generate() -> Self {
            let r = random_in_Zq();
            let mut buffer = shake256::digest::<114>(&r.to_bytes_le());
            prune(&mut buffer);
            let s = BigUint::from_bytes_le(&buffer);
            // FIXME securely delete r, h
            let public = (&*G) * &s;
            KeyPair(s, public)
        }

        #[must_use]
        pub fn public(&self) -> &Point {
            &self.1
        }

        #[must_use]
        pub fn generate_shared_secret(&self, other: &Point) -> Point {
            other * &self.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Point {
        x: BigUint,
        y: BigUint,
    }

    impl Drop for Point {
        fn drop(&mut self) {
            self.x.zeroize();
            self.y.zeroize();
        }
    }

    impl Mul<BigUint> for Point {
        type Output = Self;

        fn mul(self, rhs: BigUint) -> Self::Output {
            self.mul0(&rhs)
        }
    }

    impl<'b> Mul<&'b BigUint> for Point {
        type Output = Self;

        fn mul(self, scalar: &'b BigUint) -> Self::Output {
            self.mul0(scalar)
        }
    }

    impl<'a, 'b> Mul<&'b BigUint> for &'a Point {
        type Output = Point;

        // TODO implementation of scalar multiplication is not constant-time
        fn mul(self, scalar: &'b BigUint) -> Self::Output {
            self.mul0(scalar)
        }
    }

    impl Add<Point> for Point {
        type Output = Self;

        fn add(self, rhs: Point) -> Self::Output {
            self.add0(&rhs)
        }
    }

    impl<'b> Add<&'b Point> for Point {
        type Output = Self;

        fn add(self, rhs: &'b Point) -> Self::Output {
            self.add0(rhs)
        }
    }

    impl<'a, 'b> Add<&'b Point> for &'a Point {
        type Output = Point;

        fn add(self, rhs: &'b Point) -> Self::Output {
            self.add0(rhs)
        }
    }

    impl<'a> Neg for &'a Point {
        type Output = Point;

        fn neg(self) -> Self::Output {
            Point {
                x: &*P - &self.x,
                y: self.y.clone(),
            }
        }
    }

    impl Point {
        // TODO implementation of scalar multiplication is not constant-time
        fn mul0(&self, scalar: &BigUint) -> Point {
            let mut result = Point {
                x: utils::biguint::ZERO.clone(),
                y: utils::biguint::ONE.clone(),
            };
            let mut temp: Point = self.clone();
            for i in 0..scalar.bits() {
                if utils::biguint::bit(scalar, i) {
                    result = result.add0(&temp);
                }
                temp = temp.add0(&temp);
            }
            result
        }

        // TODO need to check if biguint -> bigint -> biguint conversions are expensive.
        fn add0(&self, rhs: &Point) -> Point {
            if self.is_identity() {
                return rhs.clone();
            }
            if rhs.is_identity() {
                return self.clone();
            }
            // FIXME rewrite to do this with `BigUint` instead of conversion to `BigInt` and back.
            let lhs_x = self.x.to_bigint().unwrap();
            let lhs_y = self.y.to_bigint().unwrap();
            let rhs_x = rhs.x.to_bigint().unwrap();
            let rhs_y = rhs.y.to_bigint().unwrap();
            let result_x: BigInt = &(&lhs_x * &rhs_y + &lhs_y * &rhs_x)
                * (&*ONE + &(&*D * &lhs_x * &rhs_x * &lhs_y * &rhs_y))
                    .mod_inverse(&*P)
                    .unwrap();
            let result_y: BigInt = &(&lhs_y * &rhs_y - &lhs_x * &rhs_x)
                * (&*ONE - &(&*D * &lhs_x * &rhs_x * &lhs_y * &rhs_y))
                    .mod_inverse(&*P)
                    .unwrap();
            Point {
                x: result_x
                    .mod_floor(&P.to_bigint().unwrap())
                    .to_biguint()
                    .unwrap(),
                y: result_y
                    .mod_floor(&P.to_bigint().unwrap())
                    .to_biguint()
                    .unwrap(),
            }
        }

        /// `decode` decodes an encoded Ed448 Point and returns an instance iff correct.
        ///
        /// # Errors
        /// Returns an error in case the encoded point contains bad data, therefore it is impossible
        /// to reconstruct a (valid) point.
        ///
        /// # Panics
        /// Panics if there are bugs.
        pub fn decode(encoded: &[u8; 57]) -> Result<Point, CryptoError> {
            let x_bit = (encoded[56] & 0b1000_0000) >> 7;
            let y = BigUint::from_bytes_le(&encoded[..56]);
            if y.cmp(&*P).is_ge() {
                return Err(CryptoError::VerificationFailure(
                    "Encoded point contains illegal y component",
                ));
            }
            let num = (&y * &y - &*utils::biguint::ONE).mod_floor(&*P);
            let denom = (&y * &y * &*D - &*utils::biguint::ONE).mod_floor(&*P);
            // REMARK the `exponent` for `modpow` could be precomputed.
            let x = (&num
                * &num
                * &num
                * &denom
                * (&num * &num * &num * &num * &num * &denom * &denom * &denom).modpow(
                    &((&*P - &*utils::biguint::THREE) / &*utils::biguint::FOUR),
                    &P,
                ))
            .mod_floor(&*P);
            if num != (&x * &x * &denom).mod_floor(&*P) {
                return Err(CryptoError::VerificationFailure(
                    "Encoded point: no square root exists",
                ));
            }
            if x == *utils::biguint::ZERO && x_bit != 0 {
                return Err(CryptoError::VerificationFailure(
                    "Encoded point: sign-bit is 1 for x = 0",
                ));
            }
            if x.is_even() == (x_bit == 0) {
                Ok(Point { x, y })
            } else {
                Ok(Point { x: (&*P - x), y })
            }
        }

        /// `encode` encodes an Ed448 Point into bytes.
        ///
        /// # Panics
        /// In case of bugs.
        #[must_use]
        pub fn encode(&self) -> [u8; 57] {
            let mut encoded = utils::biguint::to_bytes_le_fixed::<57>(&self.y);
            assert_eq!(0, encoded[56]);
            let x_bytes = self.x.to_bytes_le();
            let x_bit = if x_bytes.is_empty() {
                0
            } else {
                x_bytes[0] & 0x1
            };
            encoded[56] |= x_bit << 7;
            encoded
        }

        #[must_use]
        pub fn is_identity(&self) -> bool {
            self.x == *utils::biguint::ZERO && self.y == *utils::biguint::ONE
        }
    }

    // FIXME Ring signatures and other BigUint code (SMP4) is really waaaaay too slow. (undoubtedly my own fault)
    #[derive(Clone)]
    pub struct RingSignature {
        c1: BigUint,
        r1: BigUint,
        c2: BigUint,
        r2: BigUint,
        c3: BigUint,
        r3: BigUint,
    }

    impl OTREncodable for RingSignature {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder
                .write_ed448_scalar(&self.c1)
                .write_ed448_scalar(&self.r1)
                .write_ed448_scalar(&self.c2)
                .write_ed448_scalar(&self.r2)
                .write_ed448_scalar(&self.c3)
                .write_ed448_scalar(&self.r3);
        }
    }

    impl RingSignature {
        /// `decode` decodes the bytes of an encoded ring signature to its individual numerical
        /// components. Returning the composite structure as a result.
        ///
        /// # Errors
        /// Error in case we fail to read any of the components.
        pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
            let c1 = decoder.read_ed448_scalar()?;
            let r1 = decoder.read_ed448_scalar()?;
            let c2 = decoder.read_ed448_scalar()?;
            let r2 = decoder.read_ed448_scalar()?;
            let c3 = decoder.read_ed448_scalar()?;
            let r3 = decoder.read_ed448_scalar()?;
            Ok(Self {
                c1,
                r1,
                c2,
                r2,
                c3,
                r3,
            })
        }

        /// `verify` verifies a ring signature against the expected data.
        ///
        /// # Errors
        /// In case of verification failure.
        #[allow(non_snake_case)]
        pub fn verify(
            &self,
            A1: &Point,
            A2: &Point,
            A3: &Point,
            m: &[u8],
        ) -> Result<(), CryptoError> {
            let T1 = &*G * &self.r1 + A1 * &self.c1;
            let T2 = &*G * &self.r2 + A2 * &self.c2;
            let T3 = &*G * &self.r3 + A3 * &self.c3;
            let c = hash_to_scalar(
                USAGE_AUTH,
                &OTREncoder::new()
                    .write_ed448_point(&G)
                    .write_ed448_scalar(&Q)
                    .write_ed448_point(A1)
                    .write_ed448_point(A2)
                    .write_ed448_point(A3)
                    .write_ed448_point(&T1)
                    .write_ed448_point(&T2)
                    .write_ed448_point(&T3)
                    .write_data(m)
                    .to_vec(),
            );
            // FIXME make constant-time comparison, selection
            constant::compare_scalars_distinct(&c, &(&self.c1 + &self.c2 + &self.c3).mod_floor(&*Q))
        }

        /// `sign` generates a ring signature.
        ///
        /// # Errors
        /// In case of failure to generate ring signature.
        ///
        /// # Panics
        /// In case of implementation errors (bad usage).
        #[allow(non_snake_case, clippy::similar_names)]
        pub fn sign(
            keypair: &KeyPair,
            A1: &Point,
            A2: &Point,
            A3: &Point,
            m: &[u8],
        ) -> Result<Self, CryptoError> {
            verify(A1)?;
            verify(A2)?;
            verify(A3)?;
            let eq1 = constant::compare_points(&keypair.1, A1).is_ok();
            let eq2 = constant::compare_points(&keypair.1, A2).is_ok();
            let eq3 = constant::compare_points(&keypair.1, A3).is_ok();
            match (eq1, eq2, eq3) {
                (true, false, false) | (false, true, false) | (false, false, true) => {}
                _ => panic!("BUG: illegal combination of public keys."),
            }
            let t = random_in_Zq();
            let c1 = random_in_Zq();
            let c2 = random_in_Zq();
            let c3 = random_in_Zq();
            let r1 = random_in_Zq();
            let r2 = random_in_Zq();
            let r3 = random_in_Zq();
            // FIXME make constant-time comparison, selection
            let (T1, T2, T3) = match (eq1, eq2, eq3) {
                (true, false, false) => (&*G * &t, &*G * &r2 + A2 * &c2, &*G * &r3 + A3 * &c3),
                (false, true, false) => (&*G * &r1 + A1 * &c1, &*G * &t, &*G * &r3 + A3 * &c3),
                (false, false, true) => (&*G * &r1 + A1 * &c1, &*G * &r2 + A2 * &c2, &*G * &t),
                _ => panic!("BUG: illegal combination of public keys."),
            };
            let c = hash_to_scalar(
                USAGE_AUTH,
                &OTREncoder::new()
                    .write_ed448_point(&G)
                    .write_ed448_scalar(&Q)
                    .write_ed448_point(A1)
                    .write_ed448_point(A2)
                    .write_ed448_point(A3)
                    .write_ed448_point(&T1)
                    .write_ed448_point(&T2)
                    .write_ed448_point(&T3)
                    .write_data(m)
                    .to_vec(),
            );
            // TODO "The order of elements passed to `H` and sent to the verifier must not depend on the secret known by the prover (otherwise, the key used to produce the proof can be inferred in practice)."
            let sigma = match (eq1, eq2, eq3) {
                (true, false, false) => {
                    //let c1 = &c - &c2 - &c3;
                    let c1_derived = (&c + &*Q - &c2 + &*Q - &c3).mod_floor(&*Q);
                    //let r1 = &t - &c1 * &keypair.0;
                    let r1_derived =
                        (&t + &*Q - &(&c1_derived * &keypair.0).mod_floor(&*Q)).mod_floor(&*Q);
                    Self {
                        c1: c1_derived,
                        r1: r1_derived,
                        c2,
                        r2,
                        c3,
                        r3,
                    }
                }
                (false, true, false) => {
                    //let c2 = &c - &c1 - &c3;
                    let c2_derived = (&c + &*Q - &c1 + &*Q - &c3).mod_floor(&*Q);
                    //let r2 = &t - &c2 * &keypair.0;
                    let r2_derived =
                        (&t + &*Q - &(&c2_derived * &keypair.0).mod_floor(&*Q)).mod_floor(&*Q);
                    Self {
                        c1,
                        r1,
                        c2: c2_derived,
                        r2: r2_derived,
                        c3,
                        r3,
                    }
                }
                (false, false, true) => {
                    //let c3 = &c - &c1 - &c2;
                    let c3_derived = (&c + &*Q - &c1 + &*Q - &c2).mod_floor(&*Q);
                    //let r3 = &t - &c3 * &keypair.0;
                    let r3_derived =
                        (&t + &*Q - &(&c3_derived * &keypair.0).mod_floor(&*Q)).mod_floor(&*Q);
                    Self {
                        c1,
                        r1,
                        c2,
                        r2,
                        c3: c3_derived,
                        r3: r3_derived,
                    }
                }
                _ => panic!("BUG: should not reach here."),
            };
            // TODO securely delete t
            Ok(sigma)
        }
    }

    /// `random_in_Zq` generates a random value in Z_q and returns this as `BigUint` unsigned
    /// integer value. The value is pruned as to be guaranteed safe for use in curve Ed448.
    ///
    /// # Panics
    /// Panics if invalid input data is provided. (sanity-checks)
    // TODO is non-zero value a hard requirement? If so, change assert into a retry-loop.
    #[allow(non_snake_case)]
    #[must_use]
    pub fn random_in_Zq() -> BigUint {
        let mut h = shake256::digest::<57>(&utils::random::secure_bytes::<57>());
        // TODO all-zero is possible but very unlikely. Maybe remove the assertion, as pruning will ensure there are non-zero bytes, but it would be highly suspicious nonetheless.
        assert!(bytes::any_nonzero(&h));
        prune(&mut h);
        let v = decode_scalar(&h);
        utils::bytes::clear(&mut h);
        v
    }

    /// `prune` prunes any byte-array representing a little-endian encoded scalar value to ensure
    /// that the scalar, when decoded, produces a valid scalar value. `v` must be at least 57 bytes
    /// in size.
    ///
    /// # Panics
    /// Panics if invalid input is provided. (sanity-checks)
    pub fn prune(v: &mut [u8]) {
        assert!(v.len() >= 57);
        assert!(bytes::any_nonzero(v));
        v[0] &= 0b1111_1100;
        v[55] |= 0b1000_0000;
        v[56] = 0;
    }
}

// FIXME change name to refer to group identifier or something from otrv4
pub mod dh3072 {
    use num_bigint::BigUint;
    use once_cell::sync::Lazy;

    use crate::utils;

    use super::CryptoError;

    /// p is the prime (modulus).
    pub static P: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_radix_be(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16).unwrap()
    });

    /// g3 is the generator
    pub static G3: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u8));

    // TODO check if cofactor is needed.
    pub const COFACTOR: u8 = 2;

    // TODO why is this called subprime, isn't it the order?
    /// q is the subprime.
    pub static Q: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_radix_be(b"7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880AB9472D45556216D6998B8682283D19D42A90D5EF8E5D32767DC2822C6DF785457538ABAE83063ED9CB87C2D370F263D5FAD7466D8499EB8F464A702512B0CEE771E9130D697735F897FD036CC504326C3B01399F643532290F958C0BBD90065DF08BABBD30AEB63B84C4605D6CA371047127D03A72D598A1EDADFE707E884725C16890549D69657FFFFFFFFFFFFFFF", 16).unwrap()
    });

    /// `verify` verifies a 3072-bit DH element to confirm that it satisfies the requirements of the
    /// group.
    ///
    /// # Errors
    /// In case `v` fails verification.
    pub fn verify(v: &BigUint) -> Result<(), CryptoError> {
        if v < &G3 || v > &(&*P - &*G3) || v.modpow(&Q, &P) != *utils::biguint::ONE {
            return Err(CryptoError::VerificationFailure("element is invalid"));
        }
        Ok(())
    }

    /// `KeyPair` is a 3072 DH keypair.
    // TODO currently cloning the keypair to re-obtain ownership. Is there a way to avoid that without too much borrow checker complexity?
    #[derive(Clone)]
    pub struct KeyPair {
        private: BigUint,
        public: BigUint,
    }

    impl KeyPair {
        #[must_use]
        pub fn generate() -> Self {
            let bytes = utils::random::secure_bytes::<80>();
            let private = BigUint::from_bytes_be(&bytes);
            let public = G3.modpow(&private, &P);
            Self { private, public }
        }

        #[must_use]
        pub fn public(&self) -> &BigUint {
            &self.public
        }

        #[must_use]
        pub fn generate_shared_secret(&self, other: &BigUint) -> BigUint {
            &self.private * other
        }
    }
}

/// `constant` module provides constant-time operations.
// TODO check at some moment that it's okay to encode points/scalars to preserve proper constant-time guarantees.
pub mod constant {
    use num_bigint::BigUint;

    use super::{ed448, verify_nonzero, CryptoError};

    /// `compare_different_scalars` compares two scalars in constant-time by encoding them then
    /// constant-time-comparing the byte-arrays.
    ///
    /// # Errors
    /// Error in case scalars fail verification.
    ///
    /// # Panics
    /// Panics if instances `s1` and `s2` are the same.
    // FIXME need better name, 'distinct' bytes?
    pub fn compare_scalars_distinct(s1: &BigUint, s2: &BigUint) -> Result<(), CryptoError> {
        assert!(!core::ptr::eq(s1, s2), "BUG: s1 and s2 are same instance");
        compare(
            &s1.to_bytes_le(),
            &s2.to_bytes_le(),
            "verification of scalars failed",
        )
    }

    /// `compare_scalars` compares two scalars in constant time and returns result.
    ///
    /// # Errors
    /// In case comparison fails, i.e. scalars are not equal.
    pub fn compare_scalars(s1: &BigUint, s2: &BigUint) -> Result<(), CryptoError> {
        compare(
            &s1.to_bytes_le(),
            &s2.to_bytes_le(),
            "verification of scalars failed",
        )
    }

    /// `compare_different_points` checks if two points are the same in constant-time by comparing
    /// the byte-arrays of the encoded points in constant-time.
    ///
    /// # Errors
    /// Error in case points fail verification.
    ///
    /// # Panics
    /// Panics if instances `p1` and `p2` are the same.
    // FIXME need better name, 'distinct' bytes?
    pub fn compare_points_distinct(
        p1: &ed448::Point,
        p2: &ed448::Point,
    ) -> Result<(), CryptoError> {
        assert!(!core::ptr::eq(p1, p2), "BUG: p1 and p2 are same instance");
        compare(&p1.encode(), &p2.encode(), "verification of points failed")
    }

    /// `compare_points` compares two points in constant time.
    ///
    /// # Errors
    /// In case points fail comparison, i.e. are not equal.
    pub fn compare_points(p1: &ed448::Point, p2: &ed448::Point) -> Result<(), CryptoError> {
        compare(&p1.encode(), &p2.encode(), "verification of points failed")
    }

    /// `compare_different_bytes` verifies two same-length byte-slices in constant-time.
    ///
    /// # Errors
    /// `CryptoError` in case verification fails. Failure-cases: provide same instance twice,
    /// provide all-zero byte-arrays, provide equal slices.
    ///
    /// # Panics
    /// Panics if two provided byte-slices are same instance. (To prevent accidental programming errors.)
    // FIXME need better name, 'distinct' bytes?
    pub fn compare_bytes_distinct(data1: &[u8], data2: &[u8]) -> Result<(), CryptoError> {
        assert!(
            !core::ptr::eq(data1, data2),
            "BUG: data1 and data2 parameters are same instance"
        );
        compare(data1, data2, "verification of bytes failed")
    }

    /// `compare_bytes` compares two byte-arrays in constant-time.
    ///
    /// # Errors
    /// In case comparison fails, i.e. byte-arrays are not equal.
    pub fn compare_bytes(data1: &[u8], data2: &[u8]) -> Result<(), CryptoError> {
        compare(data1, data2, "verification of bytes failed")
    }

    fn compare(data1: &[u8], data2: &[u8], msg: &'static str) -> Result<(), CryptoError> {
        verify_nonzero(data1)?;
        verify_nonzero(data2)?;
        ring::constant_time::verify_slices_are_equal(data1, data2)
            .or(Err(CryptoError::VerificationFailure(msg)))
    }
}

fn verify_nonzero(data: &[u8]) -> Result<(), CryptoError> {
    utils::bytes::verify_nonzero(data, CryptoError::VerificationFailure("all zero-bytes"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    VerificationFailure(&'static str),
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{self},
        utils::{
            self,
            biguint::{ONE, TWO, ZERO},
        },
    };
    use num_bigint::BigUint;

    use super::{
        constant, dh,
        ed448::{self, RingSignature},
        CryptoError,
    };

    #[test]
    fn test_dh_verify_homogenous() {
        let v1 = BigUint::from(7u8);
        let v2 = BigUint::from(7u8);
        let v3 = BigUint::from(9u8);
        assert!(dh::verify(&v1, &v2).is_ok());
        assert!(dh::verify(&v2, &v1).is_ok());
        assert!(dh::verify(&v1, &v3).is_err());
        assert!(dh::verify(&v2, &v3).is_err());
        assert!(dh::verify(&v3, &v1).is_err());
        assert!(dh::verify(&v3, &v2).is_err());
    }

    #[test]
    fn test_dh_verify_heterogenous() {
        let v1 = BigUint::from(7u8);
        let v2 = BigUint::from(7u16);
        assert!(dh::verify(&v1, &v2).is_ok());
        assert!(dh::verify(&v2, &v1).is_ok());
    }

    #[test]
    #[should_panic]
    #[allow(unused_must_use)]
    fn test_dh_verify_panic_on_same() {
        let v1 = BigUint::from(7u8);
        dh::verify(&v1, &v1);
    }

    #[test]
    fn test_dh_general_expectations() {
        assert_eq!(dh::generator(), dh::generator());
        assert_eq!(dh::modulus(), dh::modulus());
        assert_eq!(dh::q(), dh::q());
        let k1 = dh::Keypair::generate();
        assert!(dh::verify_public_key(k1.public()).is_ok());
        let k2 = dh::Keypair::generate();
        assert!(dh::verify_public_key(k2.public()).is_ok());
        let k3 = dh::Keypair::generate();
        assert!(dh::verify_public_key(k3.public()).is_ok());
        let k4 = dh::Keypair::generate();
        assert!(dh::verify_public_key(k4.public()).is_ok());
        let k5 = dh::Keypair::generate();
        assert!(dh::verify_public_key(k5.public()).is_ok());
        assert_ne!(k1.public(), k2.public());
        assert_ne!(k2.public(), k3.public());
        assert_ne!(k3.public(), k4.public());
        assert_ne!(k4.public(), k5.public());
        assert_eq!(
            k1.generate_shared_secret(k2.public()),
            k2.generate_shared_secret(k1.public())
        );
        assert_eq!(
            k2.generate_shared_secret(k3.public()),
            k3.generate_shared_secret(k2.public())
        );
        assert_eq!(
            k4.generate_shared_secret(k3.public()),
            k3.generate_shared_secret(k4.public())
        );
        assert_eq!(
            k4.generate_shared_secret(k5.public()),
            k5.generate_shared_secret(k4.public())
        );
        assert_eq!(
            k1.generate_shared_secret(k5.public()),
            k5.generate_shared_secret(k1.public())
        );
        assert_eq!(
            k2.generate_shared_secret(k4.public()),
            k4.generate_shared_secret(k2.public())
        );
        assert_eq!(
            k3.generate_shared_secret(k3.public()),
            k3.generate_shared_secret(k3.public())
        );
        assert!(dh::verify_public_key(&ZERO).is_err());
        assert!(dh::verify_public_key(&ONE).is_err());
        assert!(dh::verify_public_key(&TWO).is_ok());
        assert!(dh::verify_public_key(&(dh::modulus() - &*TWO)).is_ok());
        assert!(dh::verify_public_key(&(dh::modulus() - &*ONE)).is_err());
        assert!(dh::verify_public_key(dh::modulus()).is_err());
        assert!(dh::verify_public_key(&(dh::modulus() + &*ONE)).is_err());
        assert!(dh::verify_exponent(&ZERO).is_err());
        assert!(dh::verify_exponent(&ONE).is_ok());
        assert!(dh::verify_exponent(&TWO).is_ok());
        assert!(dh::verify_exponent(&(dh::q() - &*ONE)).is_ok());
        assert!(dh::verify_exponent(dh::q()).is_err());
        assert!(dh::verify_exponent(&(dh::q() + &*ONE)).is_err());
    }

    #[test]
    #[should_panic]
    fn test_zero_length_slices() {
        constant::compare_bytes_distinct(&[], &[]).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_zero_slices() {
        constant::compare_bytes_distinct(&[0, 0, 0, 0], &[0, 0, 0, 0]).unwrap();
    }

    #[test]
    fn test_same_length_slices() {
        let s1 = b"Hello world";
        let s2 = *s1;
        constant::compare_bytes_distinct(s1, &s2).unwrap();
    }

    #[test]
    fn test_different_content() {
        assert!(constant::compare_bytes_distinct(b"Hello!", b"Yo!").is_err());
    }

    #[test]
    fn test_differing_length_slices() {
        assert!(constant::compare_bytes_distinct(b"Hello!", b"Hello").is_err());
    }

    #[test]
    fn test_encoding_decoding_point() {
        let generator = ed448::generator();
        let decoded = ed448::Point::decode(&generator.encode()).unwrap();
        assert_eq!(generator, &decoded);
        let doublecoded = ed448::Point::decode(&decoded.encode()).unwrap();
        assert_eq!(generator, &doublecoded);
    }

    #[test]
    fn test_point_generator_valid() {
        let generator = ed448::generator();
        crypto::ed448::verify(generator).unwrap();
    }

    #[test]
    fn test_point_verify() {
        let n = ed448::random_in_Zq();
        let point = ed448::generator() * &n;
        ed448::verify(&point).unwrap();
        assert!((&point * ed448::prime_order()).is_identity());
        assert_eq!(ed448::identity(), &(&point + &-&point));
    }

    #[test]
    fn test_scalar_multiplication() {
        let n = ed448::random_in_Zq();
        let p = ed448::generator() * &n;
        assert_eq!(&p + &p, &p * &*utils::biguint::TWO);
        assert_eq!(&p + &p + &p, &p * &*utils::biguint::THREE);
        assert_eq!(&p + &p + &p + &p, &p * &*utils::biguint::FOUR);
        assert_eq!(&p + &p + &p + &p + &p, &p * &*utils::biguint::FIVE);
        assert_eq!(&p + &p + &p + &p + &p + &p, &p * &*utils::biguint::SIX);
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::biguint::SEVEN
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::biguint::EIGHT
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::biguint::NINE
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::biguint::TEN
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::biguint::ELEVEN
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::biguint::TWELVE
        );
    }

    #[test]
    fn test_ring_sign_verify() -> Result<(), CryptoError> {
        let keypair = ed448::KeyPair::generate();
        let a2 = ed448::KeyPair::generate();
        let a3 = ed448::KeyPair::generate();
        let m = utils::random::secure_bytes::<250>();
        let sigma = RingSignature::sign(&keypair, keypair.public(), a2.public(), a3.public(), &m)?;
        sigma.verify(keypair.public(), a2.public(), a3.public(), &m)?;
        let sigma = RingSignature::sign(&keypair, a2.public(), keypair.public(), a3.public(), &m)?;
        sigma.verify(a2.public(), keypair.public(), a3.public(), &m)?;
        let sigma = RingSignature::sign(&keypair, a2.public(), a3.public(), keypair.public(), &m)?;
        sigma.verify(a2.public(), a3.public(), keypair.public(), &m)
    }

    #[test]
    fn test_ring_sign_verify_distinct() -> Result<(), CryptoError> {
        let m = utils::random::secure_bytes::<250>();
        let keypair = ed448::KeyPair::generate();
        let a1_public = keypair.public().clone();
        let a2 = ed448::KeyPair::generate();
        let a3 = ed448::KeyPair::generate();
        let sigma = RingSignature::sign(&keypair, &a1_public, a2.public(), a3.public(), &m)?;
        sigma.verify(&a1_public, a2.public(), a3.public(), &m)?;
        let sigma = RingSignature::sign(&keypair, a2.public(), &a1_public, a3.public(), &m)?;
        sigma.verify(a2.public(), &a1_public, a3.public(), &m)?;
        let sigma = RingSignature::sign(&keypair, a2.public(), a3.public(), &a1_public, &m)?;
        sigma.verify(a2.public(), a3.public(), &a1_public, &m)
    }

    #[test]
    fn test_ring_sign_verify_bad() {
        let m = utils::random::secure_bytes::<250>();
        let m_bad = utils::random::secure_bytes::<250>();
        let keypair = ed448::KeyPair::generate();
        let a2 = ed448::KeyPair::generate();
        let a3 = ed448::KeyPair::generate();
        let sigma =
            RingSignature::sign(&keypair, keypair.public(), a2.public(), a3.public(), &m).unwrap();
        assert!(sigma
            .verify(keypair.public(), a2.public(), a3.public(), &m_bad)
            .is_err());
        let sigma =
            RingSignature::sign(&keypair, a2.public(), keypair.public(), a3.public(), &m).unwrap();
        assert!(sigma
            .verify(a2.public(), keypair.public(), a3.public(), &m_bad)
            .is_err());
        let sigma =
            RingSignature::sign(&keypair, a2.public(), a3.public(), keypair.public(), &m).unwrap();
        assert!(sigma
            .verify(a2.public(), a3.public(), keypair.public(), &m_bad)
            .is_err());
    }

    #[test]
    #[should_panic]
    fn test_ring_sign_verify_incorrect_public_key_1() {
        let m = utils::random::secure_bytes::<250>();
        let keypair = ed448::KeyPair::generate();
        let a1 = ed448::KeyPair::generate();
        let a2 = ed448::KeyPair::generate();
        let a3 = ed448::KeyPair::generate();
        RingSignature::sign(&keypair, a1.public(), a2.public(), a3.public(), &m).unwrap();
    }
}

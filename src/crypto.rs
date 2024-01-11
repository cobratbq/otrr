// SPDX-License-Identifier: LGPL-3.0-only

use std::fmt::Debug;

use crate::utils;

// TODO double-check all big-endian/little-endian use. (generate ECDH uses little-endian)
// TODO check on if/how to clear/drop BigUint values after use.
// TODO I need to stop being a stubborn idiot and just convert BigUint to BigInt for internal cases where calculations may run into negatives. This makes everything simpler, possibly significantly faster.

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

    use super::CryptoError;

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
            (*utils::random::RANDOM)
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

    use crate::utils;

    const KEY_LENGTH: usize = 16;

    type Nonce = [u8; 16];

    #[derive(Clone)]
    pub struct Key(pub [u8; KEY_LENGTH]);

    impl Key {
        /// `generate` generates an AES-128 key.
        ///
        /// # Panics
        /// Panics if it fails to generate (sufficient) random data.
        #[must_use]
        pub fn generate() -> Self {
            let mut key = [0u8; 16];
            (*utils::random::RANDOM)
                .fill(&mut key)
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
    use num_integer::Integer;

    use crate::encoding::OTREncodable;

    use super::CryptoError;

    /// Signature type represents a DSA signature in IEEE-P1363 representation.
    const PARAM_Q_LENGTH: usize = 20;

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
        pub fn q(&self) -> &BigUint {
            self.pk.components().q()
        }

        /// `sign` signs a provided prehash value with the private key.
        ///
        /// # Panics
        /// Panics if result unexpectedly cannot be unpacked.
        #[must_use]
        pub fn sign(&self, data: &[u8]) -> Signature {
            let prehash = prehash(data, self.q());
            Signature(self.sk.sign_prehash(&prehash).unwrap())
        }
    }

    #[derive(Clone, Debug, PartialEq, PartialOrd)]
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
            if q.bits() != PARAM_Q_LENGTH * 8 {
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
        pub fn validate(&self, signature: &Signature, data: &[u8]) -> Result<(), CryptoError> {
            let prehash = prehash(data, self.q());
            self.0
                .verify_prehash(&prehash, &signature.0)
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

    impl OTREncodable for Signature {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write_mpi(self.0.r());
            encoder.write_mpi(self.0.s());
        }
    }

    impl Signature {
        /// from constructs a Signature from its mathematical components.
        ///
        /// # Errors
        /// In case of bad input.
        pub fn from(r: BigUint, s: BigUint) -> Result<Self, CryptoError> {
            Ok(Self(dsa::Signature::from_components(r, s).map_err(
                |_| {
                    CryptoError::VerificationFailure(
                        "Illegal data: decoded data does not contain valid DSA signature.",
                    )
                },
            )?))
        }
    }

    fn prehash(data: &[u8], q: &BigUint) -> [u8; 20] {
        BigUint::from_bytes_be(data)
            .mod_floor(q)
            .to_bytes_be()
            // FIXME double-check if this is correct in all cases: if bytes_be.len() < 20, probably leaves zeroes at the end.
            .try_into()
            .expect("BUG: Failed to convert prehash into 20-byte array")
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

    use crate::{crypto::otr4, utils};

    use super::{dh3072, ed448, shake256, CryptoError};

    pub const K_LENGTH: usize = 64;
    pub const ROOT_KEY_LENGTH: usize = 64;
    const BRACE_KEY_LENGTH: usize = 32;
    const CHAIN_KEY_LENGTH: usize = 64;
    pub const MAC_LENGTH: usize = 64;
    pub const MESSAGEKEY_LENGTH: usize = 64;

    const USAGE_FINGERPRINT: u8 = 0x00;
    const USAGE_THIRD_BRACE_KEY: u8 = 0x01;
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
    const USAGE_NEXT_CHAIN_KEY: u8 = 0x14;
    const USAGE_MESSAGE_KEY: u8 = 0x15;
    const USAGE_MAC_KEY: u8 = 0x16;
    const USAGE_EXTRA_SYMMETRIC_KEY: u8 = 0x17;
    pub const USAGE_AUTHENTICATOR: u8 = 0x18;
    pub const USAGE_SMP_SECRET: u8 = 0x19;
    pub const USAGE_AUTH: u8 = 0x1A;

    const PREFIX: [u8; 5] = [b'O', b'T', b'R', b'v', b'4'];

    /// `Fingerprint` represents the hash of a party's _identity_ and _forging_ keys, and is used as
    /// an identifier.
    pub type Fingerprint = [u8; 56];

    // TODO manage MAC reveals
    #[derive(Clone)]
    pub struct DoubleRatchet {
        shared_secret: MixedSharedSecret,
        root_key: [u8; 64],
        sender: Ratchet,
        receiver: Ratchet,
        next: Selector,
        i: u32,
        pn: u32,
    }

    impl Drop for DoubleRatchet {
        fn drop(&mut self) {
            utils::bytes::clear(&mut self.root_key);
            self.i = 0;
            self.pn = 0;
        }
    }

    impl DoubleRatchet {
        #[must_use]
        pub fn initialize(
            selector: &Selector,
            shared_secret: MixedSharedSecret,
            prev_root_key: [u8; ROOT_KEY_LENGTH],
        ) -> Self {
            let k = shared_secret.k();
            let (sender, receiver, next) = match selector {
                Selector::SENDER => (
                    Ratchet {
                        chain_key: kdf2(USAGE_CHAIN_KEY, &prev_root_key, &k),
                        message_id: 0,
                    },
                    Ratchet {
                        chain_key: [0u8; CHAIN_KEY_LENGTH],
                        message_id: 0,
                    },
                    Selector::RECEIVER,
                ),
                Selector::RECEIVER => (
                    Ratchet {
                        chain_key: [0u8; CHAIN_KEY_LENGTH],
                        message_id: 0,
                    },
                    Ratchet {
                        chain_key: kdf2(USAGE_CHAIN_KEY, &prev_root_key, &k),
                        message_id: 0,
                    },
                    Selector::SENDER,
                ),
            };
            Self {
                shared_secret,
                root_key: kdf2(USAGE_ROOT_KEY, &prev_root_key, &k),
                sender,
                receiver,
                next,
                i: 0,
                pn: 0,
            }
        }

        #[must_use]
        pub fn next(&self) -> Selector {
            self.next.clone()
        }

        /// `rotate_sender` rotates the sender keys of the Double Ratchet.
        ///
        /// # Panics
        /// In case `rotate_sender` is used before its turn to rotate. (See `next`)
        #[must_use]
        pub fn rotate_sender(&self) -> Self {
            assert_eq!(Selector::SENDER, self.next);
            let new_shared_secret = self.shared_secret.rotate_keypairs(self.i % 3 == 0);
            let new_k = new_shared_secret.k();
            // TODO clear k?
            Self {
                shared_secret: new_shared_secret,
                root_key: kdf2::<ROOT_KEY_LENGTH>(USAGE_ROOT_KEY, &self.root_key, &new_k),
                sender: Ratchet {
                    chain_key: kdf2::<CHAIN_KEY_LENGTH>(USAGE_CHAIN_KEY, &self.root_key, &new_k),
                    message_id: 0,
                },
                receiver: self.receiver.clone(),
                next: Selector::RECEIVER,
                i: self.i + 1,
                pn: self.sender.message_id,
            }
        }

        /// `rotate_sender_chainkey` rotates the sender chainkey for the next message (in the same
        /// ratchet). This also overwrites the current chainkey.
        ///
        /// # Panics
        /// In case of improper use: rotation of the sender chainkey is not allowed according to the
        /// protocol. This means that sender keypair rotation is required first.
        pub fn rotate_sender_chainkey(&mut self) {
            assert_eq!(otr4::Selector::RECEIVER, self.next);
            self.sender.rotate();
        }

        /// `rotate_receiver` rotates the other party's public keys.
        ///
        /// # Errors
        /// In case the public keys are illegal.
        ///
        /// # Panics
        /// In case `rotate_receiver` is used before its turn to rotate. (see `next`)
        // FIXME dh_next optional or expect same to be provided repeatedly, which may help with out-of-order messages.
        pub fn rotate_receiver(
            &self,
            ecdh_next: ed448::Point,
            dh_next: BigUint,
        ) -> Result<Self, CryptoError> {
            assert_eq!(Selector::RECEIVER, self.next);
            assert!((self.i % 3 != 0) == (dh_next == self.shared_secret.public_dh));
            let new_shared_secret =
                self.shared_secret
                    .rotate_others(self.i % 3 == 0, ecdh_next, dh_next)?;
            let mut new_k = new_shared_secret.k();
            let rotated = Self {
                shared_secret: new_shared_secret,
                root_key: kdf2::<ROOT_KEY_LENGTH>(USAGE_ROOT_KEY, &self.root_key, &new_k),
                sender: self.sender.clone(),
                receiver: Ratchet {
                    chain_key: kdf2::<CHAIN_KEY_LENGTH>(USAGE_CHAIN_KEY, &self.root_key, &new_k),
                    message_id: 0,
                },
                next: Selector::SENDER,
                i: self.i + 1,
                pn: self.pn,
            };
            utils::bytes::clear(&mut new_k);
            Ok(rotated)
        }

        pub fn rotate_receiver_chainkey(&mut self) {
            self.receiver.rotate();
        }

        #[must_use]
        pub fn i(&self) -> u32 {
            self.i
        }

        #[must_use]
        pub fn j(&self) -> u32 {
            self.sender.id()
        }

        #[must_use]
        pub fn k(&self) -> u32 {
            self.receiver.id()
        }

        #[must_use]
        pub fn pn(&self) -> u32 {
            self.pn
        }

        #[must_use]
        pub fn ecdh_public(&self) -> &ed448::Point {
            self.shared_secret.ecdh.public()
        }

        #[must_use]
        pub fn dh_public(&self) -> &BigUint {
            self.shared_secret.dh.public()
        }

        #[must_use]
        pub fn other_ecdh(&self) -> &ed448::Point {
            &self.shared_secret.public_ecdh
        }

        #[must_use]
        pub fn other_dh(&self) -> &BigUint {
            &self.shared_secret.public_dh
        }

        #[must_use]
        pub fn sender_keys(&self) -> Keys {
            self.sender.keys()
        }

        #[must_use]
        pub fn receiver_keys(&self) -> Keys {
            self.receiver.keys()
        }
    }

    /// `Ratchet` is the single ratchet of the two in the `DoubleRatchet` data structure.
    #[derive(Clone)]
    struct Ratchet {
        chain_key: [u8; CHAIN_KEY_LENGTH],
        message_id: u32,
    }

    impl Drop for Ratchet {
        fn drop(&mut self) {
            utils::bytes::clear(&mut self.chain_key);
            self.message_id = 0;
        }
    }

    impl Ratchet {
        /// `id` returns the current message id for the ratchet.
        fn id(&self) -> u32 {
            self.message_id
        }

        /// `rotate` rotates the chain key for the next message in the ratchet.
        fn rotate(&mut self) {
            self.chain_key = kdf(USAGE_NEXT_CHAIN_KEY, &self.chain_key);
            self.message_id += 1;
        }

        /// `keys` produces the MK_enc, MK_mac and extra symmetric key respectively.
        fn keys(&self) -> Keys {
            debug_assert!(utils::bytes::any_nonzero(&self.chain_key));
            let mk_enc = kdf(USAGE_MESSAGE_KEY, &self.chain_key);
            let mk_mac = kdf(USAGE_MAC_KEY, &mk_enc);
            let esk = kdf2(USAGE_EXTRA_SYMMETRIC_KEY, &[0xff], &self.chain_key);
            Keys(mk_enc, mk_mac, esk)
        }
    }

    /// `Keys` contains resp. MK_enc, MK_mac, and Extra Symmetric Key (base key). `Keys` implements
    /// `Drop` and will therefore clear itself.
    pub struct Keys(
        pub [u8; MESSAGEKEY_LENGTH],
        pub [u8; MESSAGEKEY_LENGTH],
        pub [u8; MESSAGEKEY_LENGTH],
    );

    impl Drop for Keys {
        fn drop(&mut self) {
            utils::bytes::clear3(&mut self.0, &mut self.1, &mut self.2);
        }
    }

    /// `Selector` is the selector for a specific ratchet, i.e. Sender or Receiver.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Selector {
        SENDER,
        RECEIVER,
    }

    /// `MixedSharedSecret` represents the OTRv4 mixed shared secret value.
    #[derive(Clone)]
    pub struct MixedSharedSecret {
        ecdh: ed448::ECDHKeyPair,
        dh: dh3072::KeyPair,
        public_ecdh: ed448::Point,
        public_dh: BigUint,
        brace_key: [u8; BRACE_KEY_LENGTH],
        k: [u8; K_LENGTH],
    }

    impl Drop for MixedSharedSecret {
        fn drop(&mut self) {
            utils::bytes::clear(&mut self.brace_key);
            utils::bytes::clear(&mut self.k);
        }
    }

    impl MixedSharedSecret {
        /// `new` constructs the next rotation of the mixed shared secret.
        ///
        /// # Errors
        /// In case of invalid key material.
        pub fn new(
            ecdh0: ed448::ECDHKeyPair,
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
                [0u8; BRACE_KEY_LENGTH],
            )
        }

        /// `rotate_keypairs` rotates the user's keypairs.
        ///
        /// # Panics
        /// Should only panic in case of a bug in the implementation.
        #[must_use]
        pub fn rotate_keypairs(&self, third: bool) -> Self {
            let ecdh = ed448::ECDHKeyPair::generate();
            let dh = dh3072::KeyPair::generate();
            Self::next(
                ecdh,
                dh,
                self.public_ecdh.clone(),
                self.public_dh.clone(),
                third,
                self.brace_key,
            ).expect("BUG: failure should not occur because only the keypairs are changed, meaning that all changes are within our control. Any bad data should have been detected earlier.")
        }

        /// `rotate_others` rotates the other party's public keys.
        ///
        /// # Errors
        /// In case of bad public keys.
        ///
        /// # Panics
        /// In case third-brace-key flag does not correspond with the presence/absence of the next
        /// DH public key.
        pub fn rotate_others(
            &self,
            third: bool,
            ecdh_next: ed448::Point,
            dh_next: BigUint,
        ) -> Result<Self, CryptoError> {
            assert_eq!(third, dh_next != self.public_dh);
            // TODO after rotating other party's public keys, we should clear our corresponding private keys, as next rotation will be of our keypairs. (clearing is not possible yet with BigUint)
            Self::next(
                self.ecdh.clone(),
                self.dh.clone(),
                ecdh_next,
                dh_next,
                third,
                self.brace_key,
            )
        }

        fn next(
            ecdh: ed448::ECDHKeyPair,
            dh: dh3072::KeyPair,
            public_ecdh: ed448::Point,
            public_dh: BigUint,
            third: bool,
            brace_key_prev: [u8; BRACE_KEY_LENGTH],
        ) -> Result<Self, CryptoError> {
            ed448::verify(&public_ecdh)?;
            dh3072::verify(&public_dh)?;
            let mut k_ecdh = ecdh.generate_shared_secret(&public_ecdh).encode();
            assert!(utils::bytes::any_nonzero(&k_ecdh));
            let brace_key = if third {
                let mut k_dh = utils::biguint::to_bytes_le_fixed::<{ dh3072::ENCODED_LENGTH }>(
                    &dh.generate_shared_secret(&public_dh),
                );
                let new_brace_key = kdf(USAGE_THIRD_BRACE_KEY, &k_dh);
                utils::bytes::clear(&mut k_dh);
                new_brace_key
            } else {
                assert!(utils::bytes::any_nonzero(&brace_key_prev));
                kdf(USAGE_BRACE_KEY, &brace_key_prev)
            };
            let k = kdf2::<K_LENGTH>(USAGE_SHARED_SECRET, &k_ecdh, &brace_key);
            utils::bytes::clear(&mut k_ecdh);
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
        pub fn k(&self) -> [u8; K_LENGTH] {
            self.k
        }
    }

    /// `fingerprint` derives the fingerprint from the identity public key and forging public key,
    /// that are provided as part of the party's client profile.
    #[must_use]
    pub fn fingerprint(identity_key: &ed448::Point, forging_key: &ed448::Point) -> [u8; 56] {
        hwc2(
            USAGE_FINGERPRINT,
            &identity_key.encode(),
            &forging_key.encode(),
        )
    }

    #[must_use]
    pub fn hwc<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        kdf(usage, data)
    }

    #[must_use]
    pub fn hwc2<const N: usize>(usage: u8, data1: &[u8], data2: &[u8]) -> [u8; N] {
        kdf2(usage, data1, data2)
    }

    #[must_use]
    pub fn hcmac<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        kdf(usage, data)
    }

    #[must_use]
    pub fn kdf<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        let mut buffer = Vec::with_capacity(6 + data.len());
        buffer.extend_from_slice(&PREFIX);
        buffer.push(usage);
        buffer.extend_from_slice(data);
        shake256::digest(&buffer)
    }

    #[must_use]
    pub fn kdf2<const N: usize>(usage: u8, data1: &[u8], data2: &[u8]) -> [u8; N] {
        let mut buffer = Vec::with_capacity(6 + data1.len() + data2.len());
        buffer.extend_from_slice(&PREFIX);
        buffer.push(usage);
        buffer.extend_from_slice(data1);
        buffer.extend_from_slice(data2);
        shake256::digest(&buffer)
    }
}

pub mod chacha20 {

    use chacha20::{
        cipher::{KeyIvInit, StreamCipher},
        ChaCha20,
    };

    #[must_use]
    pub fn encrypt(key: [u8; 32], m: &[u8]) -> Vec<u8> {
        crypt(key, m)
    }

    #[must_use]
    pub fn decrypt(key: [u8; 32], m: &[u8]) -> Vec<u8> {
        crypt(key, m)
    }

    fn crypt(key: [u8; 32], m: &[u8]) -> Vec<u8> {
        const ZERO_NONCE: [u8; 12] = [0u8; 12];
        let mut cipher = ChaCha20::new(&key.into(), &ZERO_NONCE.into());
        let mut buffer = Vec::from(m);
        cipher.apply_keystream(&mut buffer);
        buffer
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

pub mod ed448 {
    use std::{
        ops::{Add, Mul, Neg},
        str::FromStr,
    };

    use num_bigint::{BigInt, ModInverse, ToBigInt};
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

    pub const ENCODED_LENGTH: usize = 57;

    // G = (x=22458004029592430018760433409989603624678964163256413424612546168695
    //        0415467406032909029192869357953282578032075146446173674602635247710,
    //      y=29881921007848149267601793044393067343754404015408024209592824137233
    //        1506189835876003536878655418784733982303233503462500531545062832660)
    static G: Lazy<Point> = Lazy::new(|| {
        Point{
        x: BigInt::from_str("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710").unwrap(),
        y: BigInt::from_str("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660").unwrap(),
    }
    });

    /// `I` is the neutral element, or identity.
    static I: Lazy<Point> = Lazy::new(|| Point {
        x: (*utils::bigint::ZERO).clone(),
        y: (*utils::bigint::ONE).clone(),
    });

    /// p, the modulus
    static P: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439").unwrap()
    });

    /// q, the (prime) order
    static Q: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779").unwrap()
    });

    /// d, '-39081'
    static D: Lazy<BigInt> = Lazy::new(|| BigInt::from_str("-39081").unwrap());

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
    pub fn modulus() -> &'static BigInt {
        // FIXME temporary
        &P
    }

    /// `order` provides the (prime) order value `q`.
    #[must_use]
    pub fn order() -> &'static BigInt {
        // FIXME temporary
        &Q
    }

    pub struct EdDSAKeyPair([u8; ENCODED_LENGTH], BigInt, Point);

    impl EdDSAKeyPair {
        #[must_use]
        pub fn generate() -> Self {
            let symmetric_key = utils::random::secure_bytes::<ENCODED_LENGTH>();
            let h = shake256::digest::<114>(&symmetric_key);
            let mut secret_key_source = [0u8; ENCODED_LENGTH];
            secret_key_source.copy_from_slice(&h[..ENCODED_LENGTH]);
            prune(&mut secret_key_source);
            let secret_key = BigInt::from_bytes_le(num_bigint::Sign::Plus, &secret_key_source);
            let public_key = &*G * &secret_key;
            Self(symmetric_key, secret_key, public_key)
        }

        #[must_use]
        pub fn public(&self) -> &Point {
            &self.2
        }

        /// `sign` signs `message`. As per OTRv4 spec, always uses zero-length bytes as context.
        #[allow(non_snake_case)]
        #[must_use]
        pub fn sign(&self, message: &[u8]) -> Signature {
            // FIXME needs to be looked over
            let mut h = shake256::digest::<114>(&self.0);
            let mut secret_bytes = [0u8; 57];
            secret_bytes.clone_from_slice(&h[..57]);
            let mut prefix = [0u8; 57];
            prefix.clone_from_slice(&h[57..]);
            prune(&mut secret_bytes);
            let s = BigInt::from_bytes_le(num_bigint::Sign::Plus, &secret_bytes);
            let mut encoded_A = (&*G * &s).encode();
            let mut buffer_R = utils::bytes::concatenate3(&dom4(EDDSA_CONTEXT), &prefix, message);
            let r =
                BigInt::from_bytes_le(num_bigint::Sign::Plus, &shake256::digest::<114>(&buffer_R));
            // TODO double-check with joldilocks, it uses basepoint in 4E, it seems to be a difference in notation between papers, see RFC 8032.
            let encoded_R = (&*G * &r).encode();
            let mut buffer_K =
                utils::bytes::concatenate4(&dom4(EDDSA_CONTEXT), &encoded_R, &encoded_A, message);
            let k =
                BigInt::from_bytes_le(num_bigint::Sign::Plus, &shake256::digest::<114>(&buffer_K));
            let encoded_s =
                utils::bigint::to_bytes_le_fixed::<ENCODED_LENGTH>(&(&r + &k * &s).mod_floor(&*Q));
            utils::bytes::clear3(&mut buffer_K, &mut buffer_R, &mut encoded_A);
            utils::bytes::clear3(&mut secret_bytes, &mut prefix, &mut h);
            Signature(encoded_R, encoded_s)
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
    pub fn hash_point_to_scalar(purpose: u8, point: &Point) -> BigInt {
        hash_to_scalar(purpose, &point.encode())
    }

    #[must_use]
    pub fn hash_point_to_scalar2(purpose: u8, point1: &Point, point2: &Point) -> BigInt {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&point1.encode());
        buffer.extend_from_slice(&point2.encode());
        hash_to_scalar(purpose, &buffer)
    }

    // TODO pruning is not strictly necessary because the scalars resulting from hash_to_scalar are not used on the curve, merely as proofs.
    #[must_use]
    pub fn hash_to_scalar(purpose: u8, data: &[u8]) -> BigInt {
        decode_scalar(&hwc::<57>(purpose, data))
    }

    /// `decode_scalar` decodes an encoded scalar into `BigInt`.
    ///
    /// # Panics
    /// Panics if all bytes are zero. (sanity-check)
    #[must_use]
    pub fn decode_scalar(encoded: &[u8; 57]) -> BigInt {
        assert!(utils::bytes::any_nonzero(encoded));
        BigInt::from_bytes_le(num_bigint::Sign::Plus, encoded).mod_floor(&*Q)
    }

    // TODO currently cloning the keypair to re-obtain ownership. Is there a way to avoid that without too much borrow checker complexity?
    #[derive(Clone)]
    pub struct ECDHKeyPair(BigInt, Point);

    impl ECDHKeyPair {
        /// `generate` generates a key pair for Ed448 ECDH.
        #[must_use]
        pub fn generate() -> Self {
            let r = random_in_Zq();
            let mut buffer = shake256::digest::<114>(&r.to_bytes_le().1);
            prune(&mut buffer);
            let s = BigInt::from_bytes_le(num_bigint::Sign::Plus, &buffer);
            // FIXME securely delete r, h
            let public = (&*G) * &s;
            Self(s, public)
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

    /// `validate` validates a message given a signature and corresponding public key.
    ///
    /// # Errors
    /// In case of failure during signature validation.
    #[allow(non_snake_case)]
    pub fn validate(
        public_key: &Point,
        signature: &Signature,
        m: &[u8],
    ) -> Result<(), CryptoError> {
        let R = Point::decode(&signature.0)?;
        verify(&R)?;
        let s = BigInt::from_bytes_le(num_bigint::Sign::Plus, &signature.1);
        if s.sign() != num_bigint::Sign::Plus || s >= *Q {
            return Err(CryptoError::VerificationFailure(
                "illegal data: s component",
            ));
        }
        let digest: [u8; 2 * ENCODED_LENGTH] = shake256::digest(&utils::bytes::concatenate4(
            &dom4(EDDSA_CONTEXT),
            &signature.0,
            &public_key.encode(),
            m,
        ));
        let k = BigInt::from_bytes_le(num_bigint::Sign::Plus, &digest);
        let lhs = &*G * &s;
        let rhs = R + public_key * &k;
        constant::compare_points_distinct(&lhs, &rhs)
    }

    // TODO Ring signatures and other BigUint code (SMP4) is really waaaaay too slow. (undoubtedly my own fault)
    #[derive(Clone)]
    pub struct RingSignature {
        c1: BigInt,
        r1: BigInt,
        c2: BigInt,
        r2: BigInt,
        c3: BigInt,
        r3: BigInt,
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
            log::trace!("decode OTRv4 Ring Signature…");
            let c1 = decoder.read_ed448_scalar()?;
            let r1 = decoder.read_ed448_scalar()?;
            let c2 = decoder.read_ed448_scalar()?;
            let r2 = decoder.read_ed448_scalar()?;
            let c3 = decoder.read_ed448_scalar()?;
            let r3 = decoder.read_ed448_scalar()?;
            log::trace!("decode OTRv4 Ring Signature… done.");
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
            log::trace!("Verifying ring-signature…");
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
            keypair: &EdDSAKeyPair,
            A1: &Point,
            A2: &Point,
            A3: &Point,
            m: &[u8],
        ) -> Result<Self, CryptoError> {
            verify(A1)?;
            verify(A2)?;
            verify(A3)?;
            let eq1 = constant::compare_points(&keypair.2, A1).is_ok();
            let eq2 = constant::compare_points(&keypair.2, A2).is_ok();
            let eq3 = constant::compare_points(&keypair.2, A3).is_ok();
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
                    let c1_derived = (&c - &c2 - &c3).mod_floor(&*Q);
                    //let r1 = &t - &c1 * &keypair.0;
                    let r1_derived =
                        (&t - &(&c1_derived * &keypair.1).mod_floor(&*Q)).mod_floor(&*Q);
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
                    let c2_derived = (&c - &c1 - &c3).mod_floor(&*Q);
                    //let r2 = &t - &c2 * &keypair.0;
                    let r2_derived =
                        (&t - &(&c2_derived * &keypair.1).mod_floor(&*Q)).mod_floor(&*Q);
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
                    let c3_derived = (&c - &c1 - &c2).mod_floor(&*Q);
                    //let r3 = &t - &c3 * &keypair.0;
                    let r3_derived =
                        (&t - &(&c3_derived * &keypair.1).mod_floor(&*Q)).mod_floor(&*Q);
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

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Point {
        x: BigInt,
        y: BigInt,
    }

    impl Drop for Point {
        fn drop(&mut self) {
            self.x.zeroize();
            self.y.zeroize();
        }
    }

    // TODO is this variant (non-reference) needed, or is it handled by the compiler?
    impl Mul<BigInt> for Point {
        type Output = Self;

        fn mul(self, rhs: BigInt) -> Self::Output {
            self.mul0(&rhs)
        }
    }

    impl<'b> Mul<&'b BigInt> for Point {
        type Output = Self;

        fn mul(self, scalar: &'b BigInt) -> Self::Output {
            self.mul0(scalar)
        }
    }

    impl<'a, 'b> Mul<&'b BigInt> for &'a Point {
        type Output = Point;

        // TODO implementation of scalar multiplication is not constant-time
        fn mul(self, scalar: &'b BigInt) -> Self::Output {
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
            let y = BigInt::from_bytes_le(num_bigint::Sign::Plus, &encoded[..56]);
            if y.cmp(&*P).is_ge() {
                return Err(CryptoError::VerificationFailure(
                    "Encoded point contains illegal y component",
                ));
            }
            let num = &y * &y - &*utils::bigint::ONE;
            let denom = &y * &y * &*D - &*utils::bigint::ONE;
            // REMARK the `exponent` for `modpow` could be precomputed.
            let x = (&num
                * &num
                * &num
                * &denom
                * (&num * &num * &num * &num * &num * &denom * &denom * &denom).modpow(
                    &((&*P - &*utils::bigint::THREE) / &*utils::bigint::FOUR),
                    &P,
                ))
            .mod_floor(&*P);
            if num.mod_floor(&*P) != (&x * &x * &denom).mod_floor(&*P) {
                return Err(CryptoError::VerificationFailure(
                    "Encoded point: no square root exists",
                ));
            }
            if x == *utils::bigint::ZERO && x_bit != 0 {
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
        pub fn encode(&self) -> [u8; ENCODED_LENGTH] {
            let mut encoded = utils::bigint::to_bytes_le_fixed::<ENCODED_LENGTH>(&self.y);
            assert_eq!(0, encoded[56]);
            let x_bytes = self.x.to_bytes_le().1;
            let x_bit = if x_bytes.is_empty() {
                0
            } else {
                x_bytes[0] & 0x1
            };
            encoded[56] |= x_bit << 7;
            encoded
        }

        // TODO implementation of scalar multiplication is not constant-time
        fn mul0(&self, scalar: &BigInt) -> Point {
            let mut result = Point {
                x: utils::bigint::ZERO.clone(),
                y: utils::bigint::ONE.clone(),
            };
            let mut temp: Point = self.clone();
            for i in 0..scalar.bits() {
                if utils::bigint::bit(scalar, i) {
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
            let result_x: BigInt = &(&self.x * &rhs.y + &self.y * &rhs.x)
                * (&*ONE + &(&*D * &self.x * &rhs.x * &self.y * &rhs.y))
                    .mod_inverse(&*P)
                    .unwrap();
            let result_y: BigInt = &(&self.y * &rhs.y - &self.x * &rhs.x)
                * (&*ONE - &(&*D * &self.x * &rhs.x * &self.y * &rhs.y))
                    .mod_inverse(&*P)
                    .unwrap();
            Point {
                x: result_x.mod_floor(&P.to_bigint().unwrap()),
                y: result_y.mod_floor(&P.to_bigint().unwrap()),
            }
        }

        #[must_use]
        pub fn is_identity(&self) -> bool {
            self.x == *utils::bigint::ZERO && self.y == *utils::bigint::ONE
        }
    }

    #[derive(Clone)]
    pub struct Signature([u8; ENCODED_LENGTH], [u8; ENCODED_LENGTH]);

    impl OTREncodable for Signature {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write(&self.0);
            encoder.write(&self.1);
        }
    }

    impl Signature {
        /// `decode` decodes an OTR-encoded EdDSA signature.
        ///
        /// # Errors
        /// In case of failure to decode signature from byte-encoding.
        pub fn decode(decoder: &mut OTRDecoder) -> Result<Self, OTRError> {
            log::trace!("decode Ed448 signature…");
            let r = decoder.read::<ENCODED_LENGTH>()?;
            let s = decoder.read::<ENCODED_LENGTH>()?;
            log::trace!("decode Ed448 signature… done.");
            Ok(Self(r, s))
        }
    }

    fn dom4(y: &[u8]) -> Vec<u8> {
        assert!(y.len() <= 255);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(PREFIX_SIGED448);
        buffer.push(0);
        buffer.push(u8::try_from(y.len()).expect("BUG: length of y does not fit in a single byte"));
        buffer.extend_from_slice(y);
        buffer
    }

    const PREFIX_SIGED448: &[u8] = b"SigEd448";
    const EDDSA_CONTEXT: &[u8] = b"";

    /// `random_in_Zq` generates a random value in Z_q and returns this as `BigUint` unsigned
    /// integer value. The value is pruned as to be guaranteed safe for use in curve Ed448.
    ///
    /// # Panics
    /// Panics if invalid input data is provided. (sanity-checks)
    // TODO is non-zero value a hard requirement? If so, change assert into a retry-loop.
    #[allow(non_snake_case)]
    #[must_use]
    pub fn random_in_Zq() -> BigInt {
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
        assert!(bytes::any_nonzero(&v[..57]));
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

    pub const ENCODED_LENGTH: usize = 384;
    /// p is the prime (modulus).
    pub static P: Lazy<BigUint> = Lazy::new(|| {
        // FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
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
            0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18,
            0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77, 0x2C,
            0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5,
            0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
            0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA,
            0x05, 0x10, 0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
            0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB,
            0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
            0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09,
            0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26,
            0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76,
            0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
            0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9,
            0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC,
            0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ])
    });

    /// g3 is the generator
    pub static G3: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u8));

    // TODO check if cofactor is needed.
    pub const COFACTOR: u8 = 2;

    // TODO why is this called subprime, isn't it the order?
    /// q is the subprime.
    pub static Q: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_bytes_be(&[
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4,
            0x61, 0x1A, 0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68, 0x94, 0x81, 0x27, 0x04,
            0x45, 0x33, 0xE6, 0x3A, 0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91, 0x28, 0xA5,
            0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E, 0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
            0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B, 0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8,
            0xE1, 0x22, 0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63, 0x7A, 0x26, 0x21, 0x74,
            0xD3, 0x1B, 0xF6, 0xB5, 0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6, 0xF7, 0x1C,
            0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2, 0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
            0x24, 0x94, 0x33, 0x28, 0xF6, 0x72, 0x2D, 0x9E, 0xE1, 0x00, 0x3E, 0x5C, 0x50, 0xB1,
            0xDF, 0x82, 0xCC, 0x6D, 0x24, 0x1B, 0x0E, 0x2A, 0xE9, 0xCD, 0x34, 0x8B, 0x1F, 0xD4,
            0x7E, 0x92, 0x67, 0xAF, 0xC1, 0xB2, 0xAE, 0x91, 0xEE, 0x51, 0xD6, 0xCB, 0x0E, 0x31,
            0x79, 0xAB, 0x10, 0x42, 0xA9, 0x5D, 0xCF, 0x6A, 0x94, 0x83, 0xB8, 0x4B, 0x4B, 0x36,
            0xB3, 0x86, 0x1A, 0xA7, 0x25, 0x5E, 0x4C, 0x02, 0x78, 0xBA, 0x36, 0x04, 0x65, 0x0C,
            0x10, 0xBE, 0x19, 0x48, 0x2F, 0x23, 0x17, 0x1B, 0x67, 0x1D, 0xF1, 0xCF, 0x3B, 0x96,
            0x0C, 0x07, 0x43, 0x01, 0xCD, 0x93, 0xC1, 0xD1, 0x76, 0x03, 0xD1, 0x47, 0xDA, 0xE2,
            0xAE, 0xF8, 0x37, 0xA6, 0x29, 0x64, 0xEF, 0x15, 0xE5, 0xFB, 0x4A, 0xAC, 0x0B, 0x8C,
            0x1C, 0xCA, 0xA4, 0xBE, 0x75, 0x4A, 0xB5, 0x72, 0x8A, 0xE9, 0x13, 0x0C, 0x4C, 0x7D,
            0x02, 0x88, 0x0A, 0xB9, 0x47, 0x2D, 0x45, 0x55, 0x62, 0x16, 0xD6, 0x99, 0x8B, 0x86,
            0x82, 0x28, 0x3D, 0x19, 0xD4, 0x2A, 0x90, 0xD5, 0xEF, 0x8E, 0x5D, 0x32, 0x76, 0x7D,
            0xC2, 0x82, 0x2C, 0x6D, 0xF7, 0x85, 0x45, 0x75, 0x38, 0xAB, 0xAE, 0x83, 0x06, 0x3E,
            0xD9, 0xCB, 0x87, 0xC2, 0xD3, 0x70, 0xF2, 0x63, 0xD5, 0xFA, 0xD7, 0x46, 0x6D, 0x84,
            0x99, 0xEB, 0x8F, 0x46, 0x4A, 0x70, 0x25, 0x12, 0xB0, 0xCE, 0xE7, 0x71, 0xE9, 0x13,
            0x0D, 0x69, 0x77, 0x35, 0xF8, 0x97, 0xFD, 0x03, 0x6C, 0xC5, 0x04, 0x32, 0x6C, 0x3B,
            0x01, 0x39, 0x9F, 0x64, 0x35, 0x32, 0x29, 0x0F, 0x95, 0x8C, 0x0B, 0xBD, 0x90, 0x06,
            0x5D, 0xF0, 0x8B, 0xAB, 0xBD, 0x30, 0xAE, 0xB6, 0x3B, 0x84, 0xC4, 0x60, 0x5D, 0x6C,
            0xA3, 0x71, 0x04, 0x71, 0x27, 0xD0, 0x3A, 0x72, 0xD5, 0x98, 0xA1, 0xED, 0xAD, 0xFE,
            0x70, 0x7E, 0x88, 0x47, 0x25, 0xC1, 0x68, 0x90, 0x54, 0x9D, 0x69, 0x65, 0x7F, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ])
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
            other.modpow(&self.private, &P)
        }
    }
}

/// `constant` module provides constant-time operations.
// TODO check at some moment that it's okay to encode points/scalars to preserve proper constant-time guarantees.
pub mod constant {
    use num_bigint::BigInt;

    use super::{ed448, verify_nonzero, CryptoError};

    /// `compare_different_scalars` compares two scalars in constant-time by encoding them then
    /// constant-time-comparing the byte-arrays.
    ///
    /// # Errors
    /// Error in case scalars fail verification.
    ///
    /// # Panics
    /// Panics if instances `s1` and `s2` are the same.
    pub fn compare_scalars_distinct(s1: &BigInt, s2: &BigInt) -> Result<(), CryptoError> {
        assert!(!core::ptr::eq(s1, s2), "BUG: s1 and s2 are same instance");
        compare_scalars(s1, s2)
    }

    /// `compare_scalars` compares two scalars in constant time and returns result.
    ///
    /// # Errors
    /// In case comparison fails, i.e. scalars are not equal.
    pub fn compare_scalars(s1: &BigInt, s2: &BigInt) -> Result<(), CryptoError> {
        let (sign1, encoded1) = s1.to_bytes_le();
        let (sign2, encoded2) = s2.to_bytes_le();
        if sign1 != sign2 {
            return Err(CryptoError::VerificationFailure(
                "verification of scalars failed",
            ));
        }
        compare(&encoded1, &encoded2, "verification of scalars failed")
    }

    /// `compare_different_points` checks if two points are the same in constant-time by comparing
    /// the byte-arrays of the encoded points in constant-time.
    ///
    /// # Errors
    /// Error in case points fail verification.
    ///
    /// # Panics
    /// Panics if instances `p1` and `p2` are the same.
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

#[derive(Debug)]
pub enum CryptoError {
    VerificationFailure(&'static str),
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use crate::{
        crypto,
        encoding::{self, OTRDecoder, OTREncodable, OTREncoder},
        utils::{
            self,
            biguint::{ONE, TWO, ZERO},
        },
    };
    use num_bigint::BigUint;

    use super::{
        constant, dh,
        ed448::{self, Point, RingSignature},
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
    #[should_panic(expected = "BUG: references provided for verification must be different.")]
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
    #[should_panic(expected = "BUG: data1 and data2 parameters are same instance")]
    fn test_zero_length_slices() {
        constant::compare_bytes_distinct(&[], &[]).unwrap();
    }

    #[test]
    #[should_panic(expected = "BUG: data1 and data2 parameters are same instance")]
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
        assert!((&point * ed448::order()).is_identity());
        assert_eq!(ed448::identity(), &(&point + &-&point));
    }

    #[test]
    fn test_scalar_multiplication() {
        let n = ed448::random_in_Zq();
        let p = ed448::generator() * &n;
        assert_eq!(&p + &p, &p * &*utils::bigint::TWO);
        assert_eq!(&p + &p + &p, &p * &*utils::bigint::THREE);
        assert_eq!(&p + &p + &p + &p, &p * &*utils::bigint::FOUR);
        assert_eq!(&p + &p + &p + &p + &p, &p * &*utils::bigint::FIVE);
        assert_eq!(&p + &p + &p + &p + &p + &p, &p * &*utils::bigint::SIX);
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::bigint::SEVEN
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::bigint::EIGHT
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::bigint::NINE
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::bigint::TEN
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::bigint::ELEVEN
        );
        assert_eq!(
            &p + &p + &p + &p + &p + &p + &p + &p + &p + &p + &p + &p,
            &p * &*utils::bigint::TWELVE
        );
    }

    #[test]
    fn test_ring_sign_verify() -> Result<(), CryptoError> {
        let keypair = ed448::EdDSAKeyPair::generate();
        let a2 = ed448::ECDHKeyPair::generate();
        let a3 = ed448::ECDHKeyPair::generate();
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
        let keypair = ed448::EdDSAKeyPair::generate();
        let a1_public = keypair.public().clone();
        let a2 = ed448::ECDHKeyPair::generate();
        let a3 = ed448::ECDHKeyPair::generate();
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
        let keypair = ed448::EdDSAKeyPair::generate();
        let a2 = ed448::ECDHKeyPair::generate();
        let a3 = ed448::ECDHKeyPair::generate();
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
    #[should_panic(expected = "BUG: illegal combination of public keys.")]
    fn test_ring_sign_verify_incorrect_public_key_1() {
        let m = utils::random::secure_bytes::<250>();
        let keypair = ed448::EdDSAKeyPair::generate();
        let a1 = ed448::ECDHKeyPair::generate();
        let a2 = ed448::ECDHKeyPair::generate();
        let a3 = ed448::ECDHKeyPair::generate();
        RingSignature::sign(&keypair, a1.public(), a2.public(), a3.public(), &m).unwrap();
    }

    #[test]
    fn test_sign_verify_EdDSAKeyPair() {
        let keypair = ed448::EdDSAKeyPair::generate();
        let m = utils::random::secure_bytes::<50>();
        assert!(utils::bytes::any_nonzero(&m));
        let signature = keypair.sign(&m);
        ed448::validate(keypair.public(), &signature, &m).unwrap();
    }

    #[test]
    fn test_encode_decode_EdDSA_signature() {
        let keypair = ed448::EdDSAKeyPair::generate();
        let m = utils::random::secure_bytes::<50>();
        assert!(utils::bytes::any_nonzero(&m));
        let storesig = keypair.sign(&m);
        let encoded = encoding::OTREncoder::new()
            .write_encodable(&storesig)
            .to_vec();
        let mut dec = encoding::OTRDecoder::new(&encoded);
        let restoresig = ed448::Signature::decode(&mut dec).unwrap();
        dec.done().unwrap();
        ed448::validate(keypair.public(), &restoresig, &m).unwrap();
    }

    #[test]
    fn test_sign_verify_EdDSAKeyPair_sigs_noninterchangeable() {
        let kp1 = ed448::EdDSAKeyPair::generate();
        let kp2 = ed448::EdDSAKeyPair::generate();
        let m = utils::random::secure_bytes::<50>();
        let sig1 = kp1.sign(&m);
        let sig2 = kp2.sign(&m);
        ed448::validate(kp1.public(), &sig1, &m).unwrap();
        ed448::validate(kp2.public(), &sig2, &m).unwrap();
        ed448::validate(kp2.public(), &sig1, &m).unwrap_err();
        ed448::validate(kp1.public(), &sig2, &m).unwrap_err();
    }

    #[test]
    fn test_verify_signature_static() {
        //let m = utils::random::secure_bytes::<200>();
        //dbg!(&hex::encode(m));
        let m = hex::decode("6af513ac165479d6cfa4e47aaafc1beea2860062f6f3f163fa8edb9a8e9b5281952da13d3ff1d90f2cde03aa6c82aab5dc7817c8f4a09a625f85c3ceb7d33987d83a5b387e529ae41ae9abb45842373723b4e3c80514ac9fa69ebb3282eae231a235b494b41fd0fb4c5a74bdc1a631b052554bdd407cf1d9af2d52734c76e3f756a232bd382b24f360f465c010aef41149a1878cfd209e4f38591b61f0be980efcfcb9ac6abd513434dfb5353be51b80c54866aab0e30cd05aa95d35ea8a6f4431df50eb1ea8a794").unwrap();
        //let keypair = ed448::EdDSAKeyPair::generate();
        //let pk_encoded = keypair.public().encode();
        //dbg!(&hex::encode(pk_encoded));
        let pk_encoded: [u8; 57] = hex::decode("d1c5cf379dfdc749615e0aa9f2d37e1f4999a830966ddef392e7f071b9675c40fea1c493cca2cc47e63478a69c47c9abfbf29cf5525e1cab00").unwrap().try_into().unwrap();
        //let signature = keypair.sign(&m);
        //dbg!(&hex::encode(
        //    OTREncoder::new().write_encodable(&signature).to_vec()
        //));
        let signature = hex::decode("492280a466d0cb22a485865329ab3a54a447154017b3965f0b626fa2a2ae7af1b6dc81a097a8dfa7c9436c1d66fbd9e4301aae82e9f187a500e4a787359120c41c56c6aefa7441ed6ee5ac1ab60457031cd6c6a1aecb044e23a201210ca508685539b27e2eea12672300bc7f38688cde3200").unwrap();
        //let decoded_signature = ed448::Signature::decode(&mut OTRDecoder::new(
        //    &OTREncoder::new().write_encodable(&signature).to_vec(),
        //))
        let decoded_signature = ed448::Signature::decode(&mut OTRDecoder::new(&signature)).unwrap();
        let decoded_point = ed448::Point::decode(&pk_encoded).unwrap();
        ed448::validate(&decoded_point, &decoded_signature, &m).unwrap();
    }

    #[test]
    fn test_verify_signature_dynamic() {
        let m = utils::random::secure_bytes::<200>();
        let keypair = ed448::EdDSAKeyPair::generate();
        let signature = keypair.sign(&m);
        let pk_encoded = keypair.public().encode();
        let mut enc = OTREncoder::new();
        signature.encode(&mut enc);
        let decoded_signature =
            ed448::Signature::decode(&mut OTRDecoder::new(&enc.to_vec())).unwrap();
        let decoded_point = ed448::Point::decode(&pk_encoded).unwrap();
        ed448::validate(&decoded_point, &decoded_signature, &m).unwrap();
    }

    #[test]
    fn test_decode_point_from_otr4j() {
        let encoded_vec: Vec<u8> = [
            -34, -104, -16, -124, 35, -103, 75, 116, -80, -57, -19, 11, 97, 86, -64, 37, 12, -123,
            107, -100, 115, -78, -15, 58, -91, 95, 22, 34, 127, -26, 47, -64, 37, 39, -90, 59, 75,
            44, 90, 112, -122, 103, 115, 77, -124, -62, -98, 126, -43, 8, 42, -18, 68, -120, 75,
            90, 0,
        ]
        .into_iter()
        .map(|v: i8| u8::from_be_bytes(v.to_be_bytes()))
        .collect();
        let mut encoded = [0u8; 57];
        encoded.clone_from_slice(&encoded_vec);
        let p = Point::decode(&encoded).unwrap();
        ed448::verify(&p).unwrap();
    }

    #[test]
    fn test_decode_signature_from_otr4j() {
        let signature_vec: Vec<u8> = [
            40, -83, 48, -110, 68, 96, 18, -103, 36, -23, 37, -106, 110, 2, -80, -43, 50, 118, 65,
            -98, -119, 76, -104, 70, 85, -67, -120, -118, -26, 32, 105, -56, 103, 65, -58, -32,
            -58, -117, 121, 76, 94, -57, 98, -53, -22, 9, 10, 44, -16, 73, -7, -89, 24, 99, -13,
            -119, -128, -13, -114, -40, -77, -37, -5, -15, 66, 86, -53, -79, -14, 122, -43, -97,
            107, -111, -1, -66, -107, 51, -81, 14, -118, 92, -117, -108, -16, 124, -104, -126, -26,
            125, 18, -4, 85, -76, 39, 72, -115, 30, 69, -55, 37, 36, 38, 83, -56, -72, -3, 24, 81,
            51, -78, -52, 48, 0,
        ]
        .into_iter()
        .map(|v: i8| u8::from_be_bytes(v.to_be_bytes()))
        .collect();
        let mut signature = [0u8; 114];
        signature.clone_from_slice(&signature_vec);
        ed448::Signature::decode(&mut OTRDecoder::new(&signature)).unwrap();
    }
}

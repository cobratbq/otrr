// SPDX-License-Identifier: LGPL-3.0-only

use std::fmt::Debug;

use once_cell::sync::Lazy;
use ring::rand::SystemRandom;

use crate::utils;

static RAND: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);

// FIXME double-check all big-endian/little-endian use. (generate ECDH uses little-endian)

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
        pub public: BigUint,
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

    use crate::encoding::OTREncoder;

    use super::{aes128, dsa, sha1, sha256};

    pub struct AKESecrets {
        pub ssid: [u8; 8],
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

    #[derive(Debug)]
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
    // TODO consider if we want to keep 3 functions (kdf, hwc, hcmac) if they have same logic. (see spec)

    use super::{ed448, shake256};

    const USAGE_FINGERPRINT: u8 = 0x00;
    pub const USAGE_SMP_SECRET: u8 = 0x19;

    const PREFIX: [u8; 5] = [b'O', b'T', b'R', b'v', b'4'];

    #[must_use]
    pub fn fingerprint(public_key: &ed448::Point, forging_key: &ed448::Point) -> [u8; 56] {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&public_key.encode());
        buffer.extend_from_slice(&forging_key.encode());
        hwc::<56>(USAGE_FINGERPRINT, &buffer)
    }

    pub fn hwc<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        kdf::<N>(usage, data)
    }

    pub fn hcmac<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        kdf::<N>(usage, data)
    }

    // TODO is pruning done after `kdf` in all cases? move into kdf function?
    pub fn kdf<const N: usize>(usage: u8, data: &[u8]) -> [u8; N] {
        let mut buffer = Vec::with_capacity(6 + data.len());
        buffer.extend_from_slice(&PREFIX);
        buffer.push(usage);
        buffer.extend_from_slice(data);
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

    use crate::{
        crypto::otr4::hwc,
        encoding::OTREncodable,
        utils::{self, bigint::ONE, bytes},
    };

    use super::{shake256, CryptoError};

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

    pub struct PublicKey(Point);

    impl OTREncodable for PublicKey {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write_u16_le(0x0010);
            encoder.write_ed448_point(&self.0);
        }
    }

    impl PublicKey {
        #[must_use]
        pub fn from(data: &[u8]) -> Self {
            // FIXME implement `from` for deserializing Ed448 public key
            todo!("implement conversion from raw bytes")
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
        #[must_use]
        pub fn from(data: &[u8]) -> Self {
            // FIXME implement `from` for deserializing Ed448 forging key
            todo!("implement conversion from raw bytes")
        }
    }

    // TODO do we want the tuple types private or public?
    pub struct Signature([u8; 2 * LENGTH_BYTES]);

    impl OTREncodable for Signature {
        fn encode(&self, encoder: &mut crate::encoding::OTREncoder) {
            encoder.write(&self.0);
        }
    }

    impl Signature {
        #[must_use]
        pub fn from(data: &[u8]) -> Self {
            // FIXME implement `from` for deserializing Ed448 signature
            todo!("implement conversion from raw bytes")
        }
    }

    /// `verify` checks the provided Point for correctness.
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

    // TODO pruning is not strictly necessary because the scalars resulting from hash_to_scalar are not used on the curve, merely as proofs.
    #[must_use]
    pub fn hash_to_scalar(purpose: u8, data: &Point) -> BigUint {
        decode_scalar(&hwc::<57>(purpose, &data.encode()))
    }

    #[must_use]
    pub fn hash_to_scalar2(purpose: u8, data1: &Point, data2: &Point) -> BigUint {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&data1.encode());
        buffer.extend_from_slice(&data2.encode());
        decode_scalar(&hwc::<57>(purpose, &buffer))
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

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Point {
        x: BigUint,
        y: BigUint,
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

    // FIXME SMP4 can be simplified (less parentheses) if we can automatically use &Point if adder is Point
    impl<'a, 'b> Add<&'b Point> for &'a Point {
        type Output = Point;

        fn add(self, rhs: &'b Point) -> Self::Output {
            self.add0(rhs)
        }
    }

    impl Neg for Point {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self {
                x: &*P - self.x,
                y: self.y,
            }
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
            // FIXME check if `.modpow` is more efficient given large numbers.
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
                Ok(Point { x: (&*P - &x), y })
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

    /// `random_in_Zq` generates a random value in Z_q and returns this as `BigUint` unsigned
    /// integer value. The value is pruned as to be guaranteed safe for use in curve Ed448.
    ///
    /// # Panics
    /// Panics if invalid input data is provided. (sanity-checks)
    #[allow(non_snake_case)]
    #[must_use]
    pub fn random_in_Zq() -> BigUint {
        let mut h = shake256::digest::<57>(&utils::random::secure_bytes::<57>());
        prune(&mut h);
        assert!(bytes::any_nonzero(&h));
        BigUint::from_bytes_le(&h).mod_floor(&Q)
    }

    /// `prune` prunes a byte-array that represents an encoded scalar value to ensure
    /// that the scalar, when decoded, produces a valid scalar value.
    ///
    /// # Panics
    /// Panics if invalid input is provided. (sanity-checks)
    pub fn prune(v: &mut [u8]) {
        assert_eq!(57, v.len());
        assert!(bytes::any_nonzero(v));
        v[0] &= 0b1111_1100;
        v[55] |= 0b1000_0000;
        v[56] = 0;
    }
}

// FIXME change name to refer to group identifier or something from otrv4
pub mod dh2 {
    use num_bigint::BigUint;
    use once_cell::sync::Lazy;

    /// p is the prime (modulus).
    pub static P: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_radix_be(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16).unwrap()
    });

    /// g3 is the generator
    pub const G3: u8 = 2;

    // TODO check if cofactor is needed.
    pub const COFACTOR: u8 = 2;

    // TODO why is this called subprime, isn't it the order?
    /// q is the subprime.
    pub static Q: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_radix_be(b"7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880AB9472D45556216D6998B8682283D19D42A90D5EF8E5D32767DC2822C6DF785457538ABAE83063ED9CB87C2D370F263D5FAD7466D8499EB8F464A702512B0CEE771E9130D697735F897FD036CC504326C3B01399F643532290F958C0BBD90065DF08BABBD30AEB63B84C4605D6CA371047127D03A72D598A1EDADFE707E884725C16890549D69657FFFFFFFFFFFFFFF", 16).unwrap()
    });
}

/// `constant` module provides constant-time operations.
// TODO check at some moment that it's okay to encode points/scalars to preserve proper constant-time guarantees.
pub mod constant {
    use num_bigint::BigUint;

    use super::{ed448, verify_nonzero, CryptoError};

    /// `compare_scalars` compares two scalars in constant-time by encoding them then
    /// constant-time-comparing the byte-arrays.
    pub fn verify_scalars(scalar1: &BigUint, scalar2: &BigUint) -> Result<(), CryptoError> {
        assert!(
            !core::ptr::eq(scalar1, scalar2),
            "BUG: p1 and p2 are same instance"
        );
        verify_bytes(&scalar1.to_bytes_le(), &scalar2.to_bytes_le())
    }

    /// `compare_points` checks if two points are the same in constant-time by comparing the
    /// byte-arrays of the encoded points in constant-time.
    ///
    /// # Panics
    /// Panics if instances `p1` and `p2` are the same.
    pub fn verify_points(p1: &ed448::Point, p2: &ed448::Point) -> Result<(), CryptoError> {
        assert!(!core::ptr::eq(p1, p2), "BUG: p1 and p2 are same instance");
        verify_bytes(&p1.encode(), &p2.encode())
    }

    /// `verify` verifies two same-length byte-slices in constant-time.
    ///
    /// # Errors
    /// `CryptoError` in case verification fails. Failure-cases: provide same instance twice,
    /// provide all-zero byte-arrays, provide equal slices.
    ///
    /// # Panics
    /// Panics if two provided byte-slices are same instance. (To prevent accidental programming errors.)
    pub fn verify_bytes(data1: &[u8], data2: &[u8]) -> Result<(), CryptoError> {
        assert!(
            !core::ptr::eq(data1, data2),
            "BUG: data1 and data2 parameters are same instance"
        );
        verify_nonzero(data1)?;
        verify_nonzero(data2)?;
        ring::constant_time::verify_slices_are_equal(data1, data2).or(Err(
            CryptoError::VerificationFailure("data verification failed"),
        ))
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
        crypto::{
            self,
            ed448::{prime_order, verify},
        },
        utils::{
            self,
            biguint::{ONE, TWELVE, TWO, ZERO},
        },
    };
    use num_bigint::BigUint;

    use super::{constant, dh, ed448};

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
        assert!(dh::verify_public_key(&k1.public).is_ok());
        let k2 = dh::Keypair::generate();
        assert!(dh::verify_public_key(&k2.public).is_ok());
        let k3 = dh::Keypair::generate();
        assert!(dh::verify_public_key(&k3.public).is_ok());
        let k4 = dh::Keypair::generate();
        assert!(dh::verify_public_key(&k4.public).is_ok());
        let k5 = dh::Keypair::generate();
        assert!(dh::verify_public_key(&k5.public).is_ok());
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
        constant::verify_bytes(&[], &[]).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_zero_slices() {
        constant::verify_bytes(&[0, 0, 0, 0], &[0, 0, 0, 0]).unwrap();
    }

    #[test]
    fn test_same_length_slices() {
        let s1 = b"Hello world";
        let s2 = *s1;
        constant::verify_bytes(s1, &s2).unwrap();
    }

    #[test]
    fn test_different_content() {
        assert!(constant::verify_bytes(b"Hello!", b"Yo!").is_err());
    }

    #[test]
    fn test_differing_length_slices() {
        assert!(constant::verify_bytes(b"Hello!", b"Hello").is_err());
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
}

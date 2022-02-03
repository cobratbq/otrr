// TODO add safety assertions that prevent working with all-zero byte-arrays.
// TODO verify implementation
// TODO what constant-time implementations needed?

#[allow(non_snake_case)]
pub mod DH {

    use once_cell::sync::Lazy;

    use num_bigint::BigUint;
    use ring::rand::{SecureRandom, SystemRandom};

    use super::CryptoError;

    // FIXME generator: should we expose through function only the reference to this?
    /// GENERATOR (g): 2
    pub static GENERATOR: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u8));

    /// Modulus
    pub static MODULUS: Lazy<BigUint> = Lazy::new(|| {
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
    pub static MODULUS_MINUS_TWO: Lazy<BigUint> = Lazy::new(|| &*MODULUS - BigUint::from(2u8));

    static RAND: Lazy<SystemRandom> = Lazy::new(|| SystemRandom::new());

    pub fn verify_public_key(public_key: &BigUint) -> Result<(), CryptoError> {
        return if public_key > &*GENERATOR && public_key <= &MODULUS_MINUS_TWO {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "DH public key fails verification.",
            ))
        };
    }

    pub struct Keypair {
        generator: BigUint,
        private: BigUint,
        pub public: BigUint,
    }

    impl Keypair {
        pub fn generate() -> Self {
            let mut v = [0u8; 192];
            RAND.fill(&mut v)
                .expect("Failed to produce random bytes for random big unsigned integer value.");
            Self::new(BigUint::from_bytes_be(&v))
        }

        pub fn new(private: BigUint) -> Self {
            Self::new_custom(private, (*GENERATOR).clone())
        }

        pub fn new_custom(private: BigUint, generator: BigUint) -> Self {
            let public = generator.modpow(&private, &MODULUS);
            Self {
                generator,
                private,
                public,
            }
        }

        pub fn generate_shared_secret(&self, public_key: &BigUint) -> SharedSecret {
            public_key.modpow(&self.private, &MODULUS)
        }
    }

    pub type SharedSecret = BigUint;

    // TODO needs constant-time?
    pub fn verify(expected: &BigUint, actual: &BigUint) -> Result<(), CryptoError> {
        if expected == actual {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "Provided values are not equal.",
            ))
        }
    }
}

pub mod OTR {
    use super::{AES128, SHA256};

    pub struct DerivedSecrets {
        pub ssid: [u8; 8],
        pub c: AES128::Key,
        pub cp: AES128::Key,
        pub m1: [u8; 32],
        pub m1p: [u8; 32],
        pub m2: [u8; 32],
        pub m2p: [u8; 32],
    }

    impl Drop for DerivedSecrets {
        fn drop(&mut self) {
            self.ssid = [0u8; 8];
            self.m1 = [0u8; 32];
            self.m1p = [0u8; 32];
            self.m2 = [0u8; 32];
            self.m2p = [0u8; 32];
        }
    }

    impl DerivedSecrets {
        /// Derive the shared secrets used by OTRv3 that are based on the shared secret from the DH key exchange.
        pub fn derive_secrets(secbytes: &[u8]) -> DerivedSecrets {
            let h2secret0 = h2(0x00, &secbytes);
            let h2secret1 = h2(0x01, &secbytes);
            DerivedSecrets {
                ssid: h2secret0[..8].try_into().unwrap(),
                c: AES128::Key(h2secret1[..16].try_into().unwrap()),
                cp: AES128::Key(h2secret1[16..].try_into().unwrap()),
                m1: h2(0x02, &secbytes),
                m2: h2(0x03, &secbytes),
                m1p: h2(0x04, &secbytes),
                m2p: h2(0x05, &secbytes),
            }
        }
    }

    fn h2(b: u8, secbytes: &[u8]) -> [u8; 32] {
        let mut bytes = vec![b];
        bytes.extend_from_slice(secbytes);
        return SHA256::digest(&bytes);
    }
}

#[allow(non_snake_case)]
pub mod AES128 {
    use aes_ctr::{
        cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher},
        Aes128Ctr,
    };
    use once_cell::sync::Lazy;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::ops::Drop;

    const KEY_LENGTH: usize = 16;

    type Nonce = [u8; 16];

    static RAND: Lazy<SystemRandom> = Lazy::new(|| SystemRandom::new());

    #[derive(Clone)]
    pub struct Key(pub [u8; KEY_LENGTH]);

    impl Key {
        pub fn generate() -> Self {
            let mut key = [0u8; 16];
            RAND.fill(&mut key)
                .expect("Failed to acquire random bytes.");
            return Key(key);
        }

        pub fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            return self.crypt(nonce, data);
        }

        pub fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            return self.crypt(nonce, data);
        }

        /// crypt provides both encrypting and decrypting logic.
        fn crypt(&self, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
            let mut result = Vec::from(data);
            let key = GenericArray::from_slice(&self.0);
            let nonce = GenericArray::from_slice(nonce);
            let mut cipher = Aes128Ctr::new(&key, &nonce);
            cipher.apply_keystream(result.as_mut_slice());
            return result;
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // TODO does this form of zeroing work?
            self.0 = [0u8; KEY_LENGTH];
        }
    }
}

// TODO do we need to verify any of the DSA components, also for encoding/decoding?
#[allow(non_snake_case)]
pub mod DSA {
    use num_bigint::BigUint;

    use super::CryptoError;

    /// Signature type represents a DSA signature in IEEE-P1363 representation.
    pub const SIGNATURE_PARAM_Q_LEN: usize = 20;
    pub const SIGNATURE_LEN: usize = 2 * SIGNATURE_PARAM_Q_LEN;
    pub type Signature = [u8; SIGNATURE_LEN];

    type Hash = [u8; 32];

    pub struct Keypair {}

    impl Keypair {
        pub fn generate() -> Self {
            todo!()
        }

        pub fn public_key(&self) -> PublicKey {
            todo!()
        }

        pub fn sign(&self, content: &Hash) -> Result<Signature, CryptoError> {
            // FIXME implement signing
            todo!()
        }
    }

    // FIXME do not make fields public to further encapsulate, protect against inconsistent changes.
    pub struct PublicKey {
        pub p: BigUint,
        pub q: BigUint,
        pub g: BigUint,
        pub y: BigUint,
    }

    impl PublicKey {
        pub fn verify(&self, signature: &Signature, content: &Hash) -> Result<(), CryptoError> {
            // FIXME implement verification
            todo!()
        }
    }
}

// TODO Fingerprint = SHA1(byte-level representation of Public Key without 0x0000 which is the short-type pubkey type identifier)
#[allow(non_snake_case)]
pub mod SHA1 {

    type Digest = [u8; 20];

    pub fn digest(data: &[u8]) -> Digest {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        let mut result: Digest = [0u8; 20];
        result.clone_from_slice(digest.as_ref());
        return result;
    }
}

#[allow(non_snake_case)]
pub mod SHA256 {
    use super::CryptoError;

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

    /// hmac calculates the SHA256-HMAC value, using key 'm1' as documented in OTRv3 spec.
    pub fn hmac(m1: &[u8], data: &[u8]) -> Digest {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m1);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 32];
        result.clone_from_slice(digest.as_ref());
        return result;
    }

    /// hmac160 calculates the first 160 bits of the SHA256-HMAC value, using key 'm2' as documented in OTRv3 spec.
    pub fn hmac160(m2: &[u8], data: &[u8]) -> [u8; 20] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m2);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8; 20];
        result.clone_from_slice(&digest.as_ref()[..20]);
        return result;
    }

    pub fn verify(expected: &[u8], actual: &[u8]) -> Result<(), CryptoError> {
        // TODO implement comparison in constant-time(?)
        return if expected == actual {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailure(
                "Hash does not match the expected hash value.",
            ))
        };
    }
}

#[derive(std::fmt::Debug)]
pub enum CryptoError {
    VerificationFailure(&'static str),
}

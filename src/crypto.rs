
#[allow(non_snake_case)]
pub mod DH {

    pub fn generate() -> Keypair {
        todo!()
    }

    pub struct Keypair {
        private: num_bigint::BigUint,
        pub public: num_bigint::BigUint,
    }
}

#[allow(non_snake_case)]
pub mod AES128 {
    use aes_ctr::{Aes128Ctr, cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher}};

    /// crypt provides both encrypting and decrypting logic.
    pub fn crypt(key: &[u8;16], nonce: &[u8;16], data: &[u8]) -> Vec<u8> {
        let mut result = Vec::from(data);
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(nonce);
        let mut cipher = Aes128Ctr::new(&key, &nonce);
        cipher.apply_keystream(result.as_mut_slice());
        return result;
    }
}

#[allow(non_snake_case)]
pub mod DSA {

}

#[allow(non_snake_case)]
pub mod SHA1 {

    pub fn digest(data: &[u8]) -> [u8;20] {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        let mut result = [0u8;20];
        result.clone_from_slice(digest.as_ref());
        return result;
    }
}

#[allow(non_snake_case)]
pub mod SHA256 {

    /// digest calculates the SHA256 digest value.
    pub fn digest(data: &[u8]) -> [u8;32] {
        let digest = ring::digest::digest(&ring::digest::SHA256, data);
        let mut result = [0u8;32];
        result.clone_from_slice(digest.as_ref());
        return result;
    }

    /// hmac calculates the SHA256-HMAC value, using key 'm1' as documented in OTRv3 spec.
    pub fn hmac(m1: &[u8], data: &[u8]) -> [u8;32] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m1);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8;32];
        result.clone_from_slice(digest.as_ref());
        return result;
    }

    /// hmac160 calculates the first 160 bits of the SHA256-HMAC value, using key 'm2' as documented in OTRv3 spec.
    pub fn hmac160(m2: &[u8], data: &[u8]) -> [u8;20] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m2);
        let digest = ring::hmac::sign(&key, data);
        let mut result = [0u8;20];
        result.clone_from_slice(&digest.as_ref()[..20]);
        return result;
    }
}

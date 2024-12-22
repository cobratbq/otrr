// SPDX-License-Identifier: LGPL-3.0-only

pub mod alloc {
    #[must_use]
    pub fn vec_unique<T: Ord>(mut src: Vec<T>) -> Vec<T> {
        src.sort_unstable();
        src.dedup();
        src
    }
}

pub mod bytes {
    use core::cmp::Ordering;

    pub fn verify_nonzero<E>(data: &[u8], error: E) -> Result<(), E> {
        if any_nonzero(data) {
            Ok(())
        } else {
            Err(error)
        }
    }

    #[must_use]
    pub fn any_nonzero(data: &[u8]) -> bool {
        !all_zero(data)
    }

    #[must_use]
    pub fn all_zero(data: &[u8]) -> bool {
        for b in data {
            if *b != 0 {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn drop_by_value(data: &[u8], v: u8) -> Vec<u8> {
        let mut result = Vec::new();
        data.iter()
            .filter(|b| **b != v)
            .for_each(|b| result.push(*b));
        result
    }

    /// `cmp` compares two equal-length byte-slices for each pair of values by index.
    ///
    /// # Panics
    ///
    /// Will panic when two references to the same slice are provided.
    #[must_use]
    pub fn cmp(data1: &[u8], data2: &[u8]) -> Ordering {
        // guard against accidentally comparing the same reference against itself. Apart from the
        // obvious result, it may be indicative of a programming error.
        assert!(!core::ptr::eq(data1, data2));
        assert_eq!(data1.len(), data2.len());
        for i in 0..data1.len() {
            if data1[i] < data2[i] {
                return Ordering::Less;
            }
            if data1[i] > data2[i] {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }

    /// `clear` fills provided byte-array with zeroes.
    pub fn clear(b: &mut [u8]) {
        b.fill(0);
    }

    /// `concatenate` concatenates three byte-arrays into a new byte-array.
    pub fn concatenate(v1: &[u8], v2: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(v1);
        buffer.extend_from_slice(v2);
        buffer
    }

    /// `concatenate3` concatenates three byte-arrays into a new byte-array.
    pub fn concatenate3(v1: &[u8], v2: &[u8], v3: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(v1);
        buffer.extend_from_slice(v2);
        buffer.extend_from_slice(v3);
        buffer
    }

    /// `concatenate4` concatenates three byte-arrays into a new byte-array.
    pub fn concatenate4(v1: &[u8], v2: &[u8], v3: &[u8], v4: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(v1);
        buffer.extend_from_slice(v2);
        buffer.extend_from_slice(v3);
        buffer.extend_from_slice(v4);
        buffer
    }

    /// `dump_hex` dumps a byte-array as hexadecimal value. (0xVALUE)
    pub fn dump_hex(lbl: &str, v: &[u8]) {
        eprintln!("{lbl} ({}): 0x{}", v.len(), hex::encode(v));
    }

    #[cfg(test)]
    mod tests {
        use hex::FromHex;

        #[test]
        fn dev_split_up_hexadecimal_string_into_byte_literals() {
            let v = Vec::from_hex(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF").unwrap();
            for b in v {
                print!("0x{b:02X?}, ");
            }
        }
    }
}

pub mod bigint {
    use std::sync::LazyLock;

    use num_bigint::BigInt;

    pub static ZERO: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(0u8));
    pub static ONE: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(1u8));
    pub static TWO: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(2u8));
    pub static THREE: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(3u8));
    pub static FOUR: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(4u8));
    pub static FIVE: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(5u8));
    pub static SIX: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(6u8));
    pub static SEVEN: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(7u8));
    pub static EIGHT: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(8u8));
    pub static NINE: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(9u8));
    pub static TEN: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(10u8));
    pub static ELEVEN: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(11u8));
    pub static TWELVE: LazyLock<BigInt> = LazyLock::new(|| BigInt::from(12u8));

    pub fn to_bytes_le_fixed<const N: usize>(v: &BigInt) -> [u8; N] {
        let mut result = [0u8; N];
        let bytes = v.to_bytes_le().1;
        assert!(result.len() >= bytes.len());
        result[..bytes.len()].copy_from_slice(&bytes);
        result
    }

    // TODO assuming u64-sized limbs, but should be checked because it can be influenced with a flag
    pub fn bit(v: &BigInt, i: usize) -> bool {
        let (limb_idx, bit_idx) = (i / 64, i % 64);
        let limb = v.get_limb(limb_idx);
        (limb & 1 << bit_idx) != 0
    }
}

pub mod biguint {
    use std::sync::LazyLock;

    use num_bigint::BigUint;

    pub static ZERO: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(0u8));
    pub static ONE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(1u8));
    pub static TWO: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(2u8));
    pub static THREE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(3u8));
    pub static FOUR: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(4u8));
    pub static FIVE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(5u8));
    pub static SIX: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(6u8));
    pub static SEVEN: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(7u8));
    pub static EIGHT: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(8u8));
    pub static NINE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(9u8));
    pub static TEN: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(10u8));
    pub static ELEVEN: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(11u8));
    pub static TWELVE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(12u8));

    pub fn to_bytes_be_fixed<const N: usize>(v: &BigUint) -> [u8; N] {
        let mut buffer = [0u8; N];
        to_bytes_be_into(&mut buffer, v);
        buffer
    }

    pub fn to_bytes_be_into(dst: &mut [u8], v: &BigUint) {
        let bytes = v.to_bytes_be();
        assert!(dst.len() >= bytes.len());
        let start = dst.len() - bytes.len();
        dst[start..].copy_from_slice(&bytes);
    }

    pub fn to_bytes_le_fixed<const N: usize>(v: &BigUint) -> [u8; N] {
        let mut result = [0u8; N];
        let bytes = v.to_bytes_le();
        assert!(result.len() >= bytes.len());
        result[..bytes.len()].copy_from_slice(&bytes);
        result
    }

    pub fn to_bytes_le_into(dst: &mut [u8], v: &BigUint) {
        let bytes = v.to_bytes_le();
        assert!(dst.len() >= bytes.len());
        dst[..bytes.len()].copy_from_slice(&bytes);
    }

    // TODO assuming u64-sized limbs, but should be checked because it can be influenced with a flag
    pub fn bit(v: &BigUint, i: usize) -> bool {
        let (limb_idx, bit_idx) = (i / 64, i % 64);
        let limb = v.get_limb(limb_idx);
        (limb & 1 << bit_idx) != 0
    }
}

pub mod slice {
    /// copy copies the content from source slice to destination slice.
    /// It requires that dst is at least as long as src.
    ///
    /// # Panics
    ///
    /// Will panic if `dst` is smaller than `src`.
    pub fn copy<T: Copy>(dst: &mut [T], src: &[T]) {
        assert!(dst.len() >= src.len());
        let len = src.len();
        dst[..len].copy_from_slice(src);
    }

    /// `fill` fills a slice with specified value.
    pub fn fill<T: Copy>(data: &mut [T], value: T) {
        for i in 0..data.len() {
            data[i] = value;
        }
    }
}

pub mod usize {

    #[must_use]
    pub fn signum(v: usize) -> usize {
        usize::from(v != 0)
    }

    #[cfg(test)]
    mod tests {
        use super::signum;

        #[test]
        fn test_signum() {
            assert_eq!(0, signum(0));
            assert_eq!(1, signum(1));
            assert_eq!(1, signum(99));
            assert_eq!(1, signum(666));
        }
    }
}

pub mod u32 {

    #[must_use]
    pub fn from_4byte_be(bytes: &[u8]) -> u32 {
        assert_eq!(bytes.len(), 4);
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// `nonzero` tests if provided value is a non-zero value. Returns `None` if it was zero or
    /// `Option<value>` if larger.
    #[must_use]
    pub fn nonzero(value: u32) -> Option<u32> {
        if value == 0 {
            None
        } else {
            Some(value)
        }
    }

    /// `verify_nonzero` verifies that `value` is non-zero or returns provided error.
    pub fn verify_nonzero<E>(value: u32, error: E) -> Result<(), E> {
        if value == 0 {
            Err(error)
        } else {
            Ok(())
        }
    }
}

/// `random` provides utils for `ring::rand` secure random generator.
pub mod random {
    use std::sync::LazyLock;

    use ring::rand::{SecureRandom, SystemRandom};

    /// `RANDOM` is an instance of `ring::rand::SystemRandom`.
    pub static RANDOM: LazyLock<SystemRandom> = LazyLock::new(SystemRandom::new);

    /// `secure_bytes` produces the specified number of secure bytes as a byte-array.
    pub fn secure_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        (*RANDOM).fill(&mut bytes).unwrap();
        bytes
    }

    /// `fill_secure_bytes` fills provided buffer with bytes from (secure) random number generator.
    pub fn fill_secure_bytes(buffer: &mut [u8]) {
        (*RANDOM).fill(buffer).unwrap();
    }
}

pub mod time {
    pub fn unix_seconds_now() -> u64 {
        unix_seconds_from(std::time::UNIX_EPOCH)
    }

    pub fn unix_seconds_from(current: std::time::SystemTime) -> u64 {
        std::time::SystemTime::now()
            .duration_since(current)
            .unwrap()
            .as_secs()
    }
}

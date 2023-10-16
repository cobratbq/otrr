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
    use std::cmp::Ordering;

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
    pub fn clear(buffer: &mut [u8]) {
        buffer.fill(0);
    }

    /// `clear2` fills provided 2 byte-array with zeroes.
    pub fn clear2(buffer1: &mut [u8], buffer2: &mut [u8]) {
        buffer1.fill(0);
        buffer2.fill(0);
    }

    /// `clear3` fills provided 2 byte-array with zeroes.
    pub fn clear3(buffer1: &mut [u8], buffer2: &mut [u8], buffer3: &mut [u8]) {
        buffer1.fill(0);
        buffer2.fill(0);
        buffer3.fill(0);
    }

    /// `clear4` fills provided 2 byte-array with zeroes.
    pub fn clear4(buffer1: &mut [u8], buffer2: &mut [u8], buffer3: &mut [u8], buffer4: &mut [u8]) {
        buffer1.fill(0);
        buffer2.fill(0);
        buffer3.fill(0);
        buffer4.fill(0);
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
}

pub mod bigint {
    use num_bigint::BigInt;
    use once_cell::sync::Lazy;

    pub static ZERO: Lazy<BigInt> = Lazy::new(|| BigInt::from(0u8));
    pub static ONE: Lazy<BigInt> = Lazy::new(|| BigInt::from(1u8));
    pub static TWO: Lazy<BigInt> = Lazy::new(|| BigInt::from(2u8));
    pub static THREE: Lazy<BigInt> = Lazy::new(|| BigInt::from(3u8));
    pub static FOUR: Lazy<BigInt> = Lazy::new(|| BigInt::from(4u8));
}

pub mod biguint {
    use num_bigint::BigUint;
    use once_cell::sync::Lazy;

    pub static ZERO: Lazy<BigUint> = Lazy::new(|| BigUint::from(0u8));
    pub static ONE: Lazy<BigUint> = Lazy::new(|| BigUint::from(1u8));
    pub static TWO: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u8));
    pub static THREE: Lazy<BigUint> = Lazy::new(|| BigUint::from(3u8));
    pub static FOUR: Lazy<BigUint> = Lazy::new(|| BigUint::from(4u8));
    pub static FIVE: Lazy<BigUint> = Lazy::new(|| BigUint::from(5u8));
    pub static SIX: Lazy<BigUint> = Lazy::new(|| BigUint::from(6u8));
    pub static SEVEN: Lazy<BigUint> = Lazy::new(|| BigUint::from(7u8));
    pub static EIGHT: Lazy<BigUint> = Lazy::new(|| BigUint::from(8u8));
    pub static NINE: Lazy<BigUint> = Lazy::new(|| BigUint::from(9u8));
    pub static TEN: Lazy<BigUint> = Lazy::new(|| BigUint::from(10u8));
    pub static ELEVEN: Lazy<BigUint> = Lazy::new(|| BigUint::from(11u8));
    pub static TWELVE: Lazy<BigUint> = Lazy::new(|| BigUint::from(12u8));

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
    use once_cell::sync::Lazy;
    use ring::rand::{SecureRandom, SystemRandom};

    /// `RANDOM` is an instance of `SystemRandom`.
    pub static RANDOM: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);

    /// `secure_bytes` produces the specified number of secure bytes as a byte-array.
    pub fn secure_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        RANDOM.fill(&mut bytes).unwrap();
        bytes
    }

    /// `fill_secure_bytes` fills provided buffer with bytes from (secure) random number generator.
    pub fn fill_secure_bytes(buffer: &mut [u8]) {
        RANDOM.fill(buffer).unwrap();
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

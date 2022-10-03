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
}

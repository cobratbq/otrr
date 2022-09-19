use once_cell::sync::Lazy;
use ring::rand::{self, SecureRandom};

use crate::utils;

pub const INSTANCE_ZERO: InstanceTag = 0;
pub const INSTANCE_MIN_VALID: InstanceTag = 0x00000100;

static RAND: Lazy<rand::SystemRandom> = Lazy::new(rand::SystemRandom::new);

pub fn verify_instance_tag(tag: u32) -> Result<InstanceTag, InstanceTagError> {
    if tag > INSTANCE_ZERO && tag < INSTANCE_MIN_VALID {
        Err(InstanceTagError::IllegalValue(tag))
    } else {
        Ok(tag)
    }
}

/// InstanceTag represents a client instance tag. The instance tag is used to distinguish between
/// multiple clients using the same account.
pub type InstanceTag = u32;

pub fn random_tag() -> InstanceTag {
    let mut value = [0u8; 4];
    loop {
        (&*RAND)
            .fill(&mut value)
            .expect("Failed to acquire random bytes");
        let num = utils::std::u32::from_4byte_be(&value);
        if num >= INSTANCE_MIN_VALID {
            return num;
        }
    }
}

pub enum InstanceTagError {
    /// As a safety-margin, the instance tags have a predefined invalid range (0, 256). 0 is
    /// excluded as it is used for backwards-compatibility.
    IllegalValue(u32),
}

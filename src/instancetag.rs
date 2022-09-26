use once_cell::sync::Lazy;
use ring::rand::{self, SecureRandom};

use crate::utils;

pub const INSTANCE_ZERO: InstanceTag = 0;
const INSTANCE_MIN_VALID: InstanceTag = 0x0000_0100;

static RAND: Lazy<rand::SystemRandom> = Lazy::new(rand::SystemRandom::new);

/// `InstanceTag` represents a client instance tag. The instance tag is used to distinguish between
/// multiple clients using the same account. Introduced in OTR version 3, this tag allows treating
/// multiple (chat) clients operating on the same account independently. The instance tag is used to
/// identify individual clients as soon as the OTR protocol takes effect.
/// 
/// Instance tag `0` (`INSTANCE_ZERO`) is reserved/special as it is used to indicate the lack of
/// instance tag, both for OTR version 2 protocol and for operations before the protocol is (fully)
/// in effect. Given that `otrr` does not support protocol version 2, instance tag zero is only used
/// when the actual instance tag of the receiver of your message-to-be-sent is still unknown.
pub type InstanceTag = u32;

pub(crate) fn verify_instance_tag(tag: u32) -> Result<InstanceTag, InstanceTagError> {
    if tag > INSTANCE_ZERO && tag < INSTANCE_MIN_VALID {
        Err(InstanceTagError::IllegalValue(tag))
    } else {
        Ok(tag)
    }
}

pub(crate) fn random_tag() -> InstanceTag {
    let mut value = [0u8; 4];
    loop {
        (*RAND)
            .fill(&mut value)
            .expect("Failed to acquire random bytes");
        let num = utils::std::u32::from_4byte_be(&value);
        if num >= INSTANCE_MIN_VALID {
            return num;
        }
    }
}

pub(crate) enum InstanceTagError {
    /// As a safety-margin, the instance tags have a predefined invalid range (0, 256). 0 is
    /// excluded as it is used for backwards-compatibility.
    IllegalValue(u32),
}

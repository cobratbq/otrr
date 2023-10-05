// SPDX-License-Identifier: LGPL-3.0-only

use crate::{OTRError, utils};

pub const INSTANCE_ZERO: InstanceTag = 0;
const INSTANCE_MIN_VALID: InstanceTag = 0x0000_0100;

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

/// `verify` verifies an instance tag
///
/// # Errors
/// In case of illegal instance tag.
pub fn verify(tag: u32) -> Result<InstanceTag, OTRError> {
    if tag > INSTANCE_ZERO && tag < INSTANCE_MIN_VALID {
        Err(OTRError::ProtocolViolation("Instance tag contains illegal value."))
    } else {
        Ok(tag)
    }
}

pub(crate) fn random_tag() -> InstanceTag {
    let mut value = [0u8; 4];
    loop {
        utils::random::fill_secure_bytes(&mut value);
        let num = u32::from_be_bytes(value);
        if num >= INSTANCE_MIN_VALID {
            return num;
        }
    }
}

use crate::OTRError;

/// InstanceTag represents a client instance tag. The instance tag is used to distinguish between multiple clients using the same account.
pub const INSTANCE_ZERO: u32 = 0;
pub const INSTANCE_MIN_VALID: u32 = 0x00000100;

pub type InstanceTag = u32;

pub fn verify_instance_tag(tag: u32) -> Result<InstanceTag, OTRError> {
    if tag > INSTANCE_ZERO && tag < INSTANCE_MIN_VALID {
        Err(OTRError::ProtocolViolation("Illegal instance tag."))
    } else {
        Ok(tag)
    }
}
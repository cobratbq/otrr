pub const INSTANCE_ZERO: u32 = 0;
pub const INSTANCE_MIN_VALID: u32 = 0x00000100;

/// InstanceTag represents a client instance tag. The instance tag is used to distinguish between multiple clients using the same account.
pub type InstanceTag = u32;

pub fn verify_instance_tag(tag: u32) -> Result<InstanceTag, InstanceTagError> {
    if tag > INSTANCE_ZERO && tag < INSTANCE_MIN_VALID {
        Err(InstanceTagError::IllegalValue)
    } else {
        Ok(tag)
    }
}

pub enum InstanceTagError {
    IllegalValue,
}

pub fn from_4byte_be(bytes: &[u8]) -> u32 {
    assert_eq!(bytes.len(), 4);
    u32::from_be_bytes([
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
    ])
}

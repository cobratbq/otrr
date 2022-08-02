
pub fn any_nonzero(data: &[u8]) -> bool {
    for i in 0..data.len() {
        if data[i] != 0 {
            return true;
        }
    }
    false
}

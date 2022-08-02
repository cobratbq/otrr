/// copy copies the content from source slice to destination slice.
// FIXME is there something out-of-the-box for this?
pub fn copy<T: Copy>(dst: &mut [T], src: &[T]) {
    assert!(dst.len() >= src.len());
    for i in 0..src.len() {
        dst[i] = src[i];
    }
}

/// clone clones the content from source slice to destination slice.
// FIXME is there something out-of-the-box for this?
pub fn clone<T: Clone>(dst: &mut [T], src: &[T]) {
    assert!(dst.len() >= src.len());
    for i in 0..src.len() {
        dst[i] = src[i].clone()
    }
}

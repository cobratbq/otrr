use std::ops::{Add, Sub};


/// copy_offset copies the content from source slice to destination slice.
// FIXME is there something out-of-the-box for this?
pub fn copy_offset<T: Copy>(dst: &mut [T], dst_offset: usize, src: &[T]) {
    assert!(dst[dst_offset..].len() >= src.len());
    for i in 0..src.len() {
        dst[dst_offset+i] = src[i];
    }
}

/// clone_offset clones the content from source slice to destination slice.
// FIXME is there something out-of-the-box for this?
pub fn clone_offset<T: Clone>(dst: &mut [T], dst_offset: usize, src: &[T]) {
    assert!(dst[dst_offset..].len() >= src.len());
    for i in 0..src.len() {
        dst[dst_offset+i] = src[i].clone()
    }
}

pub mod alloc {
    /// Modify vector to drop duplicate elements. (uses unstable sorting)
    pub fn vec_unique<T: Ord>(mut src: Vec<T>) -> Vec<T> {
        src.sort_unstable();
        src.dedup();
        src
    }
}

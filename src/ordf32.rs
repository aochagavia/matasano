#[derive(PartialEq, PartialOrd)]
pub struct OrdF32(pub f32);

impl std::cmp::Ord for OrdF32 {
    fn cmp(&self, other: &OrdF32) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl std::cmp::Eq for OrdF32 {}

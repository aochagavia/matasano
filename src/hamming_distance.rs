use crate::xor;

pub fn hamming_distance(xs: &[u8], ys: &[u8]) -> u32 {
    xor::xor_bytes(xs, ys).iter().map(|x| x.count_ones()).sum()
}

#[test]
fn test_hamming_distance() {
    let distance = hamming_distance(b"this is a test", b"wokka wokka!!!");
    assert_eq!(37, distance);
}

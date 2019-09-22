use std::collections::HashMap;

pub fn count_repetitions(bytes: &[u8]) -> u32 {
    // Block size is 128 bits (16 bytes)
    let mut freq = HashMap::new();
    for block in bytes.chunks(16) {
        *freq.entry(block).or_insert(0) += 1;
    }

    // 240 chars
    // 15 blocks
    freq.iter().filter(|&(_, &v)| v > 1).map(|(_, v)| v).sum()
}

#[test]
fn test_set_1_challenge_8() {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use crate::util;

    let mut suspicious_lines = Vec::new();
    let file = File::open("challenge-data/8.txt").unwrap();
    for (line_no, line) in BufReader::new(file).lines().enumerate() {
        let bytes = util::hex_str_into_bytes(line.unwrap().trim());
        let repetitions = count_repetitions(&bytes);
        if repetitions > 0 {
            suspicious_lines.push(line_no);
        }
    }

    assert_eq!(suspicious_lines, &[132]);
}

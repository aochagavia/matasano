#![allow(dead_code)]

mod base64;
mod hamming_distance;
mod histogram;
mod util;
mod xor;

fn main() {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open("challenge-data/6.txt").unwrap();
    let ciphertext: Vec<_> = BufReader::new(file)
        .lines()
        .flat_map(|l| base64::decode(l.unwrap().trim().as_bytes()))
        .collect();

    for inferred_length in xor::infer_key_lengths(&ciphertext) {
        if let Some(decrypted_key) = xor::decrypt_repeating_xor(&ciphertext, inferred_length) {
            assert_eq!(decrypted_key, "Terminator x: Bring the noise");
            let plaintext_bytes = xor::repeating_xor(&ciphertext, decrypted_key.as_bytes());
            let plaintext = String::from_utf8_lossy(&plaintext_bytes);
            println!("{}", plaintext);
        }
    }
}

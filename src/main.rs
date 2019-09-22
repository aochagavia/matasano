#![allow(dead_code)]

mod aes;
mod base64;
mod hamming_distance;
mod histogram;
mod ordf32;
mod util;
mod xor;

fn main() {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use openssl::symm::{Cipher, decrypt};

    let file = File::open("challenge-data/7.txt").unwrap();
    let ciphertext: Vec<_> = BufReader::new(file)
        .lines()
        .flat_map(|l| base64::decode(l.unwrap().trim().as_bytes()))
        .collect();

    let cipher = Cipher::aes_128_ecb();
    let result = decrypt(cipher, b"YELLOW SUBMARINE", None, &ciphertext).unwrap();
    println!("{}", String::from_utf8_lossy(&result));
}

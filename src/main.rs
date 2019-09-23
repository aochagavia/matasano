#![allow(dead_code)]

mod aes;
mod base64;
mod hamming_distance;
mod histogram;
mod ordf32;
mod pkcs7;
mod util;
mod xor;

fn main() {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open("challenge-data/10.txt").unwrap();
    let ciphertext: Vec<_> = BufReader::new(file)
        .lines()
        .flat_map(|l| base64::decode(l.unwrap().trim().as_bytes()))
        .collect();

    let iv = [0; 16];
    let result = aes::decrypt_aes_cbc(&ciphertext, b"YELLOW SUBMARINE", &iv);
    println!("{}", String::from_utf8_lossy(&result));
}

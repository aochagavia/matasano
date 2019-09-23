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
    aes::break_aes_ecb();
}

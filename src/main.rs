#![allow(dead_code)]

mod aes;
mod base64;
mod challenge11;
mod challenge12;
mod challenge13;
mod challenge14;
mod challenge16;
mod challenge17;
mod challenge19;
mod hamming_distance;
mod histogram;
mod mersenne_twister_rng;
mod ordf32;
mod pkcs7;
mod profile;
mod util;
mod xor;

fn main() {
    // aes::break_aes_ecb();
    challenge19::crack_things();
}

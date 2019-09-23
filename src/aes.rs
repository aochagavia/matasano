use std::collections::HashMap;
use openssl::symm::{Cipher, Crypter, Mode, encrypt, decrypt};

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(cipher, key, None, ciphertext).unwrap()
}

pub fn decrypt_aes_ecb_no_padding(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    crypter.pad(false);
    let mut plaintext = vec![0; ciphertext.len() + 16];
    crypter.update(ciphertext, &mut plaintext).unwrap();
    assert_eq!(plaintext.len() - 16, ciphertext.len());
    plaintext.truncate(plaintext.len() - 16);
    plaintext
}

pub fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    encrypt(cipher, key, None, plaintext).unwrap()
}

pub fn encrypt_aes_ecb_no_padding(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    crypter.pad(false);
    let mut ciphertext = vec![0; plaintext.len() + 16]; // We need to make this +16 otherwise the library complains
    crypter.update(plaintext, &mut ciphertext).unwrap();
    assert_eq!(ciphertext.len() - 16, plaintext.len());
    ciphertext.truncate(ciphertext.len() - 16);
    ciphertext
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), 16);

    let mut plaintext = Vec::new();
    let mut prev_block = iv;
    for block in ciphertext.chunks(16) {
        // Decrypt
        // XOR against previous block
        let decrypted = decrypt_aes_ecb_no_padding(block, key);
        let xorred = crate::xor::xor_bytes(&prev_block, &decrypted);
        plaintext.extend_from_slice(&xorred);

        prev_block = block;
    }

    // Remove padding
    let padding = plaintext[plaintext.len() - 1];
    plaintext.truncate(plaintext.len() - padding as usize);

    plaintext
}

pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), 16);
    let mut plaintext = plaintext.to_owned();
    crate::pkcs7::add_padding(&mut plaintext, 16);

    // Take previous encrypted block
    // XOR it against the current plaintext block
    // Encrypt the result using ECB
    let mut ciphertext = Vec::new();
    let mut prev_block = iv.to_owned();
    for block in plaintext.chunks(16) {
        let xorred = crate::xor::xor_bytes(&prev_block, block);
        let encrypted = encrypt_aes_ecb_no_padding(&xorred, key);
        ciphertext.extend_from_slice(&encrypted);

        prev_block = encrypted;
    }

    ciphertext
}

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

pub fn aes_oracle() -> (BlockCipherMode, BlockCipherMode) {
    let plaintext = vec![b'A'; 16 * 6];
    let (ciphertext, mode) = encrypt_aes_cbc_or_ecb(&plaintext);

    // If the encryption function is using ECB, there will be at least
    // 4 repeated blocks
    if count_repetitions(&ciphertext) >= 4 {
        (BlockCipherMode::ECB, mode)
    } else {
        (BlockCipherMode::CBC, mode)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockCipherMode {
    ECB,
    CBC
}

fn encrypt_aes_cbc_or_ecb(plaintext: &[u8]) -> (Vec<u8>, BlockCipherMode) {
    use rand::{RngCore, Rng};

    // Generate random key
    let mut key = vec![0; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);

    // Modify the plaintext
    let prepend_count: usize = rng.gen_range(5, 11);
    let mut prepend_bytes = vec![0; prepend_count];
    rng.fill_bytes(&mut prepend_bytes);

    let append_count: usize = rng.gen_range(5, 11);
    let mut append_bytes = vec![0; append_count];
    rng.fill_bytes(&mut append_bytes);

    let mut new_plaintext = prepend_bytes;
    new_plaintext.extend_from_slice(plaintext);
    new_plaintext.extend_from_slice(&append_bytes);

    // Encrypt!
    if rng.gen_bool(0.5) {
        // CBC
        let mut iv = vec![0; 16];
        rng.fill_bytes(&mut iv);
        (encrypt_aes_cbc(&new_plaintext, &key, &iv), BlockCipherMode::CBC)
    } else {
        // ECB
        (encrypt_aes_ecb(&new_plaintext, &key), BlockCipherMode::ECB)
    }
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

#[test]
fn test_encrypt_aes_cbc() {
    let plaintext = b"You'll never guess the contents of this string! Muahaha";
    let key = b"YELLOW SUBMARINE";
    let iv = b"1234123412341234";
    let ciphertext = encrypt_aes_cbc(plaintext, key, iv);

    let cipher = Cipher::aes_128_cbc();
    let expected_ciphertext = encrypt(cipher, key, Some(iv), plaintext).unwrap();

    assert_eq!(ciphertext, expected_ciphertext);
}

#[test]
fn test_encrypt_decrypt_aes_cbc() {
    let plaintext: &[u8] = b"You'll never guess the contents of this string! Muahaha";
    let key = b"YELLOW SUBMARINE";
    let iv = b"1234123412341234";
    let ciphertext = encrypt_aes_cbc(plaintext, key, iv);
    let decrypted = decrypt_aes_cbc(&ciphertext, key, iv);

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_detect_aes_ecb() {
    for _ in 0..20 {
        let (detected, real) = aes_oracle();
        assert_eq!(detected, real);
    }
}

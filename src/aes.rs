use std::collections::HashMap;
use openssl::symm::{Cipher, Crypter, Mode, encrypt, decrypt};
use crate::pkcs7;

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
    pkcs7::remove_padding(&mut plaintext);

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

// Note: this function assumes that the encryption function is deterministic
pub fn detect_block_size_and_padding_bytes<F>(encrypt: F) -> (usize, usize)
where F: Fn(&[u8]) -> Vec<u8> {
    // We can discover the block size even without knowing which cipher it is by seeing
    // the effect of our input on the padding

    let len = encrypt(b"").len();
    let mut block_size = 0;
    let mut padding_bytes = 0;
    for added_bytes in 1.. {
        let bytes = vec![0; added_bytes];
        let new_len = encrypt(&bytes).len();
        if new_len > len {
            // New block added!
            padding_bytes = added_bytes;
            block_size = new_len - len;
            break;
        }
    }

    (block_size, padding_bytes)
}

// Returns how many bytes we need to add to a prefix to start a new block
pub fn detect_prefix_length<F>(encrypt: F) -> usize
where F: Fn(&[u8]) -> Vec<u8> {
    // Note: this function assumes a block size of 16

    let mut input = Vec::new();
    let mut ciphertext: Vec<u8>;
    let index = 'asd: loop {
        ciphertext = encrypt(&input);
        let blocks: Vec<_> = ciphertext.chunks(16).collect();
        for (index, window) in blocks.windows(2).enumerate() {
            if window[0] == window[1] {
                break 'asd index;
            }
        }

        input.push(0);
    };

    let bytes_to_get_new_block = input.len() - 32;
    assert!(bytes_to_get_new_block <= 16);

    index * 16 - bytes_to_get_new_block
}

pub fn is_ecb<F>(encrypt: F, block_size: usize) -> bool
where F: Fn(&[u8]) -> Vec<u8> {
    let plaintext = vec![b'A'; block_size * 6];
    let ciphertext = encrypt(&plaintext);
    count_repetitions(&ciphertext) >= 4
}

pub fn decrypt_appendix<F>(encrypt: F) -> Vec<u8>
where F: Fn(&[u8]) -> Vec<u8> {
    let (block_size, _) = detect_block_size_and_padding_bytes(
        |bytes| encrypt(bytes)
    );

    assert_eq!(block_size, 16); // Sanity check

    // Detect that this is indeed a case of ECB
    if !is_ecb(
        |bytes| encrypt(bytes),
        block_size) {
        panic!("Not ECB!");
    }

    // Detect whether there is a prefix
    let prefix_length = detect_prefix_length(|bytes| encrypt(bytes));
    let prefix_bytes_before_next_block = block_size - (prefix_length % block_size);
    let prefix_correction_bytes_len = if prefix_bytes_before_next_block == block_size { 0 } else { prefix_bytes_before_next_block };
    let prefix_correction_bytes = vec![0; prefix_correction_bytes_len];
    let ignored_prefix_bytes = prefix_length + prefix_correction_bytes_len;

    // Detect padding bytes after correcting for the prefix
    let (_, padding_bytes) = detect_block_size_and_padding_bytes(|bytes| {
        let mut plaintext = prefix_correction_bytes.to_owned();
        plaintext.extend_from_slice(&bytes);
        encrypt(&plaintext)
    });

    // Find the length of the secret text
    let secret_text = encrypt(&prefix_correction_bytes);
    let secret_text_len = secret_text.len() - padding_bytes - ignored_prefix_bytes;
    let input_len = secret_text_len + padding_bytes;

    assert!(input_len % block_size == 0);

    let mut discovered_bytes = Vec::new();
    while discovered_bytes.len() < secret_text_len {
        // Find all combinations for the last char
        let mut input = vec![0; prefix_correction_bytes_len + input_len - discovered_bytes.len() - 1];
        input.extend_from_slice(&discovered_bytes);
        input.push(0);

        let mut map = std::collections::HashMap::new();
        for x in 0..=255 {
            input[prefix_correction_bytes_len + input_len - 1] = x;
            let encrypted = encrypt(&input);

            let block = encrypted[ignored_prefix_bytes + input_len - block_size..ignored_prefix_bytes + input_len].to_owned();
            assert_eq!(block.len(), block_size); // Sanity check
            map.insert(block, x);
        }

        // Craft an input block that allows an undiscovered byte to be included in the block
        let input = vec![0; prefix_correction_bytes_len + input_len - discovered_bytes.len() - 1];
        let encrypted = encrypt(&input);
        let discovered_byte = map[&encrypted[ignored_prefix_bytes + input_len - block_size..ignored_prefix_bytes + input_len]];
        discovered_bytes.push(discovered_byte);
    }

    discovered_bytes
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


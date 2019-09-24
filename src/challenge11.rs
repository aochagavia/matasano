use crate::aes;

pub fn aes_oracle() -> (BlockCipherMode, BlockCipherMode) {
    let plaintext = vec![b'A'; 16 * 6];
    let (ciphertext, mode) = encrypt_aes_cbc_or_ecb(&plaintext);

    // If the encryption function is using ECB, there will be at least
    // 4 repeated blocks
    if aes::count_repetitions(&ciphertext) >= 4 {
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
        (aes::encrypt_aes_cbc(&new_plaintext, &key, &iv), BlockCipherMode::CBC)
    } else {
        // ECB
        (aes::encrypt_aes_ecb(&new_plaintext, &key), BlockCipherMode::ECB)
    }
}

#[test]
fn test_detect_aes_ecb() {
    for _ in 0..20 {
        let (detected, real) = aes_oracle();
        assert_eq!(detected, real);
    }
}

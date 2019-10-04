fn break_aes_cbc() -> (Vec<u8>, Vec<u8>) {
    use rand::RngCore;
    let mut key = vec![0; 16];
    let mut iv = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut iv);

    let plaintext = Vec::new();
    let (mut original_plaintext, mut ciphertext) = get_encrypted_cookie(&key, &iv);

    assert!(ciphertext.len() % 16 == 0);
    assert!(ciphertext.len() >= 32);

    // The code below should correctly decrypt the last block... Except it doesn't
    let last_two_blocks_start = ciphertext.len() - 32;
    let decrypted = decrypt_block(&mut ciphertext[last_two_blocks_start..], &key, &iv);

    // crate::pkcs7::remove_padding(&mut found);
    println!("Original length: {}", original_plaintext.len());
    crate::pkcs7::add_padding(&mut original_plaintext, 16);
    println!("{}", String::from_utf8_lossy(&original_plaintext[last_two_blocks_start + 16..]));
    println!("{}", String::from_utf8_lossy(&decrypted));
    println!("{:?}", &original_plaintext[last_two_blocks_start + 16..]);
    println!("{:?}", &iv);
    println!("{:?}", decrypted); // We are not getting the padding right...
    // println!("{:?}, {}", possible_bytes, definitive_value.unwrap());

    // TODO: manipulate ciphertext, feed it to `provide_encrypted_cookie` and
    // check whether everything is working
    // assert!(provide_encrypted_cookie(&ciphertext, &key, &iv));

    (original_plaintext, plaintext)
}

fn decrypt_block(ciphertext: &mut [u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();

    for padding_bytes in 1..=16u8 {
        let i = 16 - padding_bytes as usize;

        assert_eq!(decrypted.len(), padding_bytes - 1);

        // For all bytes we have already decrypted, configure them in such a way that we obtain the desired padding
        for (j, byte) in decrypted.iter().enumerate() {
            ciphertext[15 - j] = byte ^ padding_bytes;
        }

        // Find candidates for the next non-encrypted byte
        let mut candidate_bytes = Vec::new();
        for byte in 0..=255 {
            // prev_block[i] needs to become a value such that prev_block[i] ^ last_block[i] = padding_bytes
            // if that is the case, then we know that decrypt(last_block[i]) = prev_block[i] ^ padding_bytes
            ciphertext[i] = byte;

            if provide_encrypted_cookie(&ciphertext, &key, &iv) {
                candidate_bytes.push(byte);
            }
        }

        // println!("Padding {}: {} candidates found!", padding_bytes, candidate_bytes.len());
        assert!(candidate_bytes.len() > 0);

        // Change the values of all bytes that are not part of the padding
        if padding_bytes < 16 {
            let negate_up_to = 15 - padding_bytes as usize;
            for j in 0..=negate_up_to {
                ciphertext[j] = !ciphertext[j];
            }
        }

        // Find the one candidate that should survive
        let decrypted_len = decrypted.len();
        while let Some(candidate) = candidate_bytes.pop() {
            ciphertext[i] = candidate;
            if provide_encrypted_cookie(&ciphertext, &key, &iv) {
                decrypted.push(candidate ^ padding_bytes);
            }
        }

        // Exactly one candidate should have been found
        assert_eq!(decrypted.len(), decrypted_len + 1);
    }

    decrypted.into_iter().rev().collect()
}

fn get_encrypted_cookie(key: &[u8], iv: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let alternatives: &[&[u8]] = &[
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        // b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        // b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        // b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        // b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        // b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        // b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        // b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        // b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        // b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let bytes = alternatives.choose(&mut rng).unwrap();
    let plaintext = crate::base64::decode(&bytes);
    let ciphertext = crate::aes::encrypt_aes_cbc(&plaintext, key, iv);
    (plaintext, ciphertext)
}

// Returns true if the padding is valid, false otherwise
fn provide_encrypted_cookie(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let plaintext = crate::aes::decrypt_aes_cbc_no_padding(ciphertext, key, iv);
    crate::pkcs7::validate_padding(&plaintext)
}

#[test]
fn test_break_aes_cbc_16() {
    let (plaintext, decrypted) = break_aes_cbc();
    assert_eq!(plaintext, decrypted);
}

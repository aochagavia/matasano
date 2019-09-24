use crate::aes;

pub fn break_aes_ecb() -> Vec<u8> {
    // Set up a random key
    use rand::RngCore;
    let mut random_key = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut random_key);

    let (block_size, padding_bytes) = aes::detect_block_size_and_padding_bytes(
        |bytes| encrypt_aes_ecb_with_appendix(bytes, &random_key)
    );

    assert_eq!(block_size, 16); // Sanity check

    // Detect that this is indeed a case of ECB
    if !aes::is_ecb(
        |bytes| encrypt_aes_ecb_with_appendix(bytes, &random_key),
        block_size) {
        panic!("Not ECB!");
    }

    // Find the length of the secret text
    let secret_text = encrypt_aes_ecb_with_appendix(b"", &random_key);
    let secret_text_len = secret_text.len() - padding_bytes;
    let input_len = secret_text_len + padding_bytes;

    assert!(input_len % block_size == 0);

    let mut discovered_bytes = Vec::new();
    while discovered_bytes.len() < secret_text_len {
        // Find all combinations for the last char
        let mut input = vec![0; input_len - discovered_bytes.len() - 1];
        input.extend_from_slice(&discovered_bytes);
        input.push(0);

        let mut map = std::collections::HashMap::new();
        for x in 0..=255 {
            input[input_len - 1] = x;
            let encrypted = encrypt_aes_ecb_with_appendix(&input, &random_key);

            let block = encrypted[input_len - block_size..input_len].to_owned();
            assert_eq!(block.len(), block_size); // Sanity check
            map.insert(block, x);
        }

        // Craft an input block that allows an undiscovered byte to be included in the block
        let input = vec![0; input_len - discovered_bytes.len() - 1];
        let encrypted = encrypt_aes_ecb_with_appendix(&input, &random_key);
        let discovered_byte = map[&encrypted[input_len - block_size..input_len]];
        discovered_bytes.push(discovered_byte);
    }

    discovered_bytes
}

pub fn encrypt_aes_ecb_with_appendix(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut plaintext = plaintext.to_owned();
    let appendix = crate::base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    plaintext.extend_from_slice(&appendix);

    aes::encrypt_aes_ecb(&plaintext, key)
}

#[test]
fn test_break_aes_ecb() {
    let secret = break_aes_ecb();
    let expected = crate::base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    assert_eq!(secret, expected)
}

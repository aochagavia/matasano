use crate::aes;

#[test]
fn break_aes_cbc() {
    use rand::RngCore;
    let mut key = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let mut iv = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Find the first block completely controlled by us
    let ciphertext = encrypt_aes_cbc_with_prefix_and_appendix(b"", &key, &iv);
    let ciphertext_with_added_byte = encrypt_aes_cbc_with_prefix_and_appendix(b"a", &key, &iv);

    let (i, _) = ciphertext.iter().zip(ciphertext_with_added_byte).enumerate().find(|&(_, (&b1, b2))| b1 != b2).unwrap();
    let changed_block_start = i;

    assert!(changed_block_start % 16 == 0);

    // Assumption: the prefix ends at a block boundary. While this is not guaranteed to be the case, it is enough to solve the challenge

    let mut ciphertext = encrypt_aes_cbc_with_prefix_and_appendix(&[0; 32], &key, &iv);

    // Replace the first block controlled by us so our payload is deployed in the second block
    let mut payload = b";admin=true;".to_vec();
    payload.extend(std::iter::repeat(b' ').take(4));

    assert!(payload.len() == 16);

    let encrypted_first_block = &mut ciphertext[changed_block_start..changed_block_start + 16];
    let mut xorred_payload = crate::xor::xor_bytes(&payload, encrypted_first_block);
    encrypted_first_block.copy_from_slice(&mut xorred_payload);

    assert!(is_admin(&ciphertext, &key, &iv))
}

fn encrypt_aes_cbc_with_prefix_and_appendix(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert!(input.iter().all(|&b| b != b';' && b != b'='));

    let mut plaintext = b"comment1=cooking%20MCs;userdata=".to_vec();
    plaintext.extend_from_slice(input);
    plaintext.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
    aes::encrypt_aes_cbc(&plaintext, key, iv)
}

fn is_admin(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let plaintext = aes::decrypt_aes_cbc(ciphertext, key, iv);
    let s = String::from_utf8_lossy(&plaintext);
    s.find(";admin=true;").is_some()
}

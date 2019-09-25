use crate::aes;
use crate::profile::Profile;

fn profile_ciphertext(email: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let p = Profile::new(String::from_utf8(email).expect("Invalid UTF-8"));
    let plaintext = p.encode_as_string();
    aes::encrypt_aes_ecb(plaintext.as_bytes(), &key)
}

#[test]
fn ecb_cut_and_paste() {
    // Set up a random key
    use rand::RngCore;
    let mut random_key = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut random_key);

    // Infer block size and padding bytes
    let (block_size, padding_bytes) = aes::detect_block_size_and_padding_bytes(
        |bytes| profile_ciphertext(bytes.to_owned(), &random_key)
    );

    assert_eq!(block_size, 16); // Sanity check
    assert_eq!(padding_bytes, 10); // Sanity check

    // We want the last block to contain the text `user`, that means 12 bytes of padding
    // Adding bytes diminishes padding
    let bytes_to_add = if padding_bytes >= 12 {
        12 - padding_bytes
    } else {
        padding_bytes + 4
    };

    let email = vec![b'A'; bytes_to_add];
    let mut ciphertext = profile_ciphertext(email, &random_key);

    // We want the second block to contain the text `user` followed by the padding bytes
    // The first block starts with `email=`. We need 10 bytes to get to the second block
    let mut email = vec![b'A'; 10];
    email.extend_from_slice(b"admin");
    email.extend(std::iter::repeat(11).take(11)); // Add padding bytes

    let crafted_admin_block = profile_ciphertext(email, &random_key);
    let malicious_block = &crafted_admin_block[16..32];

    // Switch the latest block by the malicious one
    ciphertext.truncate(ciphertext.len() - 16);
    ciphertext.extend_from_slice(malicious_block);

    let decrypted = aes::decrypt_aes_ecb(&ciphertext, &random_key);
    let decrypted_p = Profile::from_string(&String::from_utf8_lossy(&decrypted));
    assert_eq!(decrypted_p.email, "AAAAAAAAAAAAAA");
    assert_eq!(decrypted_p.uid, 0);
    assert_eq!(decrypted_p.role, "admin");
}

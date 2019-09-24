use crate::aes;
use crate::profile::Profile;

fn profile_ciphertext(email: String, key: &[u8]) -> Vec<u8> {
    let p = Profile::new(email);
    let plaintext = p.encode_as_string();
    aes::encrypt_aes_ecb(plaintext.as_bytes(), &key)
}

#[test]
fn ecb_cut_and_paste() {
    // Set up a random key
    use rand::RngCore;
    let mut random_key = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut random_key);

    let ciphertext = profile_ciphertext("user@email.com".into(), &random_key);

    // Do magic to create a ciphertext containing role=admin instead of role=user
    // Only calls to `profile_ciphertext` are allowed
    // Are we allowed to change the email? The wording of the challenge is a bit vague... Probably irrelevant

    let decrypted = aes::decrypt_aes_ecb(&ciphertext, &random_key);
    let decrypted_p = Profile::from_string(&String::from_utf8_lossy(&decrypted));
    assert_eq!(decrypted_p.email, "user@email.com");
    assert_eq!(decrypted_p.uid, 0);
    assert_eq!(decrypted_p.role, "admin");
}

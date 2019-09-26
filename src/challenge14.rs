use crate::aes;

pub fn break_aes_ecb() -> Vec<u8> {
    use rand::RngCore;
    let mut random_key = vec![0; 16];
    rand::thread_rng().fill_bytes(&mut random_key);

    aes::decrypt_appendix(|bytes| {
        encrypt_aes_ecb_with_prefix_and_appendix(bytes, &random_key)
    })
}

pub fn encrypt_aes_ecb_with_prefix_and_appendix(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let random_prefix = crate::base64::decode(b"paHnxkm4Js4BXPxMOxDY8IYXbB7SAhgRdINFtMNhC2I99y7BrA==");
    let appendix = crate::base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    let mut bytes = random_prefix.to_owned();
    bytes.extend_from_slice(plaintext);
    bytes.extend_from_slice(&appendix);

    aes::encrypt_aes_ecb(&bytes, key)
}

#[test]
fn test_break_aes_ecb_14() {
    let secret = break_aes_ecb();
    let expected = crate::base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    assert_eq!(secret, expected)
}

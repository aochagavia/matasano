pub fn add_padding(bytes: &mut Vec<u8>, block_size_bytes: u8) {
    let bytes_excess = bytes.len() % block_size_bytes as usize;
    let padding_amount = block_size_bytes - bytes_excess as u8;
    for _ in 0..padding_amount {
        bytes.push(padding_amount);
    }
}

pub fn validate_padding(bytes: &[u8]) -> bool {
    // We assume the block size is 16
    assert!(bytes.len() % 16 == 0);
    assert!(bytes.len() >= 16);

    let expected_padding_bytes = bytes[bytes.len() - 1];

    if expected_padding_bytes > 16 || expected_padding_bytes == 0 {
        return false;
    }

    let padding_bytes = &bytes[bytes.len() - expected_padding_bytes as usize..bytes.len()];

    assert!(padding_bytes.len() == expected_padding_bytes as usize); // Sanity check

    padding_bytes.iter().all(|&byte| byte == expected_padding_bytes)
}

pub fn remove_padding(bytes: &mut Vec<u8>) {
    // We assume padding is valid
    let expected_padding_bytes = bytes[bytes.len() - 1] as usize;
    let len_after_removing_padding = bytes.len() - expected_padding_bytes;
    bytes.truncate(len_after_removing_padding);
}

#[test]
fn test_add_padding() {
    let mut bytes = vec![1, 2, 3, 4];
    add_padding(&mut bytes, 8);

    assert_eq!(bytes, &[1, 2, 3, 4, 4, 4, 4, 4]);


    let mut bytes = vec![1, 2, 3, 4, 5];
    add_padding(&mut bytes, 5);

    assert_eq!(bytes, &[1, 2, 3, 4, 5, 5, 5, 5, 5, 5]);
}

#[test]
fn test_validate_padding() {
    let plaintexts = (0..=16).map(|length| vec![42; length]);

    for mut plaintext in plaintexts {
        add_padding(&mut plaintext, 16);
        assert!(validate_padding(&plaintext));
    }
}

#[test]
fn test_remove_padding() {
    let plaintexts = (0..=16).map(|length| vec![42; length]);

    for mut plaintext in plaintexts {
        let original = plaintext.clone();
        add_padding(&mut plaintext, 16);
        remove_padding(&mut plaintext);
        assert!(plaintext == original);
    }
}

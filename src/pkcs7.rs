pub fn add_padding(bytes: &mut Vec<u8>, block_size_bytes: u8) {
    let bytes_excess = bytes.len() % block_size_bytes as usize;
    let padding_amount = block_size_bytes - bytes_excess as u8;
    for _ in 0..padding_amount {
        bytes.push(padding_amount);
    }
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

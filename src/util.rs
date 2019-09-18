pub fn hex_str_into_bytes(s: &str) -> Vec<u8> {
    s
        .as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

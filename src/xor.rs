pub fn xor_bytes(xs: &[u8], ys: &[u8]) -> Vec<u8> {
    assert_eq!(xs.len(), ys.len());

    xs.into_iter().zip(ys).map(|(x, y)| x ^ y).collect()
}

pub fn decode_xor_english(bytes: &[u8]) -> Option<String> {
    let key = infer_xor_key_english(bytes)?;
    let decoded = decode_xor_bytes(bytes, key);
    String::from_utf8(decoded).ok()
}

fn infer_xor_key_english(bytes: &[u8]) -> Option<u8> {
    // Try all possible keys and pick the one with the most `e`s
    // Discard all sequences where less than 80% is alphanumeric or whitespace
    let minimum_alphabetic_length = (bytes.len() as f32 * 0.8) as usize;
    (0..=255)
        .map(|key| (key, decode_xor_bytes(bytes, key)))
        .filter(|(_, bytes)| bytes.iter().filter(|b| b.is_ascii_alphanumeric() || b.is_ascii_whitespace()).count() > minimum_alphabetic_length)
        .max_by_key(|(_, bytes)| bytes.into_iter().filter(|&&b| b == b'e').count())
        .map(|(key, _)| key)
}

fn decode_xor_bytes(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.into_iter().map(|x| x ^ key).collect()
}

#[cfg(test)]
mod test {
    use crate::util;
    use super::*;

    #[test]
    fn test_xor_bytes() {
        let xs = util::hex_str_into_bytes("1c0111001f010100061a024b53535009181c");
        let ys = util::hex_str_into_bytes("686974207468652062756c6c277320657965");
        let expected_output = util::hex_str_into_bytes("746865206b696420646f6e277420706c6179");
        let output = xor_bytes(&xs, &ys);
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_decode_english() {
        let xs = util::hex_str_into_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let expected_output = "Cooking MC\'s like a pound of bacon";
        let output = decode_xor_english(&xs).unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_set_1_challenge_4() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        // Collect all xor-decoded lines that pass our alphabetic char heuristic
        let file = File::open("challenge-data/4.txt").unwrap();
        let mut decoded_lines = Vec::new();
        for line in BufReader::new(file).lines() {
            let bytes = util::hex_str_into_bytes(line.unwrap().trim());
            if let Some(decoded) = decode_xor_english(&bytes) {
                decoded_lines.push(decoded);
            }
        }

        assert!(decoded_lines.iter().any(|decoded| decoded.trim() == "Now that the party is jumping"));
    }
}

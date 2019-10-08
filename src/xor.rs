pub fn xor_bytes(xs: &[u8], ys: &[u8]) -> Vec<u8> {
    assert_eq!(xs.len(), ys.len());

    xs.into_iter().zip(ys).map(|(x, y)| x ^ y).collect()
}

pub fn xor_ecb(xs: &[u8], key: &[u8]) -> Vec<u8> {
    xs.iter().zip(key.iter().cycle()).map(|(x, k)| x ^ k).collect()
}

pub fn decode_xor_english(bytes: &[u8]) -> Option<String> {
    let key = infer_xor_key_english(bytes)?;
    let decoded = decode_xor_bytes(bytes, key);
    String::from_utf8(decoded).ok()
}

// Return the 3 most probable key lengths
pub fn infer_key_lengths(bytes: &[u8]) -> impl Iterator<Item=usize> {
    let max_length = std::cmp::min(bytes.len(), 40);
    let mut scores: Vec<_> = (2..=max_length).map(|keysize| {
        let mut distance_total = 0;
        for (block_no, block) in bytes.chunks(keysize).enumerate().take(4) {
            for (other_block_no, other_block) in bytes.chunks(keysize).enumerate().take(4) {
                if block_no == other_block_no {
                    continue;
                }

                distance_total += crate::hamming_distance::hamming_distance(block, other_block);
            }
        }

        let normalized = (distance_total as f32 / keysize as f32 * 100.0) as u32;
        (keysize, normalized)
    }).collect();
    scores.sort_unstable_by_key(|&(_, d)| d);
    scores.into_iter().map(|(keysize, _)| keysize).take(3)
}

fn infer_xor_key_english(bytes: &[u8]) -> Option<u8> {
    // Try all possible keys and pick the one which most closely resembles the char distribution of the english language
    use crate::histogram::CharHistogram;
    use crate::ordf32::OrdF32;
    let english_chars = CharHistogram::english();
    let minimum_alphabetic_length = (bytes.len() as f32 * 0.8) as usize;
    (0..=255)
        .map(|key| (key, decode_xor_bytes(bytes, key)))
        .filter(|(_, bytes)| bytes.iter().filter(|b| b.is_ascii_alphanumeric() || b.is_ascii_whitespace()).count() > minimum_alphabetic_length)
        .max_by_key(|(_, bytes)| {
            let histogram = CharHistogram::from_bytes(bytes);
            OrdF32(histogram.count_intersection(&english_chars))
        }).map(|(key, _)| key)
}

fn decode_xor_bytes(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.into_iter().map(|x| x ^ key).collect()
}

pub fn decrypt_xor_ecb(bytes: &[u8], keysize: usize) -> Option<Vec<u8>> {
    // Transpose blocks
    let mut transposed_blocks = vec![Vec::new(); keysize];
    for (byte_no, &byte) in bytes.iter().enumerate() {
        let index = byte_no % keysize;
        transposed_blocks[index].push(byte);
    }

    // Decrypt each transposed block
    transposed_blocks.iter().map(|block| infer_xor_key_english(block)).collect()
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use crate::{base64, util};
    use super::*;

    const PLAINTEXT: &'static [u8] = br#"Mr. Pocket said he was glad to see me, and he hoped I was not sorry to see him. "For I really am not," he added, with his son's smile, "an alarming personage." He was a young-looking man, in spite of his perplexities and his very gray hair, and his manner seemed quite natural"#;

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

    #[test]
    fn test_xor_ecb() {
        let key = b"ICE";

        let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let expected_output = util::hex_str_into_bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
        let output = xor_ecb(plaintext, key);
        assert_eq!(output.len(), plaintext.len());
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_set_1_challenge_6() {
        let file = File::open("challenge-data/6.txt").unwrap();
        let ciphertext: Vec<_> = BufReader::new(file)
            .lines()
            .flat_map(|l| base64::decode(l.unwrap().trim().as_bytes()))
            .collect();

        for inferred_length in infer_key_lengths(&ciphertext) {
            if let Some(decrypted_key) = decrypt_xor_ecb(&ciphertext, inferred_length) {
                assert_eq!(decrypted_key, b"Terminator x: Bring the noise");
            }
        }
    }

    #[test]
    fn test_infer_key_length() {
        let key = b"secretkey";
        let ciphertext = xor_ecb(PLAINTEXT, key);
        let mut inferred_lengths = infer_key_lengths(&ciphertext);
        assert!(inferred_lengths.any(|keysize| keysize == key.len()));
    }

    #[test]
    fn test_decrypt_xor_ecb() {
        let key = b"secretkey";
        let ciphertext = xor_ecb(PLAINTEXT, key);
        let keysize = key.len();
        let decrypted_key = decrypt_xor_ecb(&ciphertext, keysize).unwrap();
        assert_eq!(decrypted_key, key);
    }
}

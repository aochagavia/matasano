pub fn encode(bytes: &[u8]) -> String {
    let mut output = String::new();

    for sextet in sextets(bytes) {
        output.push(encode_sextet(sextet) as char);
    }

    let padding = 3 - bytes.len() % 3;
    if padding < 3 {
        for _ in 0..padding {
            output.push('=');
        }
    }

    output
}

fn sextets(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    let mut count = 0;
    let mut remainder = 0;
    for byte in bytes {
        match count % 3 {
            0 => {
                let sextet = (byte & 0b1111_1100) >> 2;
                output.push(sextet);
                remainder = byte & 0b0000_0011;
            }
            1 => {
                let sextet = ((byte & 0b1111_0000) >> 4) | (remainder << 4);
                output.push(sextet);
                remainder = byte & 0b0000_1111;
            }
            2 => {
                let sextet1 = ((byte & 0b1100_0000) >> 6) | (remainder << 2);
                let sextet2 = byte & 0b0011_1111;
                output.push(sextet1);
                output.push(sextet2);
                remainder = 0;
            }
            _ => unreachable!()
        }

        count += 1;
    }

    if remainder != 0 {
        if count % 3 == 1 {
            output.push(remainder << 4);
        } else {
            output.push(remainder << 2);
        }
    }

    output
}

fn encode_sextet(sextet: u8) -> u8 {
    match sextet {
        0..=25 => b'A' + sextet,
        26..=51 => b'a' + sextet - 26,
        52..=61 => b'0' + sextet - 52,
        62 => b'+',
        63 => b'/',
        64..=255 => unreachable!()
    }
}

#[test]
fn test_sextets() {
    let s = sextets(b"ManMan");
    let s: &[u8] = &s;
    assert_eq!([19u8, 22, 5, 46, 19, 22, 5, 46], s);
}

#[test]
fn test_sextets_remainder2() {
    let s = sextets(b"Ma");
    let s: &[u8] = &s;
    assert_eq!([19u8, 22, 4], s);
}

#[test]
fn test_sextets_remainder1() {
    let s = sextets(b"M");
    let s: &[u8] = &s;
    assert_eq!([19u8, 16], s);
}

#[test]
fn test_encode() {
    let source_bytes = b"asdfgh";
    let expected_output = "YXNkZmdo";
    let output = encode(source_bytes);
    assert_eq!(output, expected_output);
}

#[test]
fn test_encode_padding() {
    let source_bytes = b"asdf";
    let expected_output = "YXNkZg==";
    let output = encode(source_bytes);
    assert_eq!(output, expected_output);
}

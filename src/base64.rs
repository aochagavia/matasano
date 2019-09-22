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

pub fn decode(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes.len() % 4, 0);

    let mut decoded = Vec::new();
    for chunk in bytes.chunks(4) {
        let s1 = decode_sextet(chunk[0]);
        let s2 = decode_sextet(chunk[1]);
        let s3 = decode_sextet(chunk[2]);
        let s4 = decode_sextet(chunk[3]);

        let b1 = (s1 << 2) | ((s2 & 0b0011_0000) >> 4);
        let b2 = ((s2 & 0b0000_1111) << 4) | ((s3 & 0b0011_1100) >> 2);
        let b3 = ((s3 & 0b0000_0011) << 6) | s4;

        decoded.push(b1);
        decoded.push(b2);
        decoded.push(b3);
    }

    // Take padding into account
    let padding = bytes.iter().rev().take(2).filter(|&&x| x == b'=').count();
    for _ in 0..padding {
        decoded.pop();
    }

    decoded
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

fn decode_sextet(character: u8) -> u8 {
    match character {
        b'A'..=b'Z' => character - b'A',
        b'a'..=b'z' => character - b'a' + 26,
        b'0'..=b'9' => character - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        b'=' => 0,
        c => unreachable!("Unknown char: {} ({})", c as char, c)
    }
}

#[test]
fn test_encode_decode_sextets() {
    for x in 0..=63 {
        assert_eq!(x, decode_sextet(encode_sextet(x)));
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

#[test]
fn test_encode_decode() {
    // No padding
    let source_bytes = b"asdfgh";
    let output = decode(encode(source_bytes).as_bytes());
    let output: &[u8] = &output;
    assert_eq!(source_bytes, output);

    // = of padding
    let source_bytes = b"asdfg";
    let output = decode(encode(source_bytes).as_bytes());
    let output: &[u8] = &output;
    assert_eq!(source_bytes, output);

    // == of padding
    let source_bytes = b"asd";
    let output = decode(encode(source_bytes).as_bytes());
    let output: &[u8] = &output;
    assert_eq!(source_bytes, output);
}

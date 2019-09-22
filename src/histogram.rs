use crate::ordf32::OrdF32;

/// Contains the frequencies of character appearance in a text
pub struct CharHistogram {
    char_frequencies: Vec<u32>,
}

impl CharHistogram {
    fn new() -> CharHistogram {
        let length = b'z' - b'a' + 1;
        CharHistogram {
            char_frequencies: vec![0; length as usize]
        }
    }

    pub fn english() -> CharHistogram {
        // Taken from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
        CharHistogram {
            char_frequencies: vec![
                14810,
                2715,
                4943,
                7874,
                21912,
                4200,
                3693,
                10795,
                13318,
                188,
                1257,
                7253,
                4761,
                12666,
                14003,
                3316,
                205,
                10977,
                11450,
                16587,
                5246,
                2019,
                3819,
                315,
                3853,
                128,
            ]
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> CharHistogram {
        let mut histogram = CharHistogram::new();
        for &byte in bytes {
            histogram.register_char(byte);
        }

        histogram
    }

    pub fn register_char(&mut self, c: u8) {
        let index = char_to_index(c);
        if index != std::usize::MAX {
            self.char_frequencies[index] += 1;
        }
    }

    pub fn count_intersection(&self, other: &CharHistogram) -> f32 {
        let self_total_chars = self.char_frequencies.iter().sum::<u32>() as f32;
        let other_total_chars = other.char_frequencies.iter().sum::<u32>() as f32;

        self.char_frequencies.iter().zip(&other.char_frequencies).map(|(&c1, &c2)|
            std::cmp::min(OrdF32(c1 as f32 / self_total_chars), OrdF32(c2 as f32 / other_total_chars)).0
        ).sum()
    }
}

fn char_to_index(c: u8) -> usize {
    match c.to_ascii_lowercase() {
        lowercase@b'a'..=b'z' => (lowercase - b'a') as usize,
        _ => std::usize::MAX,
    }
}

#[test]
fn test_histogram_intersection() {
    let h = CharHistogram::from_bytes(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    assert!((1.0 - h.count_intersection(&h)).abs() < 0.0001);

    let smaller = CharHistogram::from_bytes(b"abcdefghijklm");
    assert!((0.5 - h.count_intersection(&smaller)).abs() < 0.0001);

    // Non-alphabetic characters are ignored
    let smaller = CharHistogram::from_bytes(b"abcdefghijklm;.,/-+=~123556");
    assert!((0.5 - h.count_intersection(&smaller)).abs() < 0.0001);
}



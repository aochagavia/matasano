const A: u32 = 0x9908B0DF;
const F: u32 = 1812433253;
const W: u32 = 32;
const M: usize = 397;
const R: u32 = 31;
const N: usize = 624;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const B: u32 = 0x9D2C5680;
const S: u32 = 7;
const C: u32 = 0xEFC60000;
const L: u32 = 18;
const T: u32 = 15;
const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct Rng {
    pub state: Vec<u32>,
    pub index: usize,
}

impl Rng {
    pub fn new(seed: u32) -> Rng {
        let mut state = vec![0; N];
        state[0] = seed;

        for i in 1..N {
            state[i] = (F as u64 * (state[i - 1] ^ (state[i - 1] >> (W - 2))) as u64 + i as u64) as u32;
        }

        Rng {
            state,
            index: N
        }
    }

    pub fn next(&mut self) -> u32 {
        if self.index >= N {
            self.twist()
        }

        let x = self.state[self.index];
        self.index += 1;
        temper(x)
    }

    fn twist(&mut self) {
        println!("Twisting!");
        for i in 0..N {
            let x = (self.state[i] & UPPER_MASK) + (self.state[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }

        self.index = 0;
    }
}

fn temper(mut x: u32) -> u32 {
    x ^= (x >> U) & D;
    x ^= (x << S) & B;
    x ^= (x << T) & C;
    x ^= x >> L;
    x
}

pub fn untemper(mut x: u32) -> u32 {
    x = un_bitshift_right_xor(x, L);
    x = un_bitshift_left_xor(x, T, C);
    x = un_bitshift_left_xor(x, S, B);
    x = un_bitshift_right_xor(x, U);
    x
}

// Adapted from https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
fn un_bitshift_right_xor(mut value: u32, shift: u32) -> u32 {
  let mut i = 0;
  let mut result = 0;

  while i * shift < 32 {
    let part_mask = (0xFFFF_FFFF << (32 - shift)) >> (shift * i);
    let part = value & part_mask;
    value ^= part >> shift;
    result |= part;
    i += 1;
  }

  result
}

// Adapted from https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
fn un_bitshift_left_xor(mut value: u32, shift: u32, mask: u32) -> u32 {
  let mut i = 0;
  let mut result = 0;

  while i * shift < 32 {
    let part_mask = (0xFFFF_FFFF >> (32 - shift)) << (shift * i);
    let part = value & part_mask;
    value ^= (part << shift) & mask;
    result |= part;
    i += 1;
  }
  return result;
}

#[test]
fn test_rng_seed_works() {
    let mut rng = Rng::new(42);
    assert_eq!(rng.next(), 1608637542);
    assert_eq!(rng.next() as i32, -873841229);
}

#[test]
fn test_rng_crack_seed() {
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    let mut rng = Rng::new(seed);
    let x = rng.next();

    // Simulate passage of 30 seconds
    let now = seed + 30;

    // Attempt to brute force this thing (limit to 1000 tries)
    let mut found = false;
    for test_seed in (0..=now).rev().take(1_000) {
        let mut test_rng = Rng::new(test_seed);
        if test_rng.next() == x {
            found = true;
            assert_eq!(seed, test_seed);
        }
    }

    assert!(found);
}

#[test]
fn test_rng_clone() {
    let mut rng = Rng::new(42);
    let values: Vec<_> = (0..624).map(|_| rng.next()).collect();

    let reconstructed_state: Vec<_> = values.iter().map(|&x| untemper(x)).collect();
    let mut cloned = Rng { state: reconstructed_state, index: 0 };

    let cloned_values = (0..624).map(|_| cloned.next());
    for (cloned_value, original_value) in cloned_values.zip(values) {
        assert_eq!(cloned_value, original_value);
    }
}

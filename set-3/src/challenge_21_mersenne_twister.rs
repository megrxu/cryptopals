use std::cell::RefCell;
use std::num::Wrapping;

const W: usize = 32;
const N: usize = 624;
const M: usize = 397;
const R: usize = 31;
const A: u32 = 0x9908B0DF;
const F: u32 = 1812433253;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MTRNG {
    seed: u32,
    index: RefCell<usize>,
    mt: RefCell<[u32; N]>,
}

impl MTRNG {
    pub fn new(seed: u32) -> Self {
        let rng = MTRNG {
            seed,
            index: RefCell::from(N),
            mt: RefCell::new([0u32; N]),
        };
        rng.seed_mt();
        rng
    }

    pub fn extract(&self) -> u32 {
        if self.index.eq(&RefCell::new(N)) {
            self.twist();
        };

        let mt = self.mt.borrow();
        let mut index = self.index.borrow_mut();
        let mut y = mt[*index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y >> T) & C);
        y = y ^ (y >> L);

        *index += 1;
        y
    }

    fn seed_mt(&self) {
        let mut mt = self.mt.borrow_mut();
        mt[0] = self.seed;
        for i in 1..N {
            let (x, y) = (Wrapping(F), Wrapping(mt[i - 1] ^ (mt[i - 1] >> (W - 2))));
            mt[i] = (x * y).0 + i as u32;
        }
    }

    fn twist(&self) {
        let mut mt = self.mt.borrow_mut();
        for i in 0..N {
            let (a, b) = (
                Wrapping(mt[i] & UPPER_MASK),
                Wrapping((mt[(i + 1) % N]) & LOWER_MASK),
            );
            let x = (a + b).0;
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa = xa ^ A;
            }
            mt[i] = mt[(i + M) % N] ^ xa;
        }
        let mut index = self.index.borrow_mut();
        *index = 0;
    }
}

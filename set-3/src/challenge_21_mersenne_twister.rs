use std::cell::RefCell;
use std::num::Wrapping;

pub const W: usize = 32;
pub const N: usize = 624;
pub const M: usize = 397;
pub const R: usize = 31;
pub const A: u32 = 0x9908B0DF;
pub const F: u32 = 1812433253;
pub const U: u32 = 11;
pub const D: u32 = 0xFFFFFFFF;
pub const S: u32 = 7;
pub const B: u32 = 0x9D2C5680;
pub const T: u32 = 15;
pub const C: u32 = 0xEFC60000;
pub const L: u32 = 18;

pub const LOWER_MASK: u32 = (1 << R) - 1;
pub const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MTRNG {
    seed: u32,
    index: RefCell<usize>,
    pub mt: RefCell<[u32; N]>,
}

impl MTRNG {
    pub fn new(seed: u32) -> Self {
        let rng = MTRNG {
            seed,
            index: RefCell::from(N),
            mt: RefCell::new([0u32; N]),
        };
        rng.seed_mt();
        rng.twist();
        rng
    }

    pub fn reset(&self) {
        self.index.replace(N);
        self.seed_mt();
        self.twist();
    }

    pub fn extract(&self) -> u32 {
        if self.index.eq(&RefCell::new(N)) {
            self.twist();
        };

        let mt = self.mt.borrow();
        println!("{:x?}", &mt[0..5]);
        let mut index = self.index.borrow_mut();
        let mut y = mt[*index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

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

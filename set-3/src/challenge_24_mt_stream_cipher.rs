use super::challenge_21_mersenne_twister::*;

pub struct TrivialStreamCipher {
    rng: MTRNG,
}

impl TrivialStreamCipher {
    pub fn new(seed: u16) -> Self {
        TrivialStreamCipher {
            rng: MTRNG::new(seed as u32),
        }
    }

    pub fn encrypt(&self, p: &[u8]) -> Vec<u8> {
        let mut c: Vec<u8> = vec![];
        let mut cur = self.rng.extract();
        for (i, &byte) in p.iter().enumerate() {
            c.push(byte ^ ((cur >> (8 * (i % 4)) & 0xff) as u8));
            if i % 4 == 3 {
                cur = self.rng.extract();
            }
        }
        c
    }

    pub fn decrypt(&self, p: &[u8]) -> Vec<u8> {
        self.rng.reset();
        self.encrypt(p)
    }
}

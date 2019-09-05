use super::challenge_18_ctr_mode::*;
use rand::Rng;
use set_2::rand;

#[derive(Default)]
pub struct EncryptionOracle {
    key: Vec<u8>,
    nounce: u64,
}

impl EncryptionOracle {
    pub fn new() -> Self {
        EncryptionOracle {
            key: rand!(16),
            nounce: 0,
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_ctr_encrypt(plaintext, &self.key, self.nounce)
    }

    pub fn decrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_ctr_decrypt(plaintext, &self.key, self.nounce)
    }
}

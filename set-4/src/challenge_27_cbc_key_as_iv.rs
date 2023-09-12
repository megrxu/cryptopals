use rand::Rng;
use set_2::challenge_10_aes_cbc::*;
use set_2::rand;

pub struct EncryptionOracle {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl EncryptionOracle {
    pub fn init() -> Self {
        let key = rand!(16);
        let iv = key.clone(); // use key as iv
        EncryptionOracle { key, iv }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        aes_cbc_encrypt(input, &self.key, &self.iv)
    }

    pub fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        aes_cbc_decrypt(input, &self.key, &self.iv)
    }

    pub fn is_revealed(&self, key: &[u8]) -> bool {
        key == self.key
    }
}

use rand::seq::IteratorRandom;
use rand::Rng;
use set_1::challenge_1_base64::base64_decode;
use set_2::challenge_10_aes_cbc::*;
use set_2::challenge_15_pkcs7_validation::*;
use set_2::challenge_9_pkcs7::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Default)]
pub struct EncryptionOracle {
    pub iv: Vec<u8>,
    key: Vec<u8>,
}

impl EncryptionOracle {
    pub fn new() -> Self {
        EncryptionOracle {
            iv: rand!(16),
            key: rand!(16),
        }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let plaintext = pkcs7_padding(input, 16);
        aes_cbc_encrypt(&plaintext, &self.key, &self.iv)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, PaddingError> {
        let plaintext = aes_cbc_decrypt(input, &self.key, &self.iv);
        pkcs7_unpadding(&plaintext, 16)
    }
}

pub fn choose_one() -> Vec<u8> {
    let fc = File::open("data/17.txt").unwrap();
    let mut rng = rand::thread_rng();
    base64_decode(
        &BufReader::new(fc)
            .lines()
            .choose(&mut rng)
            .unwrap()
            .unwrap(),
    )
}

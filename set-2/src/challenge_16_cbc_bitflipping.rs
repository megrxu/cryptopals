use super::challenge_10_aes_cbc::*;
use super::challenge_15_pkcs7_validation::*;
use super::challenge_9_pkcs7::*;
use rand::Rng;
use super::rand;

pub struct EncryptionOracle {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl EncryptionOracle {
    pub fn init() -> Self {
        EncryptionOracle {
            key: rand!(16),
            iv: rand!(16),
        }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let plaintext = &pkcs7_padding(&EncryptionOracle::construct(input), 16);
        aes_cbc_encrypt(plaintext, &self.key, &self.iv)
    }

    pub fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        let output = aes_cbc_decrypt(input, &self.key, &self.iv);
        pkcs7_unpadding(&output, 16).unwrap()
    }

    fn construct(input: &[u8]) -> Vec<u8> {
        let mut before = b"comment1=cooking%20MCs;userdata=".to_vec();
        let mut after = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();
        let mut trimed = input
            .iter()
            .cloned()
            .filter(|&c| c != b';' && c != b'=')
            .collect();
        before.append(&mut trimed);
        before.append(&mut after);
        before
    }

    pub fn is_admin(&self, ciphertext: &[u8]) -> bool {
        let plaintext = self.decrypt(ciphertext);
        let target = b";admin=true;";
        let length = target.len();
        for i in 0..plaintext.len() - length {
            if plaintext[i..i + length].to_vec() == target {
                return true;
            }
        }
        false
    }
}

use rand::{thread_rng, Rng};
use set_2::rand;
use set_3::challenge_18_ctr_mode::*;

pub struct EncryptionOracle {
    key: Vec<u8>,
    nonce: u64,
}

impl EncryptionOracle {
    pub fn init() -> Self {
        EncryptionOracle { key: rand!(16), nonce: thread_rng().gen() }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let plaintext = EncryptionOracle::construct(input);
        aes_ctr_encrypt(&plaintext, &self.key, self.nonce)
    }

    pub fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        aes_ctr_decrypt(input, &self.key, self.nonce)
    }

    fn construct(input: &[u8]) -> Vec<u8> {
        let mut before = b"comment1=cooking%20MCs;userdata=".to_vec();
        let mut after = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();
        let mut trimed = input.iter().cloned().filter(|&c| c != b';' && c != b'=').collect();
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

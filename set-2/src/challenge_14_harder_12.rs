use super::challenge_9_pkcs7::pkcs7_padding;
use rand::Rng;
use set_1::challenge_1_base64::base64_decode;
use set_1::challenge_7_aes_ecb::aes_ecb_encrypt;
use super::rand;

pub struct EncryptionOracle {
    key: Vec<u8>,
    prepend: Vec<u8>,
}

impl EncryptionOracle {
    pub fn init() -> Self {
        EncryptionOracle {
            key: rand!(16),
            prepend: rand!(rand!(choose 0..100)),
        }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let plaintext = &pkcs7_padding(&self.append_unknown(input), 16);
        aes_ecb_encrypt(plaintext, &self.key)
    }

    fn append_unknown(&self, input: &[u8]) -> Vec<u8> {
        let mut prepend = self.prepend[..].to_vec();
        let mut res = input.to_vec();
        let mut unknown =  base64_decode(&"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        prepend.append(&mut res);
        prepend.append(&mut unknown);
        prepend
    }
}

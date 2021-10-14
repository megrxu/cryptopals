use byteorder::{LittleEndian, WriteBytesExt};
use eva_crypto::aes::AES;
use set_1::challenge_2_fixed_xor::xor;

pub struct Counter {
    nounce: Vec<u8>,
}

impl Counter {
    pub fn new(nounce: u64) -> Self {
        let mut nounce_vec = vec![];
        nounce_vec.write_u64::<LittleEndian>(nounce).unwrap();
        Counter { nounce: nounce_vec }
    }
    pub fn when(&self, n: u64) -> Vec<u8> {
        let mut res = self.nounce.to_vec();
        res.write_u64::<LittleEndian>(n).unwrap();
        res
    }
}

pub fn aes_ctr_encrypt(plaintext: &[u8], key: &[u8], nounce: u64) -> Vec<u8> {
    let cipher = AES::new(key);
    let mut keystream = vec![];
    let counter = Counter::new(nounce);
    for i in 0..(plaintext.len() / 16 + 1) as u64 {
        keystream.push(cipher.encrypt(&counter.when(i)))
    }
    xor(plaintext, &keystream.concat())
}

pub fn aes_ctr_decrypt(ciphertext: &[u8], key: &[u8], nounce: u64) -> Vec<u8> {
    aes_ctr_encrypt(ciphertext, key, nounce)
}

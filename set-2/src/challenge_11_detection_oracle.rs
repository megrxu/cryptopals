use super::challenge_10_aes_cbc::aes_cbc_encrypt;
use super::challenge_9_pkcs7::pkcs7_padding;
use rand::Rng;
use set_1::challenge_7_aes_ecb::aes_ecb_encrypt;
use std::collections::HashSet;

/// Modified from <https://github.com/quininer/aes/blob/master/tests/rand.rs>

#[macro_export]
macro_rules! rand {
    ( _ ) => { ::rand::random() };
    ( $len:expr ) => {{
        ::rand::thread_rng().sample_iter(::rand::distributions::Standard).take($len).collect::<Vec<_>>()
    }};
    ( choose $range:expr, $len:expr ) => {
        ::rand::thread_rng().sample_iter(::rand::distributions::Uniform::from($range)).take($len).collect::<Vec<_>>()
    };
    ( choose $range:expr ) => {
        rand!(choose $range, 1)[0]
    };
}

fn add_bytes(input: &[u8]) -> Vec<u8> {
    let mut pre = rand!(rand!(choose 5..11));
    let mut post = rand!(rand!(choose 5..11));
    let mut input_vec = input.to_vec();

    pre.append(&mut input_vec);
    pre.append(&mut post);
    pre
}

pub fn encryption_oracle(input: &[u8]) -> (bool, Vec<u8>) {
    let key = rand!(16);
    let iv = rand!(16);
    let plaintext = &pkcs7_padding(&add_bytes(input), 16);

    if rand!(choose 0..2) == 1 {
        (true, aes_cbc_encrypt(plaintext, &key, &iv))
    } else {
        (false, aes_ecb_encrypt(plaintext, &key))
    }
}

pub fn distinguisher(ciphertext: &[u8]) -> bool {
    let set = ciphertext.chunks(16).map(|e| e.to_vec()).collect::<HashSet<Vec<u8>>>();
    set.len() == ciphertext.len() / 16
}

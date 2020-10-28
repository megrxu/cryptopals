use set_1::challenge_1_base64::base64_decode;
use set_1::challenge_2_fixed_xor::xor;
use set_1::challenge_3_single_byte_xor_cipher::crack_key;
use set_3::challenge_19_fixed_nonce_ctr::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn decrypt_statistical() {
    let fc = File::open("data/20.txt").unwrap();
    let oracle = EncryptionOracle::new();
    let ps: Vec<Vec<u8>> =
        BufReader::new(fc).lines().map(|line| base64_decode(&line.unwrap())).collect();
    let cs: Vec<Vec<u8>> = ps.iter().map(|p| oracle.encrypt(p)).collect();

    let length = ps.iter().max_by(|x, y| y.len().cmp(&x.len())).unwrap().len();

    let mut cols: Vec<Vec<u8>> = vec![vec![]; cs.len()];
    let mut guessed_key = vec![];
    for i in 0..length {
        for c in cs.iter() {
            cols[i].push(c[i]);
        }
        guessed_key.push(crack_key(&cols[i]).0)
    }
    for (i, c) in cs.iter().enumerate() {
        assert_eq!(xor(c, &guessed_key), &ps[i][0..length]);
        println!("{:?}", String::from_utf8(xor(c, &guessed_key).to_vec()));
        println!("{:?}", String::from_utf8(ps[i][0..length].to_vec()));
    }
}

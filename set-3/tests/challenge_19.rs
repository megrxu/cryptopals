use set_1::challenge_1_base64::base64_decode;
use set_1::challenge_2_fixed_xor::xor;
use set_3::challenge_19_fixed_nonce_ctr::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn try_decrypt() {
    let fc = File::open("data/19.txt").unwrap();
    let oracle = EncryptionOracle::new();
    // encrypt under a same nounce
    let cs: Vec<Vec<u8>> = BufReader::new(fc)
        .lines()
        .map(|line| oracle.encrypt(&base64_decode(&line.unwrap())))
        .collect();
    let mut set = vec![];
    let num = vec![5, 6, 11, 10, 8, 7, 7, 6];
    for idx in 0..8 {
        let mut char_map: BTreeMap<u8, usize> = BTreeMap::new();
        for c in cs.iter() {
            if c.get(idx).is_none() {
                continue;
            }
            let cur = c.get(idx).unwrap();
            if let Some(size) = char_map.get_mut(&cur) {
                *size += 1;
            } else {
                char_map.insert(*cur, 1);
            }
        }
        println!("{}: {:x?}", idx, char_map);
        for (&key, &value) in char_map.iter() {
            if value == num[idx] {
                set.push(key);
            }
        }
    }
    let letters = b"Ho   o e".to_vec();
    let keystream = xor(&set, &letters);
    let ps = cs.iter().map(|c| xor(c, &keystream)).collect::<Vec<Vec<u8>>>();
    for p in ps {
        println!("{:x?}", String::from_utf8(p));
    }
}

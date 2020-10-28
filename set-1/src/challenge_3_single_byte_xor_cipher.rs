use super::challenge_2_fixed_xor::xor;
use lazy_static::lazy_static;
use std::collections::HashMap;

pub fn crack_key(data: &[u8]) -> (u8, String) {
    let mut scores = [0.0; 256];
    for (i, item) in scores.iter_mut().enumerate() {
        let key: Vec<u8> = vec![i as u8; data.len()];
        *item = score(&xor(&data, &key));
    }
    let mut max_idx = 0;
    for i in 0..256 {
        if scores[i] >= scores[max_idx] {
            max_idx = i;
        }
    }
    (
        max_idx as u8,
        String::from_utf8(xor(&data, &vec![max_idx as u8; data.len()]))
            .unwrap_or_else(|_| "Failed!".to_string()),
    )
}

fn score(bytes: &[u8]) -> f32 {
    let imprintable = bytes
        .iter()
        .filter(|&n| (*n < 32 && *n != b'\n') || *n >= 0x7f || *n == b'^')
        .count();
    if imprintable == 0 {
        bytes.iter().fold(0.0, |res, &b| {
            res + CHAR_FREQ
                .get(&((b as char).to_ascii_lowercase()))
                .unwrap_or(&0.0)
        })
    } else {
        0.0
    }
}

lazy_static! {
    static ref CHAR_FREQ: HashMap<char, f32> = [
        ('a', 8.167),
        ('b', 1.492),
        ('c', 2.782),
        ('d', 4.253),
        ('e', 12.702),
        ('f', 2.228),
        ('g', 2.015),
        ('h', 6.094),
        ('i', 6.966),
        ('j', 0.153),
        ('k', 0.772),
        ('l', 4.025),
        ('m', 2.406),
        ('n', 6.749),
        ('o', 7.507),
        ('p', 1.929),
        ('q', 0.095),
        ('r', 5.987),
        ('s', 6.327),
        ('t', 9.056),
        ('u', 2.758),
        ('v', 0.978),
        ('w', 2.360),
        ('x', 0.150),
        ('y', 1.974),
        ('z', 0.074),
        (' ', 15.0),
    ]
    .iter()
    .cloned()
    .collect();
}

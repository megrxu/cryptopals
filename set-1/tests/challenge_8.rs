
use hex_literal::hex as hex_literal;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn challenge_7() {
    let fc = File::open("data/8.txt").unwrap();
    let mut data: Vec<u8> = vec![];
    for line in BufReader::new(fc).lines() {
        let row = line.unwrap();
        let data_set = row
            .clone()
            .as_bytes()
            .chunks(32)
            .map(|e| String::from_utf8(e.to_vec()))
            .collect::<Result<HashSet<String>, _>>()
            .unwrap();
        if data_set.len() != row.clone().len() / 32 {
            data = hex::decode(row.clone()).unwrap();
        }
    }

    assert_eq!(data, hex_literal!["d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"].to_vec())
}

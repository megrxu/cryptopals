use set_1::challenge_3_single_byte_xor_cipher::crack_key;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn challenge_4() {
    let fc = File::open("data/4.txt").unwrap();
    let mut results: Vec<(u8, String)> = vec![];
    for line in BufReader::new(fc).lines() {
        results.push(crack_key(
            &hex::decode(line.unwrap()).expect("Decoding failed"),
        ));
    }
    assert!(results.contains(&(53, "Now that the party is jumping\n".to_string())));
}

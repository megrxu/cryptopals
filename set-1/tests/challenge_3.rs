#[macro_use]
extern crate hex_literal;
use set_1::challenge_3_single_byte_xor_cipher::crack_key;

#[test]
fn challenge_3() {
    assert_eq!(
        crack_key(&hex!(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )),
        (88, "Cooking MC\'s like a pound of bacon".to_string())
    );
}

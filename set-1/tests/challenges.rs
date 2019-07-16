#[cfg(test)]
#[macro_use]
extern crate hex_literal;
extern crate hex;

use set_1::base64::base64;
use set_1::fixed_xor::xor;
use set_1::repeating_key_xor::repeating_key_xor_cipher;
use set_1::single_byte_xor_cipher::crack_key;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn base64_test() {
    assert_eq!(base64(&hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    assert_eq!(
            base64(b"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."),
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="
        );
    assert_eq!(base64(b"easure."), "ZWFzdXJlLg==");
}

#[test]
fn xor_test() {
    assert_eq!(
        xor(
            &hex!("1c0111001f010100061a024b53535009181c"),
            &hex!("686974207468652062756c6c277320657965")
        ),
        hex!("746865206b696420646f6e277420706c6179")
    )
}

#[test]
fn single_byte_xor_test() {
    assert_eq!(
        crack_key(&hex!(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )),
        (88, "Cooking MC\'s like a pound of bacon".to_string())
    );
}

#[test]
fn file_single_byte_xor_test() {
    let fc = File::open("data/4.txt").unwrap();
    let mut results: Vec<(u8, String)> = vec![];
    for line in BufReader::new(fc).lines() {
        results.push(crack_key(
            &hex::decode(line.unwrap()).expect("Decoding failed"),
        ));
    }
    assert!(results.contains(&(53, "Now that the party is jumping\n".to_string())));
}

#[test]
fn repeating_key_xor_text() {
    assert_eq!(repeating_key_xor_cipher(b"ICE", b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), hex!["0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"].to_vec());
}

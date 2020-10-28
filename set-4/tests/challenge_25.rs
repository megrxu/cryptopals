use rand::{prelude::*, thread_rng, Rng};
use set_1::challenge_1_base64::base64_decode;
use set_1::challenge_2_fixed_xor::xor;
use set_2::challenge_10_aes_cbc::*;
use set_2::challenge_15_pkcs7_validation::*;
use set_2::rand;
use set_3::challenge_18_ctr_mode::*;
use set_4::challenge_25_rawctr::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn get_plaintext() -> String {
    let fc = File::open("data/25.txt").unwrap();
    let mut data: Vec<Vec<u8>> = vec![];
    for line in BufReader::new(fc).lines() {
        data.push(base64_decode(&line.unwrap()));
    }

    let ciphertext = data.concat();
    let iv = vec![0; 16];
    if let Ok(plaintext) =
        pkcs7_unpadding(&aes_cbc_decrypt(&ciphertext, b"YELLOW SUBMARINE", &iv), 16)
    {
        String::from_utf8(plaintext).unwrap()
    } else {
        "".into()
    }
}

#[test]
fn challenge_25() {
    // get the plaintext
    let plaintext = get_plaintext();
    let data = plaintext.as_bytes();

    // prepare the ciphertext
    let key: Vec<u8> = rand!(16);
    let mut rng = thread_rng();
    let nounce = rng.next_u64();
    let mut ciphertext = aes_ctr_encrypt(&data, &key, nounce);

    // expose the API to attacker
    let c_origin = ciphertext.to_vec();
    let mut attacker_edit =
        |offset, new_text: &[u8]| edit(&mut ciphertext, &key, nounce, offset, new_text);
    let new_text = vec![0; c_origin.len()];
    attacker_edit(0, &new_text);
    let p_recover = xor(&c_origin, &ciphertext);

    // check the recovered plaintext
    assert_eq!(data, p_recover);
}

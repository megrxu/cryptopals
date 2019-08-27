#[macro_use]
extern crate set_2;

use rand::Rng;
use set_1::challenge_7_aes_ecb::{aes_ecb_decrypt, aes_ecb_encrypt};
use set_2::challenge_13_cut_and_paste::*;
use set_2::challenge_9_pkcs7::pkcs7_padding;

#[test]
fn code_correct() {
    assert_eq!(
        "foo=1.2&baz=true&zap=zazzle&false=1231213",
        encode(decode("foo=1.2&baz=true&zap=zazzle&false=1231213"))
    );

    assert_eq!(
        encode(profile_for("foo@bar.com&==")),
        "email=foo@bar.com&uid=10&role=user"
    )
}

#[test]
fn it_works() {
    let email = "foo@bar.com";
    let key: Vec<u8> = rand!(16);
    let provide = aes_ecb_encrypt(
        &pkcs7_padding(encode(profile_for(email)).as_bytes(), 16),
        &key,
    );
    let profile = String::from_utf8(aes_ecb_decrypt(&provide, &key)).unwrap();
    println!("{:?}", profile);
}

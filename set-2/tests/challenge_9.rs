use set_2::challenge_9_pkcs7::*;

#[test]
fn challenge_9() {
    assert_eq!(pkcs7_padding(b"YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04")
}

use hex_literal::hex;
use set_4::challenge_28_sha1_mac::sha1;
use set_4::challenge_30_md4_mac::md4;
use set_4::challenge_31_hmac::hmac;

#[test]
fn test_hmac() {
    assert_eq!(hmac(sha1, b"abc", b"abc", 64), hex!("5b333a389b4e9a2358ac5392bf2a64dc68e3c943"));
    assert_eq!(hmac(md4, b"abc", b"abc", 64), hex!("0d0bc7abb1d0974d2513896a0b9fe8a2"));
}

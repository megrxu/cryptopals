use set_4::challenge_30_md4_mac::*;

#[test]
fn test_md4() {
    assert_eq!(md4(b""), [0x31d6cfe0, 0xd16ae931, 0xb73c59d7, 0xe0c089c0]);
}

use set_4::challenge_28_sha1_mac::*;

#[test]
fn test_sha1() {
    assert_eq!(sha1(b"abc"), [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d]);
    assert_eq!(
        sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        [0x84983e44, 0x1c3bd26e, 0xbaae4aa1, 0xf95129e5, 0xe54670f1]
    );
}

#[test]
fn test_sha1_mac() {
    assert_ne!(sha1_mac(b"key", b"abc"), sha1_mac(b"key", b"abcd"));
    assert_ne!(sha1_mac(b"key", b"abc"), sha1_mac(b"key'", b"abc"));
}

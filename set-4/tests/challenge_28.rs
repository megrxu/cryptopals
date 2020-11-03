use hex_literal::hex;
use set_4::challenge_28_sha1_mac::*;

#[test]
fn test_sha1() {
    assert_eq!(sha1(b"abc"), hex!("a9993e364706816aba3e25717850c26c9cd0d89d"));
    assert_eq!(
        sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
    );
    assert_eq!(
        sha1(b"The quick brown fox jumps over the lazy dog"),
        hex!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
    );
}

#[test]
fn test_sha1_mac() {
    assert_ne!(sha1_mac(b"key", b"abc"), sha1_mac(b"key", b"abcd"));
    assert_ne!(sha1_mac(b"key", b"abc"), sha1_mac(b"key'", b"abc"));
}

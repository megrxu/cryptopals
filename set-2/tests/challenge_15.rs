use set_2::challenge_15_pkcs7_validation::*;
#[test]
fn unpadding() {
    assert_eq!(pkcs7_unpadding(b"ICE ICE BABY\x04\x04\x04\x04", 16).unwrap(), b"ICE ICE BABY");
    assert!(match pkcs7_unpadding(b"ICE ICE BABY\x05\x05\x05\x05", 16) {
        Err(PaddingError) => true,
        _ => false,
    });
    assert!(match pkcs7_unpadding(b"ICE ICE BABY\x01\x02\x03\x04", 16) {
        Err(PaddingError) => true,
        _ => false,
    });
}

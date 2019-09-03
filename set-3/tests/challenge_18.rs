use set_3::challenge_18_ctr_mode::*;

#[test]
fn test_counter() {
    let counter = Counter::new(0);
    assert_eq!(
        counter.when(0),
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    );
    assert_eq!(
        counter.when(1),
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
    );
    assert_eq!(
        counter.when(2),
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
    );
}

#[test]
fn test_aes_ctr() {
    let p = vec![0u8; 187];
    let k = vec![1u8; 16];
    let c = aes_ctr_encrypt(&p, &k, 897);
    assert_eq!(p, aes_ctr_decrypt(&c, &k, 897));
    assert_eq!(c.len(), 187);
}

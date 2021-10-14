use num_traits::FromPrimitive;
use rand::Rng;
use set_2::rand;
use set_5::challenge_33_dh::*;

#[test]
fn test_dh_toy() {
    let p = uinf::from_u8(23).unwrap();
    let g = uinf::from_u8(5).unwrap();
    let a = uinf::from_u8(6).unwrap();
    let b = uinf::from_u8(15).unwrap();
    let a_key = DHKey::new_from(&p, &g, a);
    let b_key = DHKey::new_from(&p, &g, b);

    let sk_a = a_key.key_exchange(&b_key.pkey);
    let sk_b = b_key.key_exchange(&a_key.pkey);

    assert_eq!(sk_a, sk_b);
}

#[test]
fn test_dh_nist() {
    let p = &NIST_P;
    let g = uinf::from_u8(2).unwrap();
    let a = uinf::from_bytes_be(&rand!(4));
    let b = uinf::from_bytes_be(&rand!(4));
    let a_key = DHKey::new_from(&p, &g, a);
    let b_key = DHKey::new_from(&p, &g, b);

    let sk_a = a_key.key_exchange(&b_key.pkey);
    let sk_b = b_key.key_exchange(&a_key.pkey);
    assert_eq!(sk_a, sk_b);
}

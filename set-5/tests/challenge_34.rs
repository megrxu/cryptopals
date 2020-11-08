use num_traits::{FromPrimitive, Zero};
use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::*;

#[test]
fn test_dh_mitm() {
    let p: uinf = NIST_P.clone();
    let g = uinf::from_u8(2).unwrap();

    // A generate skey
    let a = uinf::gen();
    let a_key = DHKey::new_from(&p, &g, a);

    // B genetrate skey
    let b = uinf::gen();
    let b_key = DHKey::new_from(&p, &g, b);

    // A sends p, g, A to M, M knows g ^ a
    // M sends p, g, p to B
    // sk_b = p ^ b mod p = 0
    let sk_b = b_key.key_exchange(&p);
    let key_b = sha1(&sk_b.to_bytes_be());

    // B sends B to M, M knows g ^ b
    // M sends p to A
    // sk_a = p ^ a mod p = 0
    let sk_a = a_key.key_exchange(&p);
    let key_a = sha1(&sk_a.to_bytes_be());

    // A, B have the same key now
    assert_eq!(key_a, key_b);

    // M compute the key
    let key = sha1(&uinf::zero().to_bytes_be());

    assert_eq!(key, key_a);
}

use num_traits::{FromPrimitive, One, Zero};
use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::*;

#[test]
fn test_dh_mitm_g_one() {
    // A generate p, g
    let p: uinf = NIST_P.clone();
    let g = uinf::from_u8(2).unwrap();

    // A generate skey
    let a = uinf::gen();
    let a_key = DHKey::new_from(&p, &g, a);

    // A sends p, g, A to M, M knows A = g ^ a, g

    // M sends p, 1, A to B
    // B genetrate skey
    let b = uinf::gen();
    let b_key = DHKey::new_from(&p, &uinf::one(), b);

    // sk_b = 1 ^ b mod p = 1
    let sk_b = b_key.key_exchange(&uinf::one());
    let key_b = sha1(&sk_b.to_bytes_be());

    // B sends B to M, M knows g_ ^ b = 1
    // M sends 1 to A
    // sk_a = p ^ a mod p = 1
    let sk_a = a_key.key_exchange(&b_key.pkey);
    let key_a = sha1(&sk_a.to_bytes_be());

    // A, B have the same key now
    assert_eq!(key_a, key_b);

    // M compute the key
    let key = sha1(&uinf::one().to_bytes_be());

    assert_eq!(key, key_a);
}

#[test]
fn test_dh_mitm_g_p() {
    // A generate p, g
    let p: uinf = NIST_P.clone();
    let g = uinf::from_u8(2).unwrap();

    // A generate skey
    let a = uinf::gen();
    let a_key = DHKey::new_from(&p, &g, a);

    // A sends p, g, A to M, M knows A = g ^ a, g

    // M sends p, p, A to B
    // B genetrate skey
    let b = uinf::gen();
    let b_key = DHKey::new_from(&p, &p, b);

    // sk_b = p ^ b mod p = 0
    let sk_b = b_key.key_exchange(&uinf::zero());
    let key_b = sha1(&sk_b.to_bytes_be());

    // B sends B to M, M knows p ^ b mod p = 0
    // M sends 0 to A
    // sk_a = 0 ^ a mod p = 0
    let sk_a = a_key.key_exchange(&b_key.pkey);
    let key_a = sha1(&sk_a.to_bytes_be());

    // A, B have the same key now
    assert_eq!(key_a, key_b);

    // M compute the key
    let key = sha1(&uinf::zero().to_bytes_be());

    assert_eq!(key, key_a);
}

#[test]
fn test_dh_mitm_g_p_dec_1() {
    // A generate p, g
    let p: uinf = NIST_P.clone();
    let g = uinf::from_u8(2).unwrap();

    // A generate skey
    let a = uinf::gen();
    let a_key = DHKey::new_from(&p, &g, a);

    // A sends p, g, A to M, M knows A = g ^ a, g

    // M sends p, p - 1, p - 1 to B
    // B genetrate skey
    let g_ = p.clone() - uinf::one();
    let b = uinf::gen();
    let b_key = DHKey::new_from(&p, &g_, b);

    // sk_b = (p - 1) ^ b mod p = -1 or 1
    let sk_b = b_key.key_exchange(&g_.clone());

    // B sends B to M, M knows (p - 1) ^ b mod p
    // M sends (p - 1) ^ b mod p to A
    // sk_a = ((p - 1) ^ b mod p) ^ a mod p = -1 or 1
    let sk_a = a_key.key_exchange(&b_key.pkey);

    // keys values are limited
    assert!(sk_a == uinf::one() || sk_a == (p.clone() - uinf::one()));
    assert!(sk_b == uinf::one() || sk_b == (p.clone() - uinf::one()));
}

use num_traits::FromPrimitive;
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
    let p = uinf::from_bytes_be(&hex::decode(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
    ).unwrap());
    let g = uinf::from_u8(2).unwrap();
    let a = uinf::gen();
    let b = uinf::gen();
    let a_key = DHKey::new_from(&p, &g, a);
    let b_key = DHKey::new_from(&p, &g, b);

    let sk_a = a_key.key_exchange(&b_key.pkey);
    let sk_b = b_key.key_exchange(&a_key.pkey);
    assert_eq!(sk_a, sk_b);
}

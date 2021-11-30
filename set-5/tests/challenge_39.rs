use num_traits::FromPrimitive;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::RSA;

#[test]
fn test_rsa() {
    let (privkey, pubkey) = RSA::keygen(3, 64);
    let m = uinf::from_u64(42).unwrap();
    let c = pubkey.raw_encrypt(&m);
    let m_ = privkey.raw_decrypt(&c);
    assert_eq!(m_, m);
}

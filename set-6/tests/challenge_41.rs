use num_bigint::RandBigInt;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::ModInv;
use set_6::challenge_41_rsa_armoring::*;

#[test]
fn unpadded_message_recovery_oracle() {
    let mut instance = RsaSimpleInstance::new();

    let rng = &mut rand::thread_rng();

    let m = b"hello world";
    let c = instance.encrypt(m).unwrap();
    let e = instance.pubkey.e.clone();
    let n = instance.pubkey.n.clone();

    let _ = instance.decrypt(&c).unwrap(); // User decrypts it
    assert!(instance.decrypt(&c).is_err());

    let c_uinf = uinf::from_bytes_be(&c);
    let s = rng.gen_biguint(64);
    let c_prime = s.clone().modpow(&e, &n) * c_uinf % &n;
    let c_ = c_prime.to_bytes_be();

    let m_prime = instance.decrypt(&c_).unwrap();
    let m_ = (uinf::from_bytes_be(&m_prime) * s.modinv(&n) % &n).to_bytes_be();

    assert_eq!(m, &m_[..]);
}

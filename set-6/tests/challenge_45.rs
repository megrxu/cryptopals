use num_bigint::RandBigInt;
use num_traits::FromPrimitive;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::ModInv;
use set_6::challenge_43_dsa::*;

#[test]
fn dsa_parameter_tampering() {
    // Setup
    let mut rng = rand::thread_rng();
    let mut dsa = DSA::default();

    // Tampering parameter : g = 0
    dsa.g = uinf::from_u8(0).unwrap();
    let (privkey, pubkey) = dsa.keygen();

    let msg = uinf::from_bytes_be(b"Hello, world");
    let sig = dsa.raw_sign(&privkey, &msg);
    assert!(dsa.raw_verify(&pubkey, &msg, &sig));

    // Randome sigs can be verified
    let forged_sig = (sig.0.clone(), rng.gen_biguint(2048) % &dsa.q);
    assert!(dsa.raw_verify(&pubkey, &msg, &forged_sig));

    // Tampering parameter : g = 1
    dsa.g = dsa.p.clone() + uinf::from_u8(1).unwrap();
    let (privkey, pubkey) = dsa.keygen();

    let msg = uinf::from_bytes_be(b"Goodbye, world");
    let sig = dsa.raw_sign(&privkey, &msg);
    assert!(dsa.raw_verify(&pubkey, &msg, &sig));

    let forged_sig = {
        let z = rng.gen_biguint(2048);
        let r = pubkey.modpow(&z, &dsa.p) % &dsa.q;
        let s = z.modinv(&dsa.q) * r.clone() % &dsa.q;
        (r, s)
    };
    assert!(dsa.raw_verify(&pubkey, &msg, &forged_sig));
}

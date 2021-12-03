use hex_literal::hex;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::ModInv;
use set_6::challenge_43_dsa::*;

#[test]
fn dsa_key_recovery_from_nonce() {
    let dsa = DSA::default();

    let pubkey = uinf::from_bytes_be(&hex!(
        "084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
        abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
        e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
        1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
        bb283e6633451e535c45513b2d33c99ea17"
    ));
    let hm = uinf::from_bytes_be(&hex!("d2d0714f014a9784047eaeccf956520045c45265"));
    let r = uinf::from_bytes_be(&hex!("60019cacdc56eedf8e080984bfa898c8c5c419a8"));
    let s = uinf::from_bytes_be(&hex!("961f2062efc3c68db965a90c924cf76580ec1bbc"));
    let sig = (r.clone(), s.clone());

    // The signature is valid
    assert!(dsa.raw_verify(&pubkey, &hm, &sig));

    // The closure to recover the key
    let _recover_key = |nonce: &uinf, r: &uinf, s: &uinf, hm: &uinf, q: &uinf| -> uinf {
        let r_ = r.modinv(q);
        let mut res: uinf = s.clone() * nonce;
        let s_ = loop {
            if &res > hm {
                break res - hm;
            }
            res += q;
        };
        r_ * s_ % q
    };

    // Took ~97 seconds to find the private key
    // let mut k = uinf::from_bytes_be(&[]).unwrap();
    // for i in 0..2 << 16 {
    //     k += uinf::one();
    //     privkey = recover_key(&k, &r, &s.clone(), &hm, &dsa.q);
    //     if dsa.g.modpow(&privkey, &dsa.p) == pubkey {
    //         break;
    //     }
    // }
    let privkey = uinf::from_bytes_be(&[
        0x15, 0xfb, 0x28, 0x73, 0xd1, 0x6b, 0x3e, 0x12, 0x9f, 0xf7, 0x6d, 0x09, 0x18, 0xfd, 0x7a,
        0xda, 0x54, 0x65, 0x9e, 0x49,
    ]);

    assert_eq!(dsa.g.modpow(&privkey, &dsa.p), pubkey);
    assert!(dsa.raw_verify(&pubkey, &hm, &dsa.raw_sign(&privkey, &hm)));
}

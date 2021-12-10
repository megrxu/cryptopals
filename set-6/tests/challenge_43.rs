use hex_literal::hex;
use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::uinf;
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

    // Took ~97 seconds to find the private key
    // let mut k = uinf::from_bytes_be(&[]).unwrap();
    // for i in 0..2 << 16 {
    //     k += uinf::one();
    //     privkey = recover_key(&k, &r, &s.clone(), &hm, &dsa.q);
    //     if dsa.g.modpow(&privkey, &dsa.p) == pubkey {
    //         break;
    //     }
    // }
    let privkey_bytes = hex!("15fb2873d16b3e129ff76d0918fd7ada54659e49");
    let privkey = uinf::from_bytes_be(&privkey_bytes);

    assert_eq!(
        sha1(b"15fb2873d16b3e129ff76d0918fd7ada54659e49"),
        hex!("0954edd5e0afe5542a4adf012611a91912a3ec16")
    );
    assert!(dsa.raw_verify(&pubkey, &hm, &dsa.raw_sign(&privkey, &hm)));
}

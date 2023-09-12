use hex_literal::hex;
use num_traits::Num;
use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::ModInv;
use set_6::challenge_43_dsa::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn get_signatures() -> Vec<(Vec<u8>, uinf, uinf, uinf)> {
    let f = File::open("data/44.txt").unwrap();
    let mut lines = BufReader::new(f).lines();
    let mut res = vec![];
    while let Some(Ok(line)) = lines.next() {
        let msg = line.as_bytes()[4..].to_vec();
        let s = &lines.next().unwrap().unwrap()[3..].parse::<uinf>().unwrap();
        let r = &lines.next().unwrap().unwrap()[3..].parse::<uinf>().unwrap();
        let k = &lines.next().unwrap().unwrap()[3..];
        let hm = {
            if k.len() % 2usize == 1 { String::from("0") + k } else { k.to_string() }
        };
        let m = uinf::from_str_radix(&hm, 16).unwrap();
        res.push((msg, s.clone(), r.clone(), m.clone()));
    }
    res
}

#[test]
fn dsa_nonce_recovery_from_repeated_nouce() {
    let dsa = DSA::default();
    let signatures = get_signatures();

    let pubkey = uinf::from_str_radix(
        "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821",
        16,
    )
    .unwrap();

    // Find the repeated-nonce signatures
    let mut meet = vec![];
    let (mut i_0, mut i_1) = (0, 0);
    for (i, (_, s, r, hm)) in signatures.iter().enumerate() {
        assert!(dsa.raw_verify(&pubkey, hm, &(r.clone(), s.clone())));
        if let Some(j) = meet.iter().position(|item: &uinf| r == item) {
            i_0 = i;
            i_1 = j;
        }
        meet.push(r.clone());
    }

    let (hm0, s0, r0) =
        (signatures[i_0].3.clone(), signatures[i_0].1.clone(), signatures[i_0].2.clone());
    let (hm1, s1) = (signatures[i_1].3.clone(), signatures[i_1].1.clone());
    let nonce = { (s0.clone() - s1).modinv(&dsa.q) * (hm0.clone() - hm1) % dsa.q.clone() };
    let privkey = recover_key(&nonce, &r0, &s0, &hm0, &dsa.q);

    assert!(dsa.raw_verify(&pubkey, &hm0, &dsa.raw_sign(&privkey, &hm0)));
    assert_eq!(
        sha1(privkey.to_str_radix(16).as_bytes()),
        hex!("ca8f6f7c66fa362d40760d135b763eb8527d3d52")
    );
}

use hex_literal::hex;
use rand::Rng;
use set_2::rand;
use set_4::challenge_28_sha1_mac::sha1;
use set_4::challenge_30_md4_mac::md4;
use set_4::challenge_31_hmac::hmac;
use std::cmp::Ordering;

#[test]
fn test_hmac() {
    assert_eq!(hmac(sha1, b"abc", b"abc", 64), hex!("5b333a389b4e9a2358ac5392bf2a64dc68e3c943"));
    assert_eq!(hmac(md4, b"abc", b"abc", 64), hex!("0d0bc7abb1d0974d2513896a0b9fe8a2"));
}

fn insecure_compare(a: &[u8], b: &[u8]) -> (bool, usize) {
    let res = a.iter().zip(b.iter()).fold((true, 0), |res, (x, y)| match (res.0, x == y) {
        (false, _) => res,
        (true, c) => (c, res.1 + 5),
    });
    (res.0 && a.len() == b.len(), res.1 + rand!(choose 0..8))
}

#[test]
#[ignore]
fn exploit_less_timing_leak() {
    let key = rand!(16);
    let file = rand!(rand!(choose 100..1000));
    let target = hmac(sha1, &key, &file, 64);

    let mut mutation = vec![0u8; 20];
    for i in 0..20 {
        let byte = (0..0xff)
            .map(|n| {
                mutation[i] = n;
                (n, insecure_compare(&mutation, &target))
            })
            .max_by(|&(_, (a_res, a)), (_, (b_res, b))| match (a_res, b_res, a.cmp(b)) {
                (false, false, _) => a.cmp(b),
                (false, true, _) => Ordering::Less,
                (true, _, _) => Ordering::Greater,
            })
            .unwrap()
            .0;
        mutation[i] = byte;
    }
    // the first method breaks.
    assert_ne!(mutation, target);

    for i in 0..20 {
        let byte = (0..0xff)
            .map(|n| {
                mutation[i] = n;
                let r = insecure_compare(&mutation, &target).0;
                let m = (0..100)
                    .map(|_| insecure_compare(&mutation, &target))
                    .fold(0, |res, (_, k)| res + k);
                (n, (r, m))
            })
            .max_by(|&(_, (a_res, a)), (_, (b_res, b))| match (a_res, b_res, a.cmp(b)) {
                (false, false, _) => a.cmp(b),
                (false, true, _) => Ordering::Less,
                (true, _, _) => Ordering::Greater,
            })
            .unwrap()
            .0;
        mutation[i] = byte;
    }
    // by many times.
    assert_eq!(mutation, target);
}

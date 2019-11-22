

use set_3::challenge_21_mersenne_twister::*;
use rand::Rng;
use set_2::rand;

fn untamper(output: u32) -> u32 {
    let mut y;
    // y = y ^ (y >> L);
    y = (output & (0xffffffff << (32 - L))) | ((output >> L) ^ (output & (0xffffffff >> L)));

    // y = y ^ ((y >> T) & C);
    // y = y ^ ((y << S) & B);
    let l7 = y & (0xffffffff >> (32 - S));
    let l14 = ((l7 << S) & B ^ y) & (0xffffffff >> (32 - S)) << S;
    let l21 = ((l14 << S) & B ^ y) & (0xffffffff >> (32 - S)) << (S * 2);
    let l28 = ((l21 << S) & B ^ y) & (0xffffffff >> (32 - S)) << (S * 3);
    let l32 = ((l28 << S) & B ^ y) & (0xffffffff >> (32 - S) << (S * 4));
    y = l32 | l28 | l21 | l14 | l7;

    // y = y ^ ((y >> U) & D);
    let h11 = y & (0xffffffff << (32 - U));
    let h22 = ((h11 >> U) & D ^ y) & (0xffffffff << (32 - U) >> U);
    let h32 = ((h22 >> U) & D ^ y) & (0xffffffff << (32 - U) >> (U * 2));
    y = h11 | h22 | h32;

    // final
    y
}

#[test]
fn clone_rng() {
    // Basic test (seed = 0)
    assert_eq!(2443250962, untamper(146746268));

    // Rand tests
    let seed: u32 = rand!(choose 0..std::u32::MAX);
    let rng = MTRNG::new(seed);
    let mt = rng.mt.borrow();
    for i in 0..624 {
        assert_eq!(mt[i], untamper(rng.extract()));
    }
}

use rand::Rng;
use set_2::rand;
use set_3::challenge_21_mersenne_twister::*;
use set_3::challenge_23_clone_mt::*;

#[test]
fn clone_rng() {
    // Rand tests
    let seed: u32 = rand!(choose 0..std::u32::MAX);
    let rng = MTRNG::new(seed);
    let mt = rng.mt.borrow();
    for i in 0..624 {
        assert_eq!(mt[i], untamper(rng.extract()));
    }
}

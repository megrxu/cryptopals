use set_3::challenge_21_mersenne_twister::*;

#[test]
fn test_rng() {
    let rng = MTRNG::new(0);
    for _ in 0..10 {
        println!("{}", rng.extract())
    }
}

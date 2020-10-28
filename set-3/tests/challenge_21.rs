use set_3::challenge_21_mersenne_twister::*;

#[test]
fn test_rng() {
    let rng = MTRNG::new(0);
    let r#ref: Vec<u32> = vec![
        2357136044, 2546248239, 3071714933, 3626093760, 2588848963, 3684848379, 2340255427,
        3638918503, 1819583497, 2678185683,
    ];
    for i in 0..10 {
        assert_eq!(rng.extract(), r#ref[i])
    }
}

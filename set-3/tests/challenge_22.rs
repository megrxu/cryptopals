use chrono::prelude::*;
use rand::Rng;
use set_2::rand;
use set_3::challenge_21_mersenne_twister::*;

fn routine() -> (u32, u32) {
    let shift = rand!(choose 40..1000);
    let utc: DateTime<Utc> = Utc::now();
    let seed = utc.timestamp_subsec_micros() + shift;
    let rng = MTRNG::new(seed);
    (seed, rng.extract())
}

#[test]
fn crack_rng() {
    let (seed, output) = routine();
    let current = Utc::now().timestamp_subsec_micros();
    let mut guess = 0;
    for i in 40..3000 {
        // 100 is for the latency
        let rng = MTRNG::new(current + i - 100);
        if rng.extract() == output {
            guess = current + i - 100;
            break;
        }
    }
    assert_eq!(guess, seed);
}

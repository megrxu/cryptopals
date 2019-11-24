use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use set_1::challenge_2_fixed_xor::xor;
use set_2::rand;
use set_3::challenge_21_mersenne_twister::*;
use set_3::challenge_24_mt_stream_cipher::*;
use set_3::challenge_23_clone_mt::*;


#[test]
fn encrypt_and_decrypt() {
    let cipher = TrivialStreamCipher::new(0);
    let op = vec![0; 16];
    let cp = cipher.decrypt(&cipher.encrypt(&op));
    assert_eq!(cp, op);
    generate_input();
}

fn generate_input() -> Vec<u8> {
    let head: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(rand!(choose 5..10))
        .collect();
    (head + "AAAAAAAAAAAAAA").as_bytes().to_vec()
}

fn encrypt_oracle() -> (u16, Vec<u8>) {
    let key: u16 = thread_rng().gen();
    let cipher = TrivialStreamCipher::new(key);
    let p: Vec<u8> = generate_input();
    (key, cipher.encrypt(&p))
}

#[test]
#[ignore]
fn crack_key() {
    let (key, c) = encrypt_oracle();
    let keystream = xor(&c, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());
    let recovered = keystream
        .chunks_exact(4)
        .map(|x| (0..4).fold(0, |res, i| res ^ ((x[i] as u32) << (i * 8))))
        .collect::<Vec<u32>>();
    let mt_prime = recovered.iter().map(|&x| untamper(x)).collect::<Vec<u32>>();
    let len = mt_prime.len();

    // How to untwist once? By brute force? Really?
    let mut guess : u16 = 0;
    for i in 0..0xffff {
        let rng = MTRNG::new(i as u32);
        // By brute force...
        if rng.mt.borrow()[len - 1] == mt_prime[len - 1] {
            guess = i as u16;
            break;
        }
    }
    assert_eq!(key, guess);
}

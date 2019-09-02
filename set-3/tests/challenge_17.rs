use set_1::challenge_1_base64::*;
use set_3::challenge_17_cbc_padding::*;

#[test]
fn test_correct() {
    let oracle = EncryptionOracle::new();
    let p = choose_one();
    let c = oracle.encrypt(&p);
    assert_eq!(p, oracle.decrypt(&c).unwrap());
    println!("{}", base64_encode(&p));
}

#[test]
fn test_decrypt() {
    let oracle = EncryptionOracle::new();
    let p = choose_one();
    let c = oracle.encrypt(&p);

    // recover a block
    let mut c_prime = c[0..32].to_vec();
    let mut block = [0xffu8; 16];
    for idx in (0..16).rev() {
        for byte in 0..0xffu8 {
            c_prime[idx] = byte;
            let res = oracle.decrypt(&c_prime);
            if res.is_ok() && res.unwrap().last().unwrap() != &0x00 {
                block[idx] = byte ^ c[idx] ^ (16 - idx as u8);
                for i in idx..16 {
                    c_prime[i] ^= (16 - idx as u8) ^ (17 - idx as u8);
                }
                break;
            }
        }
    }

    // check
    println!("Recovered: {:02x?}", block);
    println!("Plaintext: {:02x?}", &p[16..32]);
    assert_eq!(block, &p[16..32]);
}

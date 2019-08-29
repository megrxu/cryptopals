use set_1::challenge_2_fixed_xor::xor;
use set_2::challenge_16_cbc_bitflipping::*;

fn increment(faults: &mut Vec<u8>) {
    let mut iter = faults.iter_mut();
    while let Some(byte) = iter.next() {
        if *byte == 0xff {
            *byte = 0x00;
            continue;
        } else {
            *byte += 1;
            break;
        }
    }
}

#[test]
fn test_input() {
    let oracle = EncryptionOracle::init();

    let mut c = oracle.encrypt(b"aaaabbbbccccdddd");
    println!("{:?}", String::from_utf8(oracle.decrypt(&c)));
    assert_eq!(oracle.is_admin(&c), false);

    // modify the ciphertext
    let before = b"aaaabbbbccccdddd";
    let faults = xor(b"00;admin=true;00", before);
    for i in 16..32 {
        c[i] ^= faults[i - 16];
    }

    // attack
    assert!(oracle.is_admin(&c));
    assert_eq!(oracle.decrypt(&c)[32..48].to_vec(), b"00;admin=true;00");
}

#[test]
fn attack() {}

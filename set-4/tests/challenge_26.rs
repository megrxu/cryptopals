use set_1::challenge_2_fixed_xor::xor;
use set_4::challenge_26_ctr_bitflipping::*;

#[test]
fn test_input() {
    let oracle = EncryptionOracle::init();
    let userdata = b"aaaabbbbccccdddd";

    let mut c = oracle.encrypt(userdata);
    assert!(!oracle.is_admin(&c));

    // get the length
    let c1 = oracle.encrypt(b"1");
    let c2 = oracle.encrypt(b"2");
    let mut length = 0;
    for (i, &item) in xor(&c1, &c2).iter().enumerate() {
        if item != 0 {
            length = i;
            break;
        }
    }

    // modify the ciphertext
    let faults = xor(b"00;admin=true;00", userdata);
    for i in 0..16 {
        c[length + i] ^= faults[i];
    }

    // check
    assert!(oracle.is_admin(&c));
    assert_eq!(oracle.decrypt(&c)[32..48].to_vec(), b"00;admin=true;00");
}

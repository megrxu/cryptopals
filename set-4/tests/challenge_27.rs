use set_1::challenge_2_fixed_xor::xor;
use set_4::challenge_27_cbc_key_as_iv::*;

#[test]
fn attack() {
    let oracle = EncryptionOracle::init();

    // get the ciphertext
    let plaintext = b"aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd";
    let ciphertext = oracle.encrypt(plaintext);

    // edit the ciphertext in flight
    let mut ciphertext_prime = vec![];
    let c_1 = &ciphertext[0..16];
    ciphertext_prime.append(&mut c_1.to_vec());
    ciphertext_prime.append(&mut vec![0; 16]);
    ciphertext_prime.append(&mut c_1.to_vec());

    // let the reciever to decrypt the modified ciphertext
    let plaintext_prime = oracle.decrypt(&ciphertext_prime);
    let key = xor(&plaintext_prime[0..16], &plaintext_prime[32..48]);

    // check
    assert!(oracle.is_revealed(&key));
}

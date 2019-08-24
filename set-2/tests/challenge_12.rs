use set_1::challenge_1_base64::base64_decode;
use set_2::challenge_11_detection_oracle::distinguisher;
use set_2::challenge_12_byte_at_a_time::EncryptionOracle;
use std::collections::HashMap;

#[test]
#[ignore]
fn test_decrypt() {
    let oracle = EncryptionOracle::init();

    //find block size
    let origin = oracle.encrypt(&[]).len();
    let mut block_size = 0usize;
    for i in 0..64 {
        let input = vec![b'A'; i];
        let current = oracle.encrypt(&input).len();
        if current != origin {
            block_size = current - origin;
            break;
        }
    }

    // detect ECB
    let ciphertext = oracle.encrypt(&vec![b'A'; block_size * 3]);
    assert_eq!(distinguisher(ciphertext), false);

    // decrypt
    let mut decrypted: Vec<u8> = vec![];

    // build dictionary
    let mut input = vec![b'A'; block_size];
    for round in 0..origin / block_size {
        for i in 1..block_size + 1 {
            let mut dictionary: HashMap<Vec<u8>, u8> = HashMap::default();
            for i in (0..0xffu8).filter(|&n| (n == b'\n') || (n >= 32 && n < 0x7f)) {
                input[block_size - 1] = i;
                dictionary.insert(oracle.encrypt(&input)[0..block_size].to_vec(), i);
            }
            let byte = *(dictionary
                .get(
                    &oracle.encrypt(&input[0..block_size - i].to_vec())
                        [(round * block_size)..(round + 1) * block_size]
                        .to_vec(),
                )
                .unwrap_or(&0xff));
            decrypted.push(byte);
            input[block_size - 1] = byte;
            input.rotate_left(1);
        }
    }
    // filter
    decrypted = decrypted.into_iter().filter(|&n| n != 0xff).collect();

    // compare and show
    assert_eq!(decrypted, base64_decode(&"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
    println!(
        "{:?}",
        String::from_utf8(decrypted).unwrap_or("Failed".into())
    );
}

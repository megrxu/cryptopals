use rand::Rng;
use set_2::rand;
use set_4::challenge_28_sha1_mac::*;

#[test]
fn poc() {
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let key = [0u8; 16];
    let mac = sha1_mac(&key, msg);
    let mut key_msg = key.to_vec();
    key_msg.append(&mut msg.to_vec());
    let padded_msg = sha1_padding(&key_msg);

    // the continuation
    let h = (mac[0], mac[1], mac[2], mac[3], mac[4]);

    let inject = b";admin=true;";
    let mut new_msg = vec![0u8; 128];
    new_msg.append(&mut inject.to_vec());
    new_msg[16..(16 + msg.len())].copy_from_slice(msg);
    new_msg[16 + msg.len()] = 0x80;
    new_msg[120..128].copy_from_slice(&(((msg.len() + 16) * 8) as u64).to_be_bytes());

    let padded_new_msg = sha1_padding(&new_msg);

    // check the padded msg
    assert_eq!(padded_msg, padded_new_msg[0..32]);

    // check the new_mac is identical to the desired one without knowing the key
    let new_mac = to_array(sha1_continue(&padded_new_msg[32..], h));
    assert_eq!(new_mac, sha1_mac(&key, &new_msg[16..]));
}

#[test]
fn attack_prefix_with_random_key() {
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let key = rand!(rand!(choose 5..20));
    let mac = sha1_mac(&key, msg);
    let mut key_msg = key.to_vec();
    key_msg.append(&mut msg.to_vec());

    // the continuation
    let h = (mac[0], mac[1], mac[2], mac[3], mac[4]);

    let inject = b";admin=true;";
    let mut new_msg = vec![0u8; 128];
    new_msg.append(&mut inject.to_vec());
    let mut success = false;
    for key_size in 5..20 {
        new_msg[key_size..(key_size + msg.len())].copy_from_slice(msg);
        new_msg[key_size + msg.len()] = 0x80;
        new_msg[120..128].copy_from_slice(&(((msg.len() + key_size) * 8) as u64).to_be_bytes());

        let padded_new_msg = sha1_padding(&new_msg);

        // check the new_mac is identical to the desired one without knowing the key
        let new_mac = to_array(sha1_continue(&padded_new_msg[32..], h));
        if new_mac == sha1_mac(&key, &new_msg[key_size..]) {
            success = true;
            println!("Key size is {}", key_size);
            break;
        }
    }
    assert!(success);
}

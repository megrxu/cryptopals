use set_1::challenge_2_fixed_xor::xor;

pub fn hmac<H>(hash: H, key: &[u8], msg: &[u8], blocksize: usize) -> Vec<u8>
where
    H: Fn(&[u8]) -> Vec<u8>,
{
    let mut key = key.to_vec();
    if key.len() > blocksize {
        key = hash(&key);
    }
    if key.len() < blocksize {
        key.append(&mut vec![0x00; blocksize - key.len()]); // Where * is repetition.
    }

    let o_key_pad = xor(&vec![0x5c; blocksize], &key);
    let i_key_pad = xor(&vec![0x36; blocksize], &key);

    let mut padded_msg = i_key_pad;
    padded_msg.append(&mut msg.into());
    let mut hash_msg = hash(&padded_msg);

    let mut padded_key = o_key_pad;
    padded_key.append(&mut hash_msg);
    hash(&padded_key)
}

use eva_crypto::aes::AES;
use set_1::challenge_2_fixed_xor::xor;
use set_3::challenge_18_ctr_mode::*;

pub fn edit(ciphertext: &mut [u8], key: &[u8], nounce: u64, offset: u64, newtext: &[u8]) {
  // pad the plaintext
  let padded = (offset % 16) as usize;
  let mut plaintext = vec![0; padded];
  plaintext.append(&mut newtext.to_vec());

  // get the new ciphertext
  let cipher = AES::new(key);
  let mut keystream = vec![];
  let counter = Counter::new(nounce);
  let ctr_offset = offset / 16;
  for i in 0..(plaintext.len() / 16 + 1) as u64 {
    keystream.push(cipher.encrypt(&counter.when(i + ctr_offset)))
  }
  let newciphertext = xor(&plaintext, &keystream.concat());

  // edit the old ciphertext
  for i in 0..newtext.len() {
    ciphertext[i + offset as usize] = newciphertext[i + padded];
  }
}

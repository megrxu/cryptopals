use eva_crypto::aes::AES;
use set_1::challenge_2_fixed_xor::xor;

pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut last = iv.to_vec();
    let mut ciphertext = vec![];
    let cipher = AES::new(key);

    for block in plaintext.chunks(16) {
        let block = cipher.encrypt(&xor(&block, &last));
        ciphertext.push(block[0..16].to_vec());
        last = block.to_vec();
    }
    ciphertext.concat()
}

pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut last = iv.to_vec();
    let mut plaintext = vec![];
    let cipher = AES::new(key);

    for block in ciphertext.chunks(16) {
        plaintext.push(xor(&last, &cipher.decrypt(block)));
        last = block.to_vec();
    }
    plaintext.concat()
}

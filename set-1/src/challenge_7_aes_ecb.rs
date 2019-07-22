use eva_crypto::aes::AES;

pub fn aes_ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = AES::new(key);
    let mut ciphertext = vec![];
    for block in plaintext.chunks(16) {
        ciphertext.push(cipher.encrypt(block));
    }
    ciphertext.concat()
}

pub fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = AES::new(key);
    let mut plaintext = vec![];
    for block in ciphertext.chunks(16) {
        plaintext.push(cipher.decrypt(block));
    }
    plaintext.concat()
}
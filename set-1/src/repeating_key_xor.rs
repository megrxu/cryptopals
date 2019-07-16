use super::fixed_xor::xor;

pub fn repeating_key_xor_cipher(key: &[u8], data: &[u8]) -> Vec<u8> {
    xor(data, &(vec![key; data.len() / key.len() + 1]).concat())
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(e1, e2)| e1 ^ e2).collect()
}

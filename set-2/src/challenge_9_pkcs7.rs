pub fn pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = vec![data.to_vec()];
    let iter = data.chunks_exact(block_size);
    let padded_size = block_size - iter.remainder().len();
    padded.push(vec![padded_size as u8; padded_size]);
    padded.concat()
}

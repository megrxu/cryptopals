use std::fmt;

pub struct PaddingError;

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid PKCS#7 padding") // user-facing output
    }
}

impl fmt::Debug for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}", file!(), line!()) // programmer-facing output
    }
}

pub fn pkcs7_unpadding(data: &[u8], block_size: usize) -> Result<Vec<u8>, PaddingError> {
    let padded: Vec<u8> = data.to_vec();
    let (others, last) = padded.split_at(padded.len() - block_size);
    let &padded_size = last.last().unwrap();
    let mut last_vec = last.to_vec();
    for _ in 0..padded_size {
        let byte = last_vec.pop();
        if byte != Some(padded_size) {
            return Err(PaddingError);
        }
    }
    Ok(vec![others, &last_vec].concat())
}

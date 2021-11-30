use base64 as bs64;
use lazy_static::lazy_static;

// implement base64 encode by hand
lazy_static! {
    static ref BASE64_TABLE: &'static [u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

/// Encode a byte array to base64
/// ```rust
/// use set_1::challenge_1_base64::base64_encode;
/// use hex_literal::hex;
///
/// assert_eq!(
/// base64_encode(&hex!(
///     "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
/// )),
/// "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
/// );
/// ```
pub fn base64_encode(data: &[u8]) -> String {
    let mut base64_bytes: Vec<Vec<u8>> = vec![];
    let mut data_vec = data.to_vec();
    data_vec.push(0);
    data_vec.push(0);
    for block in data_vec.chunks_exact(3) {
        base64_bytes.push(vec![
            BASE64_TABLE[(block[0] >> 2) as usize],
            BASE64_TABLE[((block[0] << 4 ^ block[1] >> 4) & 0b0011_1111) as usize],
            BASE64_TABLE[((block[1] << 2 ^ block[2] >> 6) & 0b0011_1111) as usize],
            BASE64_TABLE[(block[2] & 0b0011_1111) as usize],
        ])
    }
    let mut str_bytes = base64_bytes.concat();
    match data_vec.len() % 3 {
        0 => {
            str_bytes.pop();
            str_bytes.pop();
            str_bytes.push(b'=');
            str_bytes.push(b'=');
        }
        1 => {
            str_bytes.pop();
            str_bytes.push(b'=');
        }
        _ => (),
    }
    String::from_utf8(str_bytes).unwrap()
}

// base64 decode using a crate
pub fn base64_decode(base64_str: &str) -> Vec<u8> {
    bs64::decode(base64_str).unwrap()
}

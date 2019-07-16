#[macro_use]
extern crate hex_literal;

mod base64 {
    pub fn base64(data: &[u8]) -> String {
        let table: &[u8] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ".as_bytes();
        let mut base64_bytes: Vec<Vec<u8>> = vec![];
        let mut data_vec = data.to_vec();
        data_vec.push(0);
        data_vec.push(0);
        let mut iter = data_vec.chunks_exact(3);
        while let Some(block) = iter.next() {
            base64_bytes.push(vec![
                table[(block[0] >> 2) as usize],
                table[((block[0] << 4 ^ block[1] >> 4) & 0b00111111) as usize],
                table[((block[1] << 2 ^ block[2] >> 6) & 0b00111111) as usize],
                table[(block[2] & 0b00111111) as usize],
            ])
        }
        let mut str_bytes = base64_bytes.concat();
        match data_vec.len() % 3 {
            0 => {
                str_bytes.pop();
                str_bytes.pop();
                str_bytes.push('=' as u8);
                str_bytes.push('=' as u8);
            }
            1 => {
                str_bytes.pop();
                str_bytes.push('=' as u8);
            }
            _ => (),
        }
        String::from_utf8(str_bytes).unwrap()
    }
}

mod fixed_xor {
    pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(e1, e2)| e1 ^ e2).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::base64::base64;
    use super::fixed_xor::xor;

    #[test]
    fn base64_test() {
        assert_eq!(base64(&hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(
            base64(b"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."),
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="
        );
        assert_eq!(base64(b"easure."), "ZWFzdXJlLg==");
    }

    #[test]
    fn xor_test() {
        assert_eq!(
            xor(
                &hex!("1c0111001f010100061a024b53535009181c"),
                &hex!("686974207468652062756c6c277320657965")
            ),
            hex!("746865206b696420646f6e277420706c6179")
        )
    }
}

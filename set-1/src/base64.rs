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

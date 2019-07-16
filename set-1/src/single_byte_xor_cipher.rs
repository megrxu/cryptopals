use super::fixed_xor::xor;

pub fn crack_key(data: &[u8]) -> (u8, String) {
    let mut scores = [0; 256];
    for i in 0..256 {
        let key: Vec<u8> = vec![i as u8; data.len()];
        scores[i] = score(&xor(&data, &key));
    }
    let mut max_idx = 0;
    for i in 0..256 {
        if scores[i] >= scores[max_idx] {
            max_idx = i;
        }
    }
    (
        max_idx as u8,
        String::from_utf8(xor(&data, &vec![max_idx as u8; data.len()]))
            .unwrap_or("Failed!".to_string()),
    )
}

fn score(bytes: &[u8]) -> usize {
    let printable = bytes.iter().filter(|&n| *n >= 0x20 && *n <= 0x7E).count();
    let e_freq = bytes.iter().filter(|&n| *n == 'e' as u8).count();
    let space = bytes.iter().filter(|&n| *n == ' ' as u8).count();
    (e_freq + printable) * space
}

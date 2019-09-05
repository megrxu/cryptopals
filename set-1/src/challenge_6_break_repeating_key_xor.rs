use super::challenge_2_fixed_xor::xor;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref WEIGHT: [usize; 256] = {
        let mut weight_table = [0; 256];
        for i in 0..256 {
            let mut weight = 0;
            let mut byte = i as u8;
            for _ in 0..8 {
                weight += (byte & 0x01) as usize;
                byte >>= 1;
            }
            weight_table[i as usize] = weight;
        }
        weight_table
    };
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    hamming_weight(&xor(a, b))
}

pub fn hamming_weight(bytes: &[u8]) -> usize {
    bytes.iter().fold(0, |res, &x| res + WEIGHT[x as usize])
}

pub fn find_keysize(data: &[u8]) -> Vec<usize> {
    // Compute the hamming distances
    let mut hamming_distances: Vec<usize> = vec![];
    for keysize in 2..40 {
        let mut distance = 0;
        for chunk in data.chunks_exact(2 * keysize) {
            distance += hamming_distance(&chunk[0..keysize], &chunk[keysize..2 * keysize]);
        }
        hamming_distances.push(distance);
    }

    // Sort keysize by the hamming distance
    let mut keysizes: Vec<usize> = (2..40).collect();
    keysizes.sort_by(|&a, &b| {
        hamming_distances[a - 2]
            .partial_cmp(&hamming_distances[b - 2])
            .unwrap()
    });

    // Take first 3 most possible keysize
    keysizes
        .into_iter()
        .zip([0; 3].iter())
        .map(|(e1, _)| e1)
        .collect()
}

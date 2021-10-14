use super::challenge_28_sha1_mac::{from_u32_vec, sha1_padding, Endian};

pub fn md4_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut km = vec![];
    km.append(&mut key.into());
    km.append(&mut msg.into());
    md4(&km)
}

pub fn md4(msg: &[u8]) -> Vec<u8> {
    let h = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
    let padded = sha1_padding(msg, Endian::Lit);
    let res = md4_continue(&padded, h);
    from_u32_vec(&[res.0, res.1, res.2, res.3], Endian::Lit)
}

// tiny auxiliary functions
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((!x) & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn add_all(param: &[u32]) -> u32 {
    param.iter().fold(0, |res, &x| res.overflowing_add(x).0)
}

#[allow(clippy::many_single_char_names)]
fn round_1_aux(a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32, x: &[u32]) {
    *a = add_all(&[*a, f(b, c, d), x[k]]).rotate_left(s);
}

#[allow(clippy::many_single_char_names)]
fn round_2_aux(a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32, x: &[u32]) {
    *a = add_all(&[*a, g(b, c, d), x[k], 0x5A827999]).rotate_left(s);
}

#[allow(clippy::many_single_char_names)]
fn round_3_aux(a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32, x: &[u32]) {
    *a = add_all(&[*a, h(b, c, d), x[k], 0x6ED9EBA1]).rotate_left(s);
}

pub fn md4_continue(msg: &[u32], buffer: (u32, u32, u32, u32)) -> (u32, u32, u32, u32) {
    let mut h = buffer;
    let mut x = [0u32; 16];

    for m in msg.chunks(16) {
        x.clone_from_slice(m);
        let (aa, bb, cc, dd) = h;
        // Round 1
        for i in 0..4 {
            round_1_aux(&mut h.0, h.1, h.2, h.3, 4 * i, 3, &x);
            round_1_aux(&mut h.3, h.0, h.1, h.2, 1 + 4 * i, 7, &x);
            round_1_aux(&mut h.2, h.3, h.0, h.1, 2 + 4 * i, 11, &x);
            round_1_aux(&mut h.1, h.2, h.3, h.0, 3 + 4 * i, 19, &x);
        }
        // Round 2
        for i in 0..4 {
            round_2_aux(&mut h.0, h.1, h.2, h.3, i, 3, &x);
            round_2_aux(&mut h.3, h.0, h.1, h.2, 4 + i, 5, &x);
            round_2_aux(&mut h.2, h.3, h.0, h.1, 8 + i, 9, &x);
            round_2_aux(&mut h.1, h.2, h.3, h.0, 12 + i, 13, &x);
        }
        // Round 3
        for i in [0usize, 2, 1, 3].iter() {
            round_3_aux(&mut h.0, h.1, h.2, h.3, *i, 3, &x);
            round_3_aux(&mut h.3, h.0, h.1, h.2, 8 + i, 9, &x);
            round_3_aux(&mut h.2, h.3, h.0, h.1, 4 + i, 11, &x);
            round_3_aux(&mut h.1, h.2, h.3, h.0, 12 + i, 15, &x);
        }
        // final
        h = (add_all(&[h.0, aa]), add_all(&[h.1, bb]), add_all(&[h.2, cc]), add_all(&[h.3, dd]));
    }
    h
}

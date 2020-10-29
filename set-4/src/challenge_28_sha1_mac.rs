use std::convert::TryInto;

pub fn sha1(msg: &[u8]) -> [u32; 5] {
    let padded = sha1_padding(msg);
    let mut h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);
    let mut buffer: (u32, u32, u32, u32, u32);
    let mut w = [0u32; 80];

    for m in padded.chunks(16) {
        w[..16].clone_from_slice(&m[..16]);
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }
        buffer = (h.0, h.1, h.2, h.3, h.4);
        for (t, _) in w.iter().enumerate() {
            buffer = (
                (buffer.0)
                    .rotate_left(5)
                    .overflowing_add(f(t, buffer.1, buffer.2, buffer.3))
                    .0
                    .overflowing_add(buffer.4)
                    .0
                    .overflowing_add(w[t])
                    .0
                    .overflowing_add(k(t))
                    .0,
                buffer.0,
                (buffer.1).rotate_left(30),
                buffer.2,
                buffer.3,
            );
        }
        h = (
            h.0.overflowing_add(buffer.0).0,
            h.1.overflowing_add(buffer.1).0,
            h.2.overflowing_add(buffer.2).0,
            h.3.overflowing_add(buffer.3).0,
            h.4.overflowing_add(buffer.4).0,
        )
    }
    [h.0, h.1, h.2, h.3, h.4]
}

fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | ((!b) & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        60..=79 => b ^ c ^ d,
        _ => unreachable!(),
    }
}

fn k(t: usize) -> u32 {
    match t {
        00..=19 => 0x5A827999,
        20..=39 => 0x6ED9EBA1,
        40..=59 => 0x8F1BBCDC,
        60..=79 => 0xCA62C1D6,
        _ => unreachable!(),
    }
}

fn sha1_padding(msg: &[u8]) -> Vec<u32> {
    let len = msg.len();
    let rem = (len + 1) % 64;
    let zero_len = if rem <= 56 { 56 - rem } else { 120 - rem };
    let mut padded = msg.to_vec();
    let mut msg_len = ((len * 8) as u64).to_be_bytes().to_vec();
    padded.push(0x80);
    padded.append(&mut vec![0; zero_len]);
    padded.append(&mut msg_len);
    padded.chunks(4).map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap())).collect()
}

#[test]
fn test_padding() {
    let msg = b"abc";
    let padded = sha1_padding(msg);
    padded.iter().for_each(|x| println!("{:08x?}", x));
    assert_eq!(padded.len() % 16, 0);

    println!("{:x?}", sha1(msg));
}

use super::challenge_21_mersenne_twister::*;

pub fn untamper(output: u32) -> u32 {
    let mut y;
    // y = y ^ (y >> L);
    y = (output & (0xffffffff << (32 - L))) | ((output >> L) ^ (output & (0xffffffff >> L)));

    // y = y ^ ((y << T) & C);
    let l15 = y & (0xffffffff >> (32 - T));
    let l30 = ((l15 << T) & C ^ y) & (0xffffffff >> (32 - T)) << T;
    let l32 = ((l30 << T) & C ^ y) & (0xffffffff >> (32 - T) << (T * 2));
    y = l32 | l30 | l15;

    // y = y ^ ((y << S) & B);
    let l7 = y & (0xffffffff >> (32 - S));
    let l14 = ((l7 << S) & B ^ y) & (0xffffffff >> (32 - S)) << S;
    let l21 = ((l14 << S) & B ^ y) & (0xffffffff >> (32 - S)) << (S * 2);
    let l28 = ((l21 << S) & B ^ y) & (0xffffffff >> (32 - S)) << (S * 3);
    let l32 = ((l28 << S) & B ^ y) & (0xffffffff >> (32 - S) << (S * 4));
    y = l32 | l28 | l21 | l14 | l7;

    // y = y ^ ((y >> U) & D);
    let h11 = y & (0xffffffff << (32 - U));
    let h22 = ((h11 >> U) & D ^ y) & (0xffffffff << (32 - U) >> U);
    let h32 = ((h22 >> U) & D ^ y) & (0xffffffff << (32 - U) >> (U * 2));
    y = h11 | h22 | h32;

    // final
    y
}

use super::challenge_33_dh::*;
use num_bigint::{RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{FromPrimitive, One, Signed, Zero};
use rand::distributions::Distribution;
use std::convert::TryFrom;

pub trait ModInv {
    fn modinv(&self, modulus: &Self) -> Self;
}

fn ext_euclid(a: &iinf, b: &iinf) -> (iinf, iinf, iinf) {
    let (mut s_, mut s) = (iinf::one(), iinf::zero());
    let (mut t_, mut t) = (iinf::zero(), iinf::one());
    let (mut r_, mut r) = (a.clone(), b.clone());
    if b.is_zero() {
        return (One::one(), Zero::zero(), a.clone());
    } else {
        while !r.is_zero() {
            let q = r_.div_floor(&r);
            let tmp = r.clone();
            r = r_ - q.clone() * r;
            r_ = tmp;
            let tmp = s.clone();
            s = s_ - q.clone() * s;
            s_ = tmp;
            let tmp = t.clone();
            t = t_ - q.clone() * t;
            t_ = tmp;
        }
    }
    (s_, t_, r_)
}

/// The inverse of a modulo m.
/// ```rust
/// use set_5::challenge_39_rsa::{ModInv};
/// use set_5::challenge_33_dh::uinf;
/// use num_traits::{FromPrimitive, One};
///
/// let one = uinf::one();
/// let num = uinf::from_u64(17).unwrap();
/// let p = uinf::from_u64(3120).unwrap();
/// let inv = num.modinv(&p);
/// assert_eq!( &inv * &num % &p, one);
/// assert_eq!( inv, uinf::from_u64(2753).unwrap());
/// ```
impl ModInv for uinf {
    fn modinv(&self, modulus: &uinf) -> uinf {
        let a = iinf::from_biguint(Sign::Plus, self.clone());
        let b = iinf::from_biguint(Sign::Plus, modulus.clone());
        let (s, _, r) = ext_euclid(&a, &b);
        if r == One::one() {
            let mut res = s;
            while res.is_negative() {
                res += b.clone();
            }
            uinf::try_from(res).unwrap()
        } else {
            uinf::zero()
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MillerRabinStatus {
    ProbablyPrime,
    ProvablyComposite(uinf),
    NotPowerOfPrime,
}

/// ## Miller-Rabin primality test
/// Refer to FIPS 186-4 C.3.2, *Enhanced Miller-Rabin Probabilistic Primality Test*.
/// <https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf>
/// ```rust
/// use set_5::challenge_39_rsa::{miller_rabin_test, MillerRabinStatus};
/// use set_5::challenge_33_dh::uinf;
/// use num_traits::FromPrimitive;
///
/// assert_eq!(miller_rabin_test(&uinf::from_u64(99999199999).unwrap(), 128), MillerRabinStatus::ProbablyPrime);
/// ```
pub fn miller_rabin_test(w: &uinf, iterations: usize) -> MillerRabinStatus {
    let w_ = w.clone() - uinf::one();
    let two = uinf::from_u8(2).unwrap();
    let wlen = w.bits();
    let mut rng = rand::thread_rng();

    // Let a be the largest integer such that 2 ** a divides w–1.
    let a = (0..wlen).filter(|&i| w_.is_multiple_of(&two.pow(i as u32))).max().unwrap();
    let m = w_.div_floor(&two.pow(a as u32));

    // Main Loop
    for _ in 0..iterations {
        // Set the flags
        let mut continue_flag = false;
        let mut skip_flag = false;

        // Random string b, ensure that 1 < b < w - 1
        let b = loop {
            let b_ = rng.gen_biguint(wlen);
            if b_ > uinf::one() && b_ < w_ {
                break b_;
            }
        };
        let mut g = b.gcd(w);
        if g > One::one() {
            return MillerRabinStatus::ProvablyComposite(g);
        }
        let mut z = b.modpow(&m, w);
        if (z == uinf::one()) || (z == w_) {
            continue;
        }
        // This x is shared until the end of the main loop
        let mut x = uinf::one();
        // The sub loop
        for _ in 0..a {
            x = z.clone();
            z = x.modpow(&two, w);
            if z == w_ {
                continue_flag = true;
                break; // break the sub loop
            }
            if z == uinf::one() {
                skip_flag = true;
                break; // break the sub loop
            }
        }
        if continue_flag {
            continue; // continue to the next iteration
        }
        if !skip_flag {
            x = z.clone();
            z = x.modpow(&two, w);
            if z != uinf::one() {
                x = z;
            }
        }
        g = (x - uinf::one()).gcd(w);
        if g > uinf::one() {
            return MillerRabinStatus::ProvablyComposite(g);
        }
        return MillerRabinStatus::NotPowerOfPrime;
    }
    MillerRabinStatus::ProbablyPrime
}

/// ```rust
/// use set_5::challenge_39_rsa::probably_prime;
/// use set_5::challenge_33_dh::uinf;
/// use num_traits::FromPrimitive;
///
/// assert_eq!(
/// vec![
///     2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
///     89, 97
/// ],
/// (0..100).filter(|&i| probably_prime(&uinf::from_u64(i).unwrap())).collect::<Vec<_>>()
/// );
/// ```
pub fn probably_prime(w: &uinf) -> bool {
    if w <= &uinf::one() {
        return false;
    } else if w.is_even() {
        return w == &uinf::from_u8(2).unwrap();
    } else if w == &uinf::from_u8(3).unwrap() {
        return true;
    }

    let bits = w.bits();
    let iterations = if bits > 2048 { 128 } else { 64 };
    matches!(miller_rabin_test(w, iterations), MillerRabinStatus::ProbablyPrime)
}

pub struct ProbablyPrimeDistribution(pub u64);

/// ```rust
/// use set_5::challenge_39_rsa::{probably_prime, ProbablyPrimeDistribution};
/// use set_5::challenge_33_dh::uinf;
/// use rand::Rng;
/// use rand::distributions::Distribution;
///
/// let dist = ProbablyPrimeDistribution(256);
/// let mut rng = rand::thread_rng();
/// for i in 0..5 {
///     let n = dist.sample(&mut rng);
///     assert!(probably_prime(&n));
/// }
/// ```
impl rand::distributions::Distribution<uinf> for ProbablyPrimeDistribution {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> uinf {
        match self {
            ProbablyPrimeDistribution(bits) => loop {
                let w = rng.gen_biguint(*bits);
                if probably_prime(&w) {
                    return w;
                }
            },
        }
    }
}

#[derive(Default, Clone)]
pub struct RSA;

#[derive(Clone, PartialEq, Debug)]
pub struct RsaPrivateKey {
    d: uinf,
    n: uinf,
}

#[derive(Clone, PartialEq, Debug)]
pub struct RsaPublicKey {
    e: uinf,
    n: uinf,
}

/// ```rust
/// use set_5::challenge_39_rsa::{RSA, RsaPrivateKey, RsaPublicKey};
/// use set_5::challenge_33_dh::uinf;
/// use num_traits::FromPrimitive;
///
/// let (privkey, pubkey) = RSA::keygen(3, 64);
/// let m = uinf::from_u64(42).unwrap();
/// let c = RSA::encrypt(&pubkey, &m);
/// let m_ = RSA::decrypt(&privkey, &c);
/// assert_eq!(m_, m);
/// ```
impl RSA {
    pub fn keygen(e: u64, bits: u64) -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let dist = ProbablyPrimeDistribution(bits);
        let res = loop {
            let (p, q) = (dist.sample(&mut rng), dist.sample(&mut rng));
            let n = p.clone() * q.clone();
            let et = (p - uinf::one()) * (q - uinf::one());
            let e_ = uinf::from_u64(e).unwrap();
            let d = e_.modinv(&et);
            if !d.is_zero() {
                break (RsaPrivateKey { d, n: n.clone() }, RsaPublicKey { e: e_, n });
            }
        };
        println!("{:?}", res);
        res
    }

    pub fn encrypt(pubkey: &RsaPublicKey, m: &uinf) -> uinf {
        m.modpow(&pubkey.e, &pubkey.n)
    }

    pub fn decrypt(privkey: &RsaPrivateKey, c: &uinf) -> uinf {
        c.modpow(&privkey.d, &privkey.n)
    }
}

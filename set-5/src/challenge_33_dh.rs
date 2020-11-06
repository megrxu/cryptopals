use num_bigint::{BigInt, BigUint};
use num_traits::{FromPrimitive, One, Zero};
use rand::Rng;
use set_2::rand;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Num, NumOps, FromPrimitive, ToPrimitive, One, Zero)]
pub struct uinf(BigUint);

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Num, NumOps, FromPrimitive, ToPrimitive, One, Zero)]
pub struct iinf(BigInt);

impl uinf {
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        uinf(BigUint::from_bytes_be(bytes))
    }
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        uinf(BigUint::from_bytes_le(bytes))
    }
    pub fn two() -> Self {
        uinf::from_u8(2).unwrap()
    }
    pub fn gen() -> Self {
        uinf(BigUint::from_bytes_be(&rand!(3)))
    }
}

pub fn mod_exp(modulo: uinf, base: uinf, exp: uinf) -> uinf {
    mod_exp_iter(&modulo, &base, &exp, uinf::one())
}

pub fn mod_mul(modulo: uinf, a: uinf, b: uinf) -> uinf {
    mod_mul_iter(&modulo, &a, &b, uinf::zero())
}

fn mod_mul_iter(modulo: &uinf, a: &uinf, b: &uinf, res: uinf) -> uinf {
    if b.clone() == uinf::zero() {
        res
    } else if b.clone() % uinf::two() == uinf::zero() {
        mod_mul_iter(modulo, &(a.clone() * uinf::two()), &(b.clone() / uinf::two()), res)
    } else {
        mod_mul_iter(
            modulo,
            &(a.clone() * uinf::two()),
            &(b.clone() / uinf::two()),
            (res + a.clone()) % modulo.clone(),
        )
    }
}

fn mod_exp_iter(modulo: &uinf, base: &uinf, exp: &uinf, res: uinf) -> uinf {
    if exp.clone() == uinf::zero() {
        res
    } else if exp.clone() % uinf::two() == uinf::zero() {
        mod_exp_iter(
            modulo,
            &(mod_mul(modulo.clone(), base.clone(), base.clone())),
            &(exp.clone() / uinf::two()),
            res,
        )
    } else {
        mod_exp_iter(
            modulo,
            &(mod_mul(modulo.clone(), base.clone(), base.clone())),
            &(exp.clone() / uinf::two()),
            res * base.clone() % modulo.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DHKey {
    pub p: uinf,
    pub pkey: uinf,
    g: uinf,
    skey: uinf,
}

impl DHKey {
    pub fn new_from(p: &uinf, g: &uinf, skey: uinf) -> Self {
        let pkey = mod_exp(p.clone(), g.clone(), skey.clone());
        DHKey { p: p.clone(), g: g.clone(), pkey, skey }
    }

    pub fn key_exchange(&self, bpkey: &uinf) -> uinf {
        mod_exp(self.p.clone(), bpkey.clone(), self.skey.clone())
    }
}

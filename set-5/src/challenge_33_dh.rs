use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint};

#[allow(non_camel_case_types)]
pub type uinf = BigUint;
#[allow(non_camel_case_types)]
pub type iinf = BigInt;

pub fn mod_exp(modulo: uinf, base: uinf, exp: uinf) -> uinf {
    base.modpow(&exp, &modulo)
}

pub fn mod_mul(modulo: uinf, a: uinf, b: uinf) -> uinf {
    a * b % modulo
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

lazy_static! {
    pub static ref NIST_P : uinf = uinf::from_bytes_be(&hex::decode(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
    ).unwrap());
}

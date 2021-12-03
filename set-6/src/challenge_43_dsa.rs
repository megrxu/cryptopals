use hex_literal::hex;
use num_bigint::RandBigInt;
use num_traits::FromPrimitive;
use num_traits::Zero;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::ModInv;

#[derive(Clone)]
pub struct DSA {
    pub p: uinf,
    pub q: uinf,
    pub g: uinf,
}

/// Digital Signature Algorithm <https://en.wikipedia.org/wiki/Digital_signature_algorithm>
/// ```rust
/// use set_6::challenge_43_dsa::*;
/// use num_traits::FromPrimitive;
/// use set_5::challenge_33_dh::uinf;
///
/// let dsa = DSA::default();
/// let (privkey, pubkey) = dsa.keygen();
/// let hm = uinf::from_u64(1000).unwrap();
/// let sig = dsa.raw_sign(&privkey, &hm);
/// assert!(dsa.raw_verify(&pubkey, &hm, &sig));
/// ```
impl DSA {
    pub fn para_gen() -> DSA {
        let p = uinf::from_u64(0x8000000000000000).unwrap();
        let q = uinf::from_u64(0x8000000000000001).unwrap();
        let g = uinf::from_u64(0x8000000000000001).unwrap();
        DSA { p, q, g }
    }
    pub fn new(p: uinf, q: uinf, g: uinf) -> DSA {
        DSA { p, q, g }
    }

    pub fn keygen_with_bits(&self, bits: u64) -> (uinf, uinf) {
        let mut rng = rand::thread_rng();
        let x = loop {
            let _x = rng.gen_biguint(bits) % &self.q;
            if !_x.is_zero() {
                break _x;
            }
        };
        let y = self.g.modpow(&x, &self.p);
        (x, y)
    }

    pub fn keygen(&self) -> (uinf, uinf) {
        self.keygen_with_bits(2048)
    }

    pub fn raw_sign_with_bits(&self, bits: u64, privkey: &uinf, hm: &uinf) -> (uinf, uinf) {
        let mut rng = rand::thread_rng();
        loop {
            let k = rng.gen_biguint(bits) % &self.q;
            let r = self.g.modpow(&k, &self.p) % &self.q;
            let s = (k.modinv(&self.q) * (hm + privkey * &r)) % &self.q;
            if !k.is_zero() || !r.is_zero() && !s.is_zero() {
                return (r, s);
            }
        }
    }

    pub fn raw_sign(&self, privkey: &uinf, hm: &uinf) -> (uinf, uinf) {
        self.raw_sign_with_bits(2048, privkey, hm)
    }

    pub fn raw_verify(&self, pubkey: &uinf, hm: &uinf, sig: &(uinf, uinf)) -> bool {
        let (r, s) = sig;
        if r >= &self.q || s >= &self.q {
            return false;
        }
        let w = s.modinv(&self.q);
        let u_1 = (hm * w.clone()) % &self.q;
        let u_2 = (r * w) % &self.q;
        let v = (self.g.modpow(&u_1, &self.p) * pubkey.modpow(&u_2, &self.p) % &self.p) % &self.q;
        &v == r
    }
}

impl Default for DSA {
    fn default() -> DSA {
        let p_s = hex!(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"
        );
        let q_s = hex!("f4f47f05794b256174bba6e9b396a7707e563c5b");
        let g_s = hex!(
            "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291"
        );
        let p = uinf::from_bytes_be(&p_s);
        let q = uinf::from_bytes_be(&q_s);
        let g = uinf::from_bytes_be(&g_s);
        DSA { p, q, g }
    }
}

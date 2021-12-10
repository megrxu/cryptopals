use num_integer::Integer;
use num_traits::FromPrimitive;
use set_5::challenge_33_dh::uinf;
use set_6::challenge_41_rsa_armoring::*;

trait ParityOracle {
    fn parity(&mut self, c: &[u8]) -> bool;
}

impl ParityOracle for RsaInstance {
    fn parity(&mut self, c: &[u8]) -> bool {
        let m = self.decrypt(c).unwrap();
        m.iter().last().unwrap() % 2 == 0
    }
}

#[test]
fn rsa_parity_oracle() {
    let m = b"I feel lucky!";

    let mut instance = RsaInstance::default();
    let ciphertext = instance.encrypt(m).unwrap();

    let mut parity = instance.parity(&ciphertext);

    // n / m, 0/1 -> 1/1
    let mut top_n = uinf::from_u64(1).unwrap();
    let mut top_m = uinf::from_u64(1).unwrap();
    let mut bot_n = uinf::from_u64(0).unwrap();
    let mut bot_m = uinf::from_u64(1).unwrap();
    let two = uinf::from_u64(2).unwrap();
    let n = instance.pubkey.n.clone();
    let e = instance.pubkey.e.clone();

    let mid_mn = |a_n: &uinf, a_m: &uinf, b_n: &uinf, b_m: &uinf| -> (uinf, uinf) {
        let lcm = a_m.lcm(b_m);
        (
            lcm.clone() / a_m.clone() * a_n.clone() + lcm.clone() / b_m.clone() * b_n.clone(),
            two.clone() * lcm.clone(),
        )
    };
    let mut c = uinf::from_bytes_be(&ciphertext);

    for _ in 0..n.bits() {
        let nm = mid_mn(&top_n, &top_m, &bot_n, &bot_m);
        c = c.clone() * two.modpow(&e, &n) % n.clone();
        let p = instance.parity(&c.to_bytes_be());
        if p == parity {
            bot_n = nm.0;
            bot_m = nm.1;
            parity = p;
        } else {
            top_n = nm.0;
            top_m = nm.1;
        }
    }

    let m_top = n.clone() * top_n / top_m;
    let m_bot = n.clone() * bot_n / bot_m;

    let m_ori = uinf::from_bytes_be(m);

    assert!(m_ori == m_top || m_ori == m_bot);
}

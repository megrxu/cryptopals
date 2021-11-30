use num_traits::FromPrimitive;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::{ModInv, RSA};

#[test]
fn rsa_broadcast_attack() {
    let (_, pub_0) = RSA::keygen(3, 64);
    let (_, pub_1) = RSA::keygen(3, 64);
    let (_, pub_2) = RSA::keygen(3, 64);

    let m = uinf::from_u64(42).unwrap();

    let c_0 = pub_0.raw_encrypt(&m);
    let c_1 = pub_1.raw_encrypt(&m);
    let c_2 = pub_2.raw_encrypt(&m);

    let ms_0 = pub_1.n.clone() * pub_2.n.clone();
    let ms_1 = pub_0.n.clone() * pub_2.n.clone();
    let ms_2 = pub_0.n.clone() * pub_1.n.clone();
    let n = pub_0.n.clone() * pub_1.n.clone() * pub_2.n.clone();

    let res = ((c_0 * ms_0.clone() * ms_0.modinv(&pub_0.n))
        + (c_1 * ms_1.clone() * ms_1.modinv(&pub_1.n))
        + (c_2 * ms_2.clone() * ms_2.modinv(&pub_2.n)))
        % n;
    assert_eq!(res.cbrt(), m);
}

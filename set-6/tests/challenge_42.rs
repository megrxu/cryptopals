use rand::RngCore;
use set_5::challenge_33_dh::uinf;
use set_6::challenge_42_pkcs1::*;

#[test]
fn bleichenbachers_attack() {
    let mut instance = RsaPKCS1Signature::new();

    let msg = b"hi mom";

    let sig = instance.sign(msg).unwrap();
    assert!(instance.verify(&sig, msg, true).is_ok());
    assert!(instance.verify(&sig, msg, false).is_ok());

    let msg_len = msg.len();
    let hash_len = 20;
    let len = 3 + msg_len + hash_len;
    let mut forged = vec![0u8; len];
    let mut rng = rand::thread_rng();

    forged[0] = 0x01;
    forged[1] = 0xff;
    forged[2] = 0x00;
    forged[3..3 + msg_len].copy_from_slice(msg);

    let _3 = &uinf::from_slice(&[3]);
    rng.fill_bytes(&mut forged[3 + msg_len..len]);
    let em = uinf::from_bytes_be(&forged[..len]);
    let forged_sig = em.cbrt().to_bytes_be();
    assert!(instance.verify(&forged_sig, msg, true).is_ok());
    assert!(instance.verify(&forged_sig, msg, false).is_err());
}

use num_traits::FromPrimitive;
use rand::seq::SliceRandom;
use rand::Rng;
use set_2::rand;
use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::{uinf, NIST_P};
use set_5::challenge_38_ssrp::*;

#[test]
fn test_ssrp() {
    let mut instance = SSRPInstance::init(&rand!(16), &rand!(16));

    let mut client = instance.client();
    let mut server = instance.server();

    // C->S
    // Send I, A=g**a % N (a la Diffie Hellman)
    let packet = (Some(client.public_key()), client.email.to_vec());
    instance.handle(&mut client, &mut server, SSRPWire::ClientToServer, packet);

    // S->C
    // Send a random 128-bit u, B = g**b % N
    let packet = (Some(server.public_key()), rand!(16));
    instance.handle(&mut client, &mut server, SSRPWire::ServerToClient, packet);

    // C->S
    // Token challenge
    let packet = (None, client.token.clone().unwrap());
    let status = instance.handle(&mut client, &mut server, SSRPWire::ClientToServer, packet);

    assert_eq!(status, SSRPStatus::Success);
}

#[test]
fn attack_ssrp() {
    let password_candidates = [
        "password".as_bytes(),
        "pa55word".as_bytes(),
        "PassW0rD".as_bytes(),
        "Pa5sw0rd".as_bytes(),
        "passwoRd".as_bytes(),
    ];
    let mut rng = rand::thread_rng();
    let password = password_candidates.choose(&mut rng).unwrap();
    let mut instance = SSRPInstance::init(&rand!(16), password);

    // Malicious server set salt to 0
    instance.config = SSRPConfig::new(NIST_P.clone(), uinf::from_u64(2).unwrap(), vec![]);

    let mut client = instance.client();
    let mut malious_server = instance.server();
    let p = instance.config.p.clone();
    let g = instance.config.g.clone();

    // C->S
    // Send I, A=g**a % N (a la Diffie Hellman)
    let packet = (Some(client.public_key()), client.email.to_vec());
    instance.handle(&mut client, &mut malious_server, SSRPWire::ClientToServer, packet);

    // S->C
    // Send a random 128-bit u, B = g**b % N
    // But malicious server set b = u = 1, thus B = g**1 % N = g,
    // Therefore, Client_S = B ** (a + ux) = g ** (a + x) = A * (g ** x),
    // where A is the public key of the client
    let packet = (Some(g.clone()), vec![1]);
    instance.handle(&mut client, &mut malious_server, SSRPWire::ServerToClient, packet);

    // C->S
    // Get Client Token and Guess
    let token = client.token.clone().unwrap();

    // Without any knowledge of the password, the server can generate a list of tokens to check
    let tokens_to_check = password_candidates
        .iter()
        .map(|password| {
            let x = uinf::from_bytes_be(&sha1(password));
            let res = (client.public_key() * g.modpow(&x, &p)) % &p;
            sha1(&res.to_bytes_be())
        })
        .collect::<Vec<Vec<u8>>>();

    // And the client-generated token must be in these tokens, which implies the password
    assert!(tokens_to_check.contains(&token));
}

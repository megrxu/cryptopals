use rand::Rng;
use set_2::rand;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_36_srp::*;

#[test]
fn test_srp_with_some_keys() {
    let mut instance = SRPInstance::init(&rand!(16), &rand!(16));
    let mut client = instance.client();
    let mut server = instance.server();
    // C->S
    // Send I, A=g**a % N (a la Diffie Hellman)
    let packet = (Some(uinf::from_bytes_be(&[0])), client.email.to_vec());
    instance.handle(&mut client, &mut server, SRPWire::ClientToServer, packet);
    // S->C
    // Send salt, B=kv + g**b % N
    let packet = (Some(server.public_key()), server.salt.to_vec());
    instance.handle(&mut client, &mut server, SRPWire::ServerToClient, packet);

    // C->S
    // Token challenge
    let packet = (None, client.token.clone().unwrap());
    let status = instance.handle(&mut client, &mut server, SRPWire::ClientToServer, packet);
}

use super::challenge_33_dh::*;
use num_traits::FromPrimitive;
use rand::Rng;
use set_2::rand;
use set_4::challenge_28_sha1_mac::{sha1, sha1_mac};

#[derive(Clone)]
pub struct SSRPConfig {
    pub p: uinf,
    pub g: uinf,
    pub salt: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SSRPStatus {
    ServerInit,
    ServerReady,
    ClientReady,
    Success,
    Unauthorized,
}

pub struct SSRPServer {
    config: SSRPConfig,
    verifier: uinf,
    private_key: uinf,
    token: Option<Vec<u8>>,
}

pub struct SSRPClient {
    pub email: Vec<u8>,
    pub token: Option<Vec<u8>>,
    config: SSRPConfig,
    password: Vec<u8>,
    private_key: uinf,
}

pub struct SSRPInstance {
    pub config: SSRPConfig,
    status: SSRPStatus,
    email: Vec<u8>,
    password: Vec<u8>,
}

pub enum SSRPWire {
    ClientToServer,
    ServerToClient,
}

pub type Packet = (Option<uinf>, Vec<u8>);

impl Default for SSRPConfig {
    fn default() -> Self {
        SSRPConfig { p: NIST_P.clone(), g: uinf::from_u64(2).unwrap(), salt: rand!(16) }
    }
}

impl SSRPConfig {
    pub fn new(p: uinf, g: uinf, salt: Vec<u8>) -> Self {
        SSRPConfig { p, g, salt }
    }
}

impl SSRPClient {
    fn new(config: &SSRPConfig, password: &[u8], email: &[u8]) -> Self {
        SSRPClient {
            config: config.clone(),
            password: password.to_vec(),
            email: email.to_vec(),
            private_key: uinf::from_bytes_be(&rand!(4)),
            token: None,
        }
    }

    pub fn public_key(&self) -> uinf {
        let p = &self.config.p;
        let g = &self.config.g;
        g.modpow(&self.private_key, p)
    }

    pub fn compute(&self, uvec: &[u8], server_pub: uinf) -> Vec<u8> {
        let p = &self.config.p;
        let a = &self.private_key;

        let x = uinf::from_bytes_be(&sha1_mac(&self.config.salt, &self.password));
        let u = uinf::from_bytes_be(uvec); // the 128-bit random number from server 

        // S = B ** (a + ux) % n
        let s = server_pub.modpow(&(a + &(u * x)), p);
        s.to_bytes_be()
    }

    pub fn response(&self, u: &[u8], server_pub: uinf) -> Vec<u8> {
        sha1(&self.compute(u, server_pub))
    }
}

impl SSRPServer {
    fn new(config: &SSRPConfig, password: &[u8]) -> Self {
        let x = uinf::from_bytes_be(&sha1_mac(&config.salt, password));
        SSRPServer {
            config: config.clone(),
            verifier: config.g.modpow(&x, &config.p),
            private_key: uinf::from_bytes_be(&rand!(4)),
            token: None,
        }
    }

    pub fn public_key(&self) -> uinf {
        //  B= g**b % N
        let p = &self.config.p;
        let g = &self.config.g;
        g.modpow(&self.private_key, p)
    }

    pub fn challenge(&self, uvec: &[u8], client_pub: uinf) -> Vec<u8> {
        let p = &self.config.p;
        let b = &self.private_key;
        let v = &self.verifier;
        let u = uinf::from_bytes_be(uvec);

        // S = (A * v ** u)**b % n
        let s = (client_pub * v.modpow(&u, p)).modpow(b, p);
        sha1(&s.to_bytes_be())
    }

    pub fn check(&self, token: &[u8]) -> bool {
        token == self.token.clone().unwrap()
    }
}

impl SSRPInstance {
    pub fn init(email: &[u8], password: &[u8]) -> Self {
        let config = SSRPConfig::default();
        SSRPInstance {
            config,
            status: SSRPStatus::ServerInit,
            email: email.to_vec(),
            password: password.to_vec(),
        }
    }

    pub fn client(&self) -> SSRPClient {
        SSRPClient::new(&self.config, &self.password, &self.email)
    }

    pub fn server(&self) -> SSRPServer {
        SSRPServer::new(&self.config, &self.password)
    }

    pub fn handle(
        &mut self,
        client: &mut SSRPClient,
        server: &mut SSRPServer,
        wire: SSRPWire,
        data: Packet,
    ) -> SSRPStatus {
        match (&self.status, &wire) {
            (SSRPStatus::ServerInit, SSRPWire::ClientToServer) => match data {
                (Some(_), _) => {
                    self.status = SSRPStatus::ServerReady;
                    self.status.clone()
                }
                _ => panic!("Invalid packet"),
            },
            (SSRPStatus::ServerReady, SSRPWire::ServerToClient) => match data {
                (Some(server_pub), u) => {
                    self.status = SSRPStatus::ClientReady;
                    server.token = Some(server.challenge(&u, client.public_key()));
                    client.token = Some(client.response(&u, server_pub));
                    self.status.clone()
                }
                _ => panic!("Invalid packet"),
            },
            (SSRPStatus::ClientReady, SSRPWire::ClientToServer) => match data {
                (None, token) => {
                    if server.check(&token) {
                        self.status = SSRPStatus::Success;
                    } else {
                        self.status = SSRPStatus::Unauthorized;
                    }
                    self.status.clone()
                }
                _ => panic!("Invalid packet"),
            },
            _ => self.status.clone(),
        }
    }
}

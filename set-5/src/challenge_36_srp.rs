use super::challenge_33_dh::*;
use num_traits::FromPrimitive;
use rand::Rng;
use set_2::rand;
use set_4::challenge_28_sha1_mac::{sha1, sha1_mac};

#[derive(Clone)]
pub struct SRPConfig {
    p: uinf,
    g: uinf,
    k: uinf,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SRPStatus {
    ServerInit,
    ServerReady,
    ClientReady,
    Success,
    Unauthorized,
}

pub struct SRPServer {
    config: SRPConfig,
    verifier: uinf,
    pub salt: Vec<u8>,
    private_key: uinf,
    token: Option<Vec<u8>>,
}

pub struct SRPClient {
    pub email: Vec<u8>,
    pub token: Option<Vec<u8>>,
    config: SRPConfig,
    password: Vec<u8>,
    private_key: uinf,
}

pub struct SRPInstance {
    config: SRPConfig,
    status: SRPStatus,
    email: Vec<u8>,
    password: Vec<u8>,
}

pub enum SRPWire {
    ClientToServer,
    ServerToClient,
}

pub type Packet = (Option<uinf>, Vec<u8>);

impl Default for SRPConfig {
    fn default() -> Self {
        SRPConfig {
            p: NIST_P.clone(),
            g: uinf::from_u64(2).unwrap(),
            k: uinf::from_u64(3).unwrap(),
        }
    }
}

impl SRPClient {
    fn new(config: &SRPConfig, password: &[u8], email: &[u8]) -> Self {
        SRPClient {
            config: config.clone(),
            password: password.to_vec(),
            email: email.to_vec(),
            private_key: uinf::from_bytes_be(&rand!(4)),
            token: None,
        }
    }

    pub fn public_key(&self) -> uinf {
        mod_exp(self.config.p.clone(), self.config.g.clone(), self.private_key.clone())
    }

    pub fn compute(&self, salt: &[u8], server_pub: uinf) -> Vec<u8> {
        let g = &self.config.g;
        let p = &self.config.p;
        let k = &self.config.k;
        let a = &self.private_key;
        let mut uvec = self.public_key().to_bytes_be();
        uvec.append(&mut server_pub.to_bytes_be());
        let u = uinf::from_bytes_be(&uvec);
        let x = uinf::from_bytes_be(&sha1_mac(salt, &self.password));
        // S = (B - k * g**x)**(a + u * x) % N
        let s = (server_pub + p - (k * g.modpow(&x, p) % p)).modpow(&(a + u * x), p);
        s.to_bytes_be()
    }

    pub fn response(&self, salt: &[u8], server_pub: uinf) -> Vec<u8> {
        sha1(&self.compute(salt, server_pub))
    }
}

impl SRPServer {
    fn new(config: &SRPConfig, password: &[u8]) -> Self {
        let salt = rand!(1);
        let x = uinf::from_bytes_be(&sha1_mac(&salt, password));
        SRPServer {
            config: config.clone(),
            salt,
            verifier: config.g.modpow(&x, &config.p),
            private_key: uinf::from_bytes_be(&rand!(4)),
            token: None,
        }
    }

    pub fn public_key(&self) -> uinf {
        //  B=kv + g**b % N
        let p = &self.config.p;
        let g = &self.config.g;
        let v = &self.verifier;
        let k = &self.config.k;
        (k * v + g.modpow(&self.private_key, p)) % p
    }

    pub fn challenge(&self, client_pub: uinf) -> Vec<u8> {
        let p = &self.config.p;
        let b = &self.private_key;
        let v = &self.verifier;
        let mut uvec = client_pub.to_bytes_be();
        uvec.append(&mut self.public_key().to_bytes_be());
        let u = uinf::from_bytes_be(&uvec);

        // S = (A * v**u) ** b % N
        let s = (client_pub * v.modpow(&u, p)).modpow(b, p);
        sha1(&s.to_bytes_be())
    }

    pub fn check(&self, token: &[u8]) -> bool {
        token == self.token.clone().unwrap()
    }
}

impl SRPInstance {
    pub fn init(email: &[u8], password: &[u8]) -> Self {
        let config = SRPConfig::default();
        SRPInstance {
            config,
            status: SRPStatus::ServerInit,
            email: email.to_vec(),
            password: password.to_vec(),
        }
    }

    pub fn client(&self) -> SRPClient {
        SRPClient::new(&self.config, &self.password, &self.email)
    }

    pub fn server(&self) -> SRPServer {
        SRPServer::new(&self.config, &self.password)
    }

    pub fn handle(
        &mut self,
        client: &mut SRPClient,
        server: &mut SRPServer,
        wire: SRPWire,
        data: Packet,
    ) -> SRPStatus {
        match (&self.status, &wire) {
            (SRPStatus::ServerInit, SRPWire::ClientToServer) => match data {
                (Some(client_pub), _) => {
                    self.status = SRPStatus::ServerReady;
                    server.token = Some(server.challenge(client_pub));
                    self.status.clone()
                }
                _ => panic!("Invalid packet"),
            },
            (SRPStatus::ServerReady, SRPWire::ServerToClient) => match data {
                (Some(server_pub), salt) => {
                    self.status = SRPStatus::ClientReady;
                    client.token = Some(client.response(&salt, server_pub));
                    self.status.clone()
                }
                _ => panic!("Invalid packet"),
            },
            (SRPStatus::ClientReady, SRPWire::ClientToServer) => match data {
                (None, token) => {
                    if server.check(&token) {
                        self.status = SRPStatus::Success;
                    } else {
                        self.status = SRPStatus::Unauthorized;
                    }
                    self.status.clone()
                }
                _ => panic!("Invalid packet"),
            },
            _ => self.status.clone(),
        }
    }
}

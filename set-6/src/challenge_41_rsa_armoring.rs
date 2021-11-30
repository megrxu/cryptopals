use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::{RsaPrivateKey, RsaPublicKey, RSA};

#[derive(Clone, Debug)]
pub struct RsaInstance {
    pub pubkey: RsaPublicKey,
    pub privkey: RsaPrivateKey,
    history: Vec<Box<[u8]>>,
    pub check_duplicate: bool,
}

#[derive(Clone, Debug)]
pub enum RsaInstanceError {
    DuplicateMessage,
}

pub struct RsaConfig {
    pub bits: u64,
    pub e: u64,
}

/// ```
/// use set_6::challenge_41_rsa_armoring::*;
///
/// let mut instance = RsaInstance::default();
///
/// let m = b"hello world";
/// let c = instance.encrypt(m);
/// assert!(c.is_ok());
///
/// let c = instance.encrypt(m);
/// assert!(c.is_err());
/// ```
impl RsaInstance {
    pub fn new(config: Option<RsaConfig>, check_duplicate: bool) -> Self {
        let config = config.unwrap_or(RsaConfig { e: 3, bits: 64 });
        let (privkey, pubkey) = RSA::keygen(config.e, config.bits);
        RsaInstance { pubkey, privkey, history: Vec::new(), check_duplicate }
    }

    fn processed(&mut self, m: &[u8]) -> bool {
        let hash = sha1(m).into_boxed_slice();
        if self.history.contains(&hash) {
            true
        } else {
            self.history.push(hash);
            false
        }
    }

    pub fn encrypt(&mut self, m: &[u8]) -> Result<Vec<u8>, RsaInstanceError> {
        if !self.check_duplicate || !self.processed(m) {
            Ok(self.pubkey.raw_encrypt(&uinf::from_bytes_be(m)).to_bytes_be())
        } else {
            Err(RsaInstanceError::DuplicateMessage)
        }
    }

    pub fn decrypt(&mut self, c: &[u8]) -> Result<Vec<u8>, RsaInstanceError> {
        if !self.check_duplicate || !self.processed(c) {
            Ok(self.privkey.raw_decrypt(&uinf::from_bytes_be(c)).to_bytes_be())
        } else {
            Err(RsaInstanceError::DuplicateMessage)
        }
    }
}

impl Default for RsaInstance {
    fn default() -> Self {
        Self::new(None, true)
    }
}

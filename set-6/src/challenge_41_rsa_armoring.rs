use set_4::challenge_28_sha1_mac::sha1;
use set_5::challenge_33_dh::uinf;
use set_5::challenge_39_rsa::{RsaPrivateKey, RsaPublicKey, RSA};

#[derive(Clone, Debug)]
pub struct RsaSimpleInstance {
    pub pubkey: RsaPublicKey,
    privkey: RsaPrivateKey,
    history: Vec<Box<[u8]>>,
}

#[derive(Clone, Debug)]
pub enum RsaSimpleInstanceError {
    DuplicateMessage,
}

/// ```
/// use set_6::challenge_41_rsa_armoring::*;
///
/// let mut instance = RsaSimpleInstance::new();
///
/// let m = b"hello world";
/// let c = instance.encrypt(m);
/// assert!(c.is_ok());
///
/// let c = instance.encrypt(m);
/// assert!(c.is_err());
/// ```
impl RsaSimpleInstance {
    pub fn new() -> Self {
        let (privkey, pubkey) = RSA::keygen(3, 64);
        RsaSimpleInstance { pubkey, privkey, history: Vec::new() }
    }

    pub fn encrypt(&mut self, m: &[u8]) -> Result<Vec<u8>, RsaSimpleInstanceError> {
        let hash = sha1(m).into_boxed_slice();
        if self.history.contains(&hash) {
            Err(RsaSimpleInstanceError::DuplicateMessage)
        } else {
            self.history.push(hash);
            Ok(RSA::encrypt(&self.pubkey, &uinf::from_bytes_be(m)).to_bytes_be())
        }
    }

    pub fn decrypt(&mut self, c: &[u8]) -> Result<Vec<u8>, RsaSimpleInstanceError> {
        let hash = sha1(c).into_boxed_slice();
        if self.history.contains(&hash) {
            Err(RsaSimpleInstanceError::DuplicateMessage)
        } else {
            self.history.push(hash);
            Ok(RSA::decrypt(&self.privkey, &uinf::from_bytes_be(c)).to_bytes_be())
        }
    }
}

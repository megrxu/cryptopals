use super::challenge_41_rsa_armoring::*;
use set_4::challenge_28_sha1_mac::sha1;

#[derive(Clone, Debug)]
pub struct RsaPKCS1Signature {
    pub rsa: RsaInstance,
}

#[derive(Clone, Debug)]
pub enum RsaPKCS1SignatureError {
    MessageTooLong,
    Verification,
    Internal(RsaInstanceError),
}

#[allow(clippy::new_without_default)]
impl RsaPKCS1Signature {
    pub fn new() -> Self {
        RsaPKCS1Signature { rsa: RsaInstance::new(Some(RsaConfig { e: 3, bits: 256 }), false) }
    }

    pub fn sign(&mut self, m: &[u8]) -> Result<Vec<u8>, RsaPKCS1SignatureError> {
        let k: usize = (self.rsa.privkey.bits() / 8) as usize;
        let hash_len = 20;
        let t_len = m.len() + hash_len;

        if k < t_len + 11 {
            return Err(RsaPKCS1SignatureError::MessageTooLong);
        }

        let mut em = vec![0xff; k];
        em[0] = 0x00;
        em[1] = 0x01;
        em[k - t_len - 1] = 0x00;
        em[k - t_len..k - hash_len].copy_from_slice(m);
        em[k - hash_len..k].copy_from_slice(&sha1(m));

        println!("em: {:?}", em);
        match self.rsa.decrypt(&em) {
            Ok(m) => Ok(m),
            Err(e) => Err(RsaPKCS1SignatureError::Internal(e)),
        }
    }

    pub fn verify(
        &mut self,
        sig: &[u8],
        m: &[u8],
        weak: bool,
    ) -> Result<(), RsaPKCS1SignatureError> {
        let res = self.rsa.encrypt(sig);
        if res.is_err() {
            return Err(RsaPKCS1SignatureError::Verification);
        }

        // Should be constant time comparison, but I'am lazy
        let em = res.unwrap();

        // The first zero is omitted.
        let mut ok = em[0] == 0x01;
        let mut i = 1;
        loop {
            if em[i] == 0x00 {
                break;
            } else if em[i] != 0xff {
                return Err(RsaPKCS1SignatureError::Verification);
            }
            i += 1;
        }
        ok &= &em[i + 1..i + m.len() + 1] == m;
        if !weak {
            // check the hash
            ok &= em[i + m.len() + 1..] == sha1(m);
        }
        if ok { Ok(()) } else { Err(RsaPKCS1SignatureError::Verification) }
    }
}

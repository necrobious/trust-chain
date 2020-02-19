use crate::v3::PUBLICKEYBYTES;
use core::fmt;
use core::cmp;

#[derive(Copy,Clone)]
pub struct PublicKey([u8;PUBLICKEYBYTES]);

impl PublicKey {
    pub fn from_slice(b:&[u8]) -> Option<PublicKey> {
        if b.len() != PUBLICKEYBYTES { return None }

        let mut key = PublicKey([0u8; PUBLICKEYBYTES]);
        key.0.copy_from_slice(b);
        Some(key)
    }
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        let mut acc = 0;
        for (l,r) in self.0.iter().zip(other.0.iter()) {acc ^= *l ^ *r;}
        acc == 0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex_str = self.0.iter().map(|b| format!("{:02x?}",b)).collect::<String>();
        write!(f,"PublicKey({})",hex_str)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

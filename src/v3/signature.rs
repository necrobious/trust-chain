use crate::v3::SIGNATUREBYTES;
use core::fmt;
use core::cmp;

#[derive(Copy,Clone)]
pub struct Signature([u8;SIGNATUREBYTES]);

impl Signature {
    pub fn from_slice(b:&[u8]) -> Option<Signature> {
        if b.len() != SIGNATUREBYTES { return None }

        let mut sig = Signature([0u8;SIGNATUREBYTES]);
        sig.0.copy_from_slice(b);
        Some(sig)
    }
}

impl cmp::PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        let mut acc = 0;
        for (l,r) in self.0.iter().zip(other.0.iter()) {acc ^= *l ^ *r;}
        acc == 0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex_str = self.0.iter().map(|b| format!("{:02x?}",b)).collect::<String>();
        write!(f,"Signature({})",hex_str)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl From<ring::signature::Signature> for Signature {
    fn from (ring_sig:ring::signature::Signature) -> Self {
        let mut sig = Signature([0u8;SIGNATUREBYTES]);
        sig.0.copy_from_slice(ring_sig.as_ref());
        sig
    }
}

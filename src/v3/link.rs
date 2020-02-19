use crate::v3::key::PublicKey;
use crate::v3::signature::Signature;
use crate::v3::expiry::{Expiry,NotBefore,NotAfter};

#[derive(Copy,Clone,Debug,PartialEq)]
pub struct Root {
    key: PublicKey
}

#[derive(Copy,Clone,Debug,PartialEq)]
pub struct Link {
    key: PublicKey,
    sig: Signature,
    exp: Expiry,
}

impl Link {
    pub fn new (key: PublicKey, sig: Signature, exp:Expiry) -> Link {
        Link {key, sig, exp}
    }
}

impl Root {
    pub fn new (key: PublicKey) -> Root {
        Root {key}
    }
}

pub trait Key {
    fn key       (&self) -> PublicKey;
}

pub trait Signed {
    fn sig (&self) -> Signature;
}

pub trait Expire {
    fn exp (&self) -> Expiry;
}

pub trait TrustLink {
    fn key       (&self) -> PublicKey;
    fn signature (&self) -> Option<Signature>;
    fn is_root   (&self) -> bool;
}

impl Key for Root {
    fn key       (&self) -> PublicKey {self.key}
}

impl Key for Link {
    fn key       (&self) -> PublicKey {self.key}
}

impl Signed for Link {
    fn sig (&self) -> Signature {self.sig}
}

impl Expire for Link {
    fn exp (&self) -> Expiry {self.exp}
}

impl TrustLink for Root {
    fn key       (&self) -> PublicKey {self.key}
    fn signature (&self) -> Option<Signature> {None}
    fn is_root   (&self) -> bool {true}
}

impl TrustLink for Link {
    fn key       (&self) -> PublicKey {self.key}
    fn signature (&self) -> Option<Signature> {Some(self.sig)}
    fn is_root   (&self) -> bool {false}
}


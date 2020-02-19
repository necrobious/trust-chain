use crate::v3::key::PublicKey;
use crate::v3::signature::Signature;

#[derive(Copy,Clone,Debug,PartialEq)]
pub struct Root {
    key: PublicKey
}

#[derive(Copy,Clone,Debug,PartialEq)]
pub struct Link {
    key: PublicKey,
    sig: Signature,
}

impl Link {
    pub fn new (key: PublicKey, sig: Signature) -> Link {
        Link {key, sig}
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


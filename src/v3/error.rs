#[derive(Copy,Clone,Debug,PartialEq)]
pub enum TrustError {
    NoRootKeyTrust,
    InvalidSignature,
    InvalidExpiry,
    MaxChainLengthExceeded,
    InvalidTrustChain
}



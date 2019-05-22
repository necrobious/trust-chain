#[derive(Clone,Debug)]
pub enum TrustError {
    NoRootKeyTrust,
    InvalidSignature,
    MaxChainLengthExceeded,
}



#[derive(Debug)]
pub enum TrustError {
    NoRootKeyTrust,
    InvalidSignature,
    MaxChainLengthExceeded,
}



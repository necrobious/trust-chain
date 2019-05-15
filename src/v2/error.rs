#[derive(Debug)]
pub enum TrustError {
    NoRootKeyTrust,
    InvalidRootKey,
    InvalidEndKey,
    InvalidIntermediateKey,
    InvalidSignature,
    MaxChainLengthExceeded,
}



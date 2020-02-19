pub const PUBLICKEYBYTES : usize = 32;
pub const SIGNATUREBYTES : usize = 64;

pub const MAXCHAINLINKS  : u8 =  5;

// ------------------------------[   T,   C,  v.    3]
pub const TC_V3_HEADER: [u8;4] = [0x54,0x43,0x00,0x03];

mod error;
mod key;
mod signature;
mod link;
mod keystore;
mod trust_chain;
mod parsers;

pub use error::*;
pub use key::*;
pub use link::*;
pub use signature::*;
pub use keystore::*;
pub use trust_chain::*;
pub use parsers::*;


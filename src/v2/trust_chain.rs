use sodiumoxide::crypto::sign::ed25519::{self, PublicKey,Signature};
use super::error::TrustError;
use std::fmt;

pub const PUBLICKEYBYTES:usize = 32;
pub const SIGNATUREBYTES:usize = 64;
pub const MAXCHAINLINKS:usize = 5;

//--- The Trust anchor in the system. The Root Keys we trust implicitly
pub trait RootKeysStore {
    fn contains_root_key(&self, candidate: &[u8]) -> bool;
}

impl RootKeysStore for Vec<PublicKey> {
    fn contains_root_key(&self, candidate: &[u8]) -> bool {
        for key in self.iter() {
            if key.0 == candidate { return true; }
        }
        false
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum TrustChain {
    RootOnlyChain {
        root_key:PublicKey
    },
    TwoLinkChain {
        root_key:PublicKey,
        end_key: PublicKey,
        root_sig_over_end_key: Signature
    },
    ThreeLinkChain {
        root_key: PublicKey,
        intermediate_key: PublicKey,
        end_key:  PublicKey,
        root_sig_over_intermediate_key: Signature,
        intermediate_sig_over_end_key: Signature,
    },
    FourLinkChain {
        root_key: PublicKey,
        intermediate1_key: PublicKey,
        intermediate2_key: PublicKey,
        end_key:  PublicKey,
        root_sig_over_intermediate1_key: Signature,
        intermediate1_sig_over_intermediate2_key: Signature,
        intermediate2_sig_over_end_key: Signature,
    },
    FiveLinkChain {
        root_key: PublicKey,
        intermediate1_key: PublicKey,
        intermediate2_key: PublicKey,
        intermediate3_key: PublicKey,
        end_key:  PublicKey,
        root_sig_over_intermediate1_key: Signature,
        intermediate1_sig_over_intermediate2_key: Signature,
        intermediate2_sig_over_intermediate3_key: Signature,
        intermediate3_sig_over_end_key: Signature,
    }

}

impl fmt::Display for TrustChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:x?}, )", self.as_bytes(), )
    }
}

impl TrustChain {
    pub fn root_only_chain(root_key: PublicKey, root_key_store:Box<RootKeysStore>) -> Result<TrustChain,TrustError>  {
        if !root_key_store.contains_root_key(&root_key.0) {
            return Err(TrustError::NoRootKeyTrust)
        }
        Ok(TrustChain::RootOnlyChain {root_key: root_key})
    }

    pub fn two_link_chain(
        root_key: PublicKey,
        end_key: PublicKey,
        root_sig_over_end_key: Signature,
        root_key_store:Box<RootKeysStore>) -> Result<TrustChain,TrustError> {
        TrustChain::root_only_chain(root_key, root_key_store)
            .and_then(|chain| chain.append(end_key, root_sig_over_end_key))
    }

    pub fn three_link_chain(
        root_key: PublicKey,
        intermediate_key: PublicKey,
        end_key: PublicKey,
        root_sig_over_intermediate_key: Signature,
        intermediate_sig_over_end_key: Signature,
        root_key_store:Box<RootKeysStore>) -> Result<TrustChain,TrustError> {
        TrustChain::root_only_chain(root_key, root_key_store)
            .and_then(|chain| chain.append(intermediate_key, root_sig_over_intermediate_key))
            .and_then(|chain| chain.append(end_key, intermediate_sig_over_end_key))
    }

    pub fn four_link_chain(
        root_key: PublicKey,
        intermediate1_key: PublicKey,
        intermediate2_key: PublicKey,
        end_key: PublicKey,
        root_sig_over_intermediate1_key: Signature,
        intermediate1_sig_over_intermediate2_key: Signature,
        intermediate2_sig_over_end_key: Signature,
        root_key_store:Box<RootKeysStore>) -> Result<TrustChain,TrustError> {
        TrustChain::root_only_chain(root_key, root_key_store)
            .and_then(|chain| chain.append(intermediate1_key, root_sig_over_intermediate1_key))
            .and_then(|chain| chain.append(intermediate2_key, intermediate1_sig_over_intermediate2_key))
            .and_then(|chain| chain.append(end_key, intermediate2_sig_over_end_key))
    }

    pub fn five_link_chain(
        root_key: PublicKey,
        intermediate1_key: PublicKey,
        intermediate2_key: PublicKey,
        intermediate3_key: PublicKey,
        end_key: PublicKey,
        root_sig_over_intermediate1_key: Signature,
        intermediate1_sig_over_intermediate2_key: Signature,
        intermediate2_sig_over_intermediate3_key: Signature,
        intermediate3_sig_over_end_key: Signature,
        root_key_store:Box<RootKeysStore>) -> Result<TrustChain,TrustError> {
        TrustChain::root_only_chain(root_key, root_key_store)
            .and_then(|chain| chain.append(intermediate1_key, root_sig_over_intermediate1_key))
            .and_then(|chain| chain.append(intermediate2_key, intermediate1_sig_over_intermediate2_key))
            .and_then(|chain| chain.append(intermediate3_key, intermediate2_sig_over_intermediate3_key))
            .and_then(|chain| chain.append(end_key, intermediate3_sig_over_end_key))
    }


    pub fn append(self, new_end_key: PublicKey, new_end_sig:Signature) -> Result<TrustChain, TrustError> {
        match self {
            TrustChain::RootOnlyChain{
                root_key,
            } => {
                if !ed25519::verify_detached(
                    &new_end_sig,
                    &new_end_key.0,
                    &root_key
                ) {
                    Err(TrustError::InvalidSignature)
                } else {
                    Ok(TrustChain::TwoLinkChain {
                        root_key: root_key,
                        end_key: new_end_key,
                        root_sig_over_end_key:new_end_sig,
                    })
                }
            },
            TrustChain::TwoLinkChain{
                root_key,
                end_key,
                root_sig_over_end_key,
            } => {
                if !ed25519::verify_detached(
                    &new_end_sig,
                    &new_end_key.0,
                    &end_key
                ) {
                    Err(TrustError::InvalidSignature)
                } else {
                    Ok(TrustChain::ThreeLinkChain {
                        root_key: root_key,
                        intermediate_key: end_key,
                        end_key: new_end_key,
                        root_sig_over_intermediate_key: root_sig_over_end_key,
                        intermediate_sig_over_end_key: new_end_sig,
                    })
                }
            },
            TrustChain::ThreeLinkChain{
                root_key,
                intermediate_key,
                end_key,
                root_sig_over_intermediate_key,
                intermediate_sig_over_end_key,
            } => {
                if !ed25519::verify_detached(
                    &new_end_sig,
                    &new_end_key.0,
                    &end_key
                ) {
                    Err(TrustError::InvalidSignature)
                } else {
                    Ok(TrustChain::FourLinkChain {
                        root_key: root_key,
                        intermediate1_key: intermediate_key,
                        intermediate2_key: end_key,
                        end_key: new_end_key,
                        root_sig_over_intermediate1_key: root_sig_over_intermediate_key,
                        intermediate1_sig_over_intermediate2_key: intermediate_sig_over_end_key,
                        intermediate2_sig_over_end_key: new_end_sig,
                    })
                }
            },
            TrustChain::FourLinkChain{
                root_key,
                intermediate1_key,
                intermediate2_key,
                end_key,
                root_sig_over_intermediate1_key,
                intermediate1_sig_over_intermediate2_key,
                intermediate2_sig_over_end_key,
            } => {
                if !ed25519::verify_detached(
                    &new_end_sig,
                    &new_end_key.0,
                    &end_key
                ) {
                    Err(TrustError::InvalidSignature)
                } else {
                    Ok(TrustChain::FiveLinkChain {
                        root_key: root_key,
                        intermediate1_key: intermediate1_key,
                        intermediate2_key: intermediate2_key,
                        intermediate3_key: end_key,
                        end_key: new_end_key,
                        root_sig_over_intermediate1_key: root_sig_over_intermediate1_key,
                        intermediate1_sig_over_intermediate2_key: intermediate1_sig_over_intermediate2_key,
                        intermediate2_sig_over_intermediate3_key: intermediate2_sig_over_end_key,
                        intermediate3_sig_over_end_key: new_end_sig,
                    })
                }
            },
            TrustChain::FiveLinkChain{..} => {
                Err(TrustError::MaxChainLengthExceeded)
            }
        }
    }

    pub fn end_key(&self) -> PublicKey {
        match self {
            TrustChain::RootOnlyChain{root_key:key, ..} => key.clone(),
            TrustChain::TwoLinkChain{end_key:key,   ..} => key.clone(),
            TrustChain::ThreeLinkChain{end_key:key, ..} => key.clone(),
            TrustChain::FourLinkChain{end_key:key,  ..} => key.clone(),
            TrustChain::FiveLinkChain{end_key:key,  ..} => key.clone(),
        }
    }

    pub fn verify_data (&self, untrusted_signature: &Signature, untrusted_data: &[u8]) -> Result<(),TrustError> {
        if !ed25519::verify_detached(untrusted_signature, untrusted_data, &self.end_key()) {
            return Err(TrustError::InvalidSignature)
        }
        Ok(())
    }

    pub fn as_bytes (&self) -> Vec<u8> {
        let mut header:Vec<u8> = vec!(0x54,0x43,0x00,0x02);
        match self {
            TrustChain::RootOnlyChain {
                root_key
            } => {
                let mut v:Vec<u8> = Vec::with_capacity(37);
                v.append(&mut header); // 4 bytes
                v.append(&mut root_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut vec!(0x00)); // 1 byte
                v
            },
            TrustChain::TwoLinkChain {
                root_key,
                end_key,
                root_sig_over_end_key,
            } => {
                let mut v:Vec<u8> = Vec::with_capacity(133);
                v.append(&mut header); // 4 bytes
                v.append(&mut root_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut vec!(0x01)); // 1 byte
                v.append(&mut end_key.0.clone().to_vec());  // 32 bytes
                v.append(&mut root_sig_over_end_key.0.clone().to_vec());  // 64 bytes
                v
            },
            TrustChain::ThreeLinkChain {
                root_key,
                intermediate_key,
                end_key,
                root_sig_over_intermediate_key,
                intermediate_sig_over_end_key,
            } => {
                let mut v:Vec<u8> = Vec::with_capacity(229);
                v.append(&mut header); // 4 bytes
                v.append(&mut root_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut vec!(0x02)); // 1 byte
                v.append(&mut intermediate_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut root_sig_over_intermediate_key.0.clone().to_vec());  // 64 bytes
                v.append(&mut end_key.0.clone().to_vec());  // 32 bytes
                v.append(&mut intermediate_sig_over_end_key.0.clone().to_vec());  // 64 bytes
                v
            },
            TrustChain::FourLinkChain {
                root_key,
                intermediate1_key,
                intermediate2_key,
                end_key,
                root_sig_over_intermediate1_key,
                intermediate1_sig_over_intermediate2_key,
                intermediate2_sig_over_end_key,
            } => {
                let mut v:Vec<u8> = Vec::with_capacity(229);
                v.append(&mut header); // 4 bytes
                v.append(&mut root_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut vec!(0x03)); // 1 byte chain length
                v.append(&mut intermediate1_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut root_sig_over_intermediate1_key.0.clone().to_vec());  // 64 bytes
                v.append(&mut intermediate2_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut intermediate1_sig_over_intermediate2_key.0.clone().to_vec());  // 64 bytes
                v.append(&mut end_key.0.clone().to_vec());  // 32 bytes
                v.append(&mut intermediate2_sig_over_end_key.0.clone().to_vec());  // 64 bytes
                v
            },
            TrustChain::FiveLinkChain {
                root_key,
                intermediate1_key,
                intermediate2_key,
                intermediate3_key,
                end_key,
                root_sig_over_intermediate1_key,
                intermediate1_sig_over_intermediate2_key,
                intermediate2_sig_over_intermediate3_key,
                intermediate3_sig_over_end_key,
            } => {
                let mut v:Vec<u8> = Vec::with_capacity(229);
                v.append(&mut header); // 4 bytes
                v.append(&mut root_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut vec!(0x04)); // 1 byte chain length
                v.append(&mut intermediate1_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut root_sig_over_intermediate1_key.0.clone().to_vec());  // 64 bytes
                v.append(&mut intermediate2_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut intermediate1_sig_over_intermediate2_key.0.clone().to_vec());  // 64 bytes
                v.append(&mut intermediate3_key.0.clone().to_vec()); // 32 bytes
                v.append(&mut intermediate2_sig_over_intermediate3_key.0.clone().to_vec());  // 64 bytes
                v.append(&mut end_key.0.clone().to_vec());  // 32 bytes
                v.append(&mut intermediate3_sig_over_end_key.0.clone().to_vec());  // 64 bytes
                v
            }

        }
    }
}


#[test]
fn root_only_chain_construction () {
    let (pkey, _skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(pkey));
    let chain = TrustChain::root_only_chain(pkey, root_key_store);
    assert!(chain.is_ok());
}

#[test]
fn two_link_chain_construction () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (end_pkey, _end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let sig = ed25519::sign_detached(&end_pkey.0, &root_skey);

    let chain = TrustChain::two_link_chain(
        root_pkey,
        end_pkey,
        sig,
        root_key_store
    );
    assert!(chain.is_ok());
}

#[test]
fn three_link_chain_construction () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (intr_pkey, intr_skey) = ed25519::gen_keypair();
    let (end_pkey, _end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&intr_pkey.0, &root_skey);
    let intr_sig = ed25519::sign_detached(&end_pkey.0, &intr_skey);

    let chain = TrustChain::three_link_chain(
        root_pkey,
        intr_pkey,
        end_pkey,
        root_sig,
        intr_sig,
        root_key_store
    );
    assert!(chain.is_ok());
}

#[test]
fn four_link_chain_construction () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (intr1_pkey, intr1_skey) = ed25519::gen_keypair();
    let (intr2_pkey, intr2_skey) = ed25519::gen_keypair();
    let (end_pkey, _end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&intr1_pkey.0, &root_skey);
    let intr1_sig = ed25519::sign_detached(&intr2_pkey.0, &intr1_skey);
    let intr2_sig = ed25519::sign_detached(&end_pkey.0, &intr2_skey);

    let chain = TrustChain::four_link_chain(
        root_pkey,
        intr1_pkey,
        intr2_pkey,
        end_pkey,
        root_sig,
        intr1_sig,
        intr2_sig,
        root_key_store
    );
    assert!(chain.is_ok());
}

#[test]
fn five_link_chain_construction () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (intr1_pkey, intr1_skey) = ed25519::gen_keypair();
    let (intr2_pkey, intr2_skey) = ed25519::gen_keypair();
    let (intr3_pkey, intr3_skey) = ed25519::gen_keypair();
    let (end_pkey, _end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&intr1_pkey.0, &root_skey);
    let intr1_sig = ed25519::sign_detached(&intr2_pkey.0, &intr1_skey);
    let intr2_sig = ed25519::sign_detached(&intr3_pkey.0, &intr2_skey);
    let intr3_sig = ed25519::sign_detached(&end_pkey.0, &intr3_skey);

    let chain = TrustChain::five_link_chain(
        root_pkey,
        intr1_pkey,
        intr2_pkey,
        intr3_pkey,
        end_pkey,
        root_sig,
        intr1_sig,
        intr2_sig,
        intr3_sig,
        root_key_store
    );
    assert!(chain.is_ok());
}




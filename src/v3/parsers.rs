use crate::trust_chain_v3;
use crate::v3::trust_chain::{TrustChain};
use crate::v3::link::{Root, Link};
use crate::v3::{PUBLICKEYBYTES,MAXCHAINLINKS,TC_V3_HEADER};
use crate::v3::error::TrustError;
use crate::v3::key::PublicKey;
use crate::v3::signature::Signature;
use crate::v3::keystore::RootKeysStore;

use std::io::Read;

#[inline]
fn read_link <R> (input: &mut R) -> Result<Link, TrustError>
where R: Read  {
    let mut buf = [0u8;96];
    let bytes_read = input.read(&mut buf).map_err(|_| TrustError::InvalidTrustChain)?;
    if bytes_read != 96 { return Err(TrustError::InvalidTrustChain) }
    PublicKey::from_slice(&buf[0..PUBLICKEYBYTES])
        .and_then(|key| Signature::from_slice(&buf[PUBLICKEYBYTES..96]).map(|sig| Link::new(key,sig)))
        .ok_or(TrustError::InvalidTrustChain)
}

#[inline]
fn read_root <R> (input: &mut R) -> Result<Root, TrustError>
where R: Read  {
    let mut buf = [0u8;PUBLICKEYBYTES];
    let bytes_read = input.read(&mut buf).map_err(|_| TrustError::InvalidTrustChain)?;
    if bytes_read != PUBLICKEYBYTES { return Err(TrustError::InvalidTrustChain) }
    PublicKey::from_slice(&buf)
        .map(|key| Root::new(key))
        .ok_or(TrustError::InvalidTrustChain)
}

pub fn trust_chain <'ks, R> (input: &mut R, root_keys_store:&'ks (dyn RootKeysStore<'ks> + 'ks)) -> Result<TrustChain,TrustError>
where R: Read  {
    let mut buf = [0u8;5];
    let bytes_read = input.read(&mut buf).map_err(|_| TrustError::InvalidTrustChain)?;

    if bytes_read != 5 {
        return Err(TrustError::InvalidTrustChain)
    }

    if buf[0..4] != TC_V3_HEADER {
        return Err(TrustError::InvalidTrustChain)
    }

    let chain_length = buf[4] ;
    if chain_length > MAXCHAINLINKS {
        return Err(TrustError::MaxChainLengthExceeded)
    }

    if chain_length < 1 {
        return Err(TrustError::InvalidTrustChain)
    }

    match chain_length {
        1 => { trust_chain_v3!(root_keys_store, read_root(input)?) },
        2 => { trust_chain_v3!(root_keys_store, read_root(input)?, read_link(input)?) },
        3 => { trust_chain_v3!(root_keys_store, read_root(input)?, read_link(input)?, read_link(input)?) },
        4 => { trust_chain_v3!(root_keys_store, read_root(input)?, read_link(input)?, read_link(input)?, read_link(input)?) },
        5 => { trust_chain_v3!(root_keys_store, read_root(input)?, read_link(input)?, read_link(input)?, read_link(input)?, read_link(input)?) },
        _ => Err(TrustError::InvalidTrustChain)
    }
}

#[cfg(test)]
mod tests {
    use crate::v3::{PUBLICKEYBYTES,SIGNATUREBYTES};
    use ring::rand::{SystemRandom, SecureRandom};
    use ring::signature;
    use ring::signature::KeyPair;
    use super::*;

    fn gen_keypair(rand: &dyn SecureRandom) -> Option<signature::Ed25519KeyPair> {
        let mut seed = [0u8; PUBLICKEYBYTES];
        rand.fill(&mut seed).ok().and_then(|_| signature::Ed25519KeyPair::from_seed_unchecked(&seed).ok())
    }

    fn assert_arr_elm_eq (lft: &[u8], lft_off:usize, rgt:&[u8], rgt_off:usize, count:usize) {
        let mut i = 0;
        while i < count {
            assert_eq!(lft[i+lft_off], rgt[i+rgt_off]);
            i = i + 1;
        }
    }

    fn assert_key (lft: &[u8], lft_off:usize, rgt:&[u8], rgt_off:usize) {
        assert_arr_elm_eq(lft, lft_off, rgt, rgt_off, PUBLICKEYBYTES)
    }

    fn assert_sig (lft: &[u8], lft_off:usize, rgt:&[u8], rgt_off:usize) {
        assert_arr_elm_eq(lft, lft_off, rgt, rgt_off, SIGNATUREBYTES)
    }

    macro_rules! assert_ok {
        ($res:expr) => {{
            if $res.is_err() {
                assert!(false, format!("{:?}",$res.unwrap_err()));
            }
        }};
    }

    #[test]
    fn root_only_chain_end_to_end_test () {
        let rand           = SystemRandom::new();
        let keypair        = gen_keypair(&rand).unwrap();
        let pkey           = PublicKey::from_slice(keypair.public_key().as_ref());

        assert!(pkey.is_some());

        let root           = pkey.unwrap();
        let root_key_store = vec!(root);
        let chain          = TrustChain::new(&root_key_store, Root::new(root));

        assert_ok!(chain);

        let chain          = chain.unwrap();
        let test_data      = b"test data";
        let sig            = Signature::from(keypair.sign(test_data));
        let verify_res     = chain.verify_data(&sig, test_data);

        assert_ok!(verify_res);

        let cb             = chain.as_bytes();

        assert_eq!(cb[0..4], TC_V3_HEADER);
        assert_eq!(cb[4], 0x01);// chain length
        assert_key(&cb,5, root.as_ref(), 0);// root public key, 32 bytes

        let parsed_chain   = trust_chain(&mut cb.as_slice(), &root_key_store);

        assert_ok!(parsed_chain);

        let parsed_chain   = parsed_chain.unwrap();
        let verify_parsed  = parsed_chain.verify_data(&sig, test_data);

        assert_ok!(verify_parsed);
    }

    #[test]
    fn two_link_chain_end_to_end_test () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root           = PublicKey::from_slice(root_keypair.public_key().as_ref());
        let end            = PublicKey::from_slice(end_keypair.public_key().as_ref());

        assert!(root.is_some());
        assert!(end.is_some());

        let root           = root.unwrap();
        let end            = end.unwrap();
        let root_key_store = vec!(root);
        let root_sig       = Signature::from_slice(root_keypair.sign(end.as_ref()).as_ref());

        assert!(root_sig.is_some());

        let root_sig       = root_sig.unwrap();
        let link1          = Link::new(end, root_sig);
        let chain          = trust_chain_v3!(&root_key_store, Root::new(root), link1);

        assert_ok!(chain);

        let chain          = chain.unwrap();
        let test_data      = b"test data";
        let end_sig        = Signature::from(end_keypair.sign(test_data));
        let verify_res     = chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_res);

        let cb             = chain.as_bytes();

        assert_eq!(cb[0..4], TC_V3_HEADER);
        assert_eq!(cb[4], 0x02);// subsequent chain length
        assert_key(&cb, 5, root.as_ref(), 0);// root public key, 32 bytes
        assert_key(&cb,37, end.as_ref(),  0);
        assert_sig(&cb,69, root_sig.as_ref(),  0);

        let parsed_chain   = trust_chain(&mut cb.as_slice(), &root_key_store);

        assert_ok!(parsed_chain);

        let parsed_chain   = parsed_chain.unwrap();
        let verify_parsed  = parsed_chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_parsed);
    }

    #[test]
    fn three_link_chain_end_to_end_test () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let intr_keypair   = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root           = PublicKey::from_slice(root_keypair.public_key().as_ref());
        let intr           = PublicKey::from_slice(intr_keypair.public_key().as_ref());
        let end            = PublicKey::from_slice(end_keypair.public_key().as_ref());

        assert!(root.is_some());
        assert!(intr.is_some());
        assert!(end.is_some());

        let root           = root.unwrap();
        let intr           = intr.unwrap();
        let end            = end.unwrap();
        let root_key_store = vec!(root);
        let root_sig       = Signature::from_slice(root_keypair.sign(intr.as_ref()).as_ref());
        let intr_sig       = Signature::from_slice(intr_keypair.sign(end.as_ref()).as_ref());

        assert!(root_sig.is_some());
        assert!(intr_sig.is_some());

        let root_sig       = root_sig.unwrap();
        let intr_sig       = intr_sig.unwrap();
        let link1          = Link::new(intr, root_sig);
        let link2          = Link::new(end,  intr_sig);
        let chain          = trust_chain_v3!(&root_key_store, Root::new(root), link1, link2);

        assert_ok!(chain);

        let chain          = chain.unwrap();
        let test_data      = b"test data";
        let end_sig        = Signature::from(end_keypair.sign(test_data));
        let verify_res     = chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_res);

        let cb             = chain.as_bytes();

        assert_eq!(cb[0..4], TC_V3_HEADER);
        assert_eq!(cb[4], 0x03);// subsequent chain length
        assert_key(&cb,  5, root.as_ref(),0);// root public key, 32 bytes
        assert_key(&cb, 37, intr.as_ref(),0);
        assert_sig(&cb, 69, root_sig.as_ref(),0);
        assert_key(&cb,133, end.as_ref(),0);
        assert_sig(&cb,165, intr_sig.as_ref(),0);

        let parsed_chain   = trust_chain(&mut cb.as_slice(), &root_key_store);

        assert_ok!(parsed_chain);

        let parsed_chain   = parsed_chain.unwrap();
        let verify_parsed  = parsed_chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_parsed);
    }

    #[test]
    fn four_link_chain_end_to_end_test () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let intr1_keypair  = gen_keypair(&rand).unwrap();
        let intr2_keypair  = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root           = PublicKey::from_slice(root_keypair.public_key().as_ref());
        let intr1          = PublicKey::from_slice(intr1_keypair.public_key().as_ref());
        let intr2          = PublicKey::from_slice(intr2_keypair.public_key().as_ref());
        let end            = PublicKey::from_slice(end_keypair.public_key().as_ref());

        assert!(root.is_some());
        assert!(intr1.is_some());
        assert!(intr2.is_some());
        assert!(end.is_some());

        let root           = root.unwrap();
        let intr1          = intr1.unwrap();
        let intr2          = intr2.unwrap();
        let end            = end.unwrap();
        let root_key_store = vec!(root);
        let root_sig       = Signature::from_slice(root_keypair.sign(intr1.as_ref()).as_ref());
        let intr1_sig      = Signature::from_slice(intr1_keypair.sign(intr2.as_ref()).as_ref());
        let intr2_sig      = Signature::from_slice(intr2_keypair.sign(end.as_ref()).as_ref());

        assert!(root_sig.is_some());
        assert!(intr1_sig.is_some());
        assert!(intr2_sig.is_some());

        let root_sig       = root_sig.unwrap();
        let intr1_sig      = intr1_sig.unwrap();
        let intr2_sig      = intr2_sig.unwrap();
        let link1          = Link::new(intr1, root_sig);
        let link2          = Link::new(intr2, intr1_sig);
        let link3          = Link::new(end,   intr2_sig);
        let chain          = trust_chain_v3!(&root_key_store, Root::new(root), link1, link2, link3);

        assert_ok!(chain);

        let chain          = chain.unwrap();
        let test_data      = b"test data";
        let end_sig        = Signature::from(end_keypair.sign(test_data));
        let verify_res     = chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_res);

        let cb             = chain.as_bytes();

        assert_eq!(cb[0..4], TC_V3_HEADER);
        assert_eq!(cb[4], 0x04);// subsequent chain length
        assert_key(&cb,  5, root.as_ref(),0);// root public key, 32 bytes
        assert_key(&cb, 37, intr1.as_ref(),0);
        assert_sig(&cb, 69, root_sig.as_ref(),0);
        assert_key(&cb,133, intr2.as_ref(),0);
        assert_sig(&cb,165, intr1_sig.as_ref(),0);
        assert_key(&cb,229, end.as_ref(),0);
        assert_sig(&cb,261, intr2_sig.as_ref(),0);

        let parsed_chain   = trust_chain(&mut cb.as_slice(), &root_key_store);

        assert_ok!(parsed_chain);

        let parsed_chain   = parsed_chain.unwrap();
        let verify_parsed  = parsed_chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_parsed);
    }

    #[test]
    fn five_link_chain_end_to_end_test () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let intr1_keypair  = gen_keypair(&rand).unwrap();
        let intr2_keypair  = gen_keypair(&rand).unwrap();
        let intr3_keypair  = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root           = PublicKey::from_slice(root_keypair.public_key().as_ref());
        let intr1          = PublicKey::from_slice(intr1_keypair.public_key().as_ref());
        let intr2          = PublicKey::from_slice(intr2_keypair.public_key().as_ref());
        let intr3          = PublicKey::from_slice(intr3_keypair.public_key().as_ref());
        let end            = PublicKey::from_slice(end_keypair.public_key().as_ref());

        assert!(root.is_some());
        assert!(intr1.is_some());
        assert!(intr2.is_some());
        assert!(intr3.is_some());
        assert!(end.is_some());

        let root           = root.unwrap();
        let intr1          = intr1.unwrap();
        let intr2          = intr2.unwrap();
        let intr3          = intr3.unwrap();
        let end            = end.unwrap();
        let root_key_store = vec!(root);
        let root_sig       = Signature::from_slice(root_keypair.sign(intr1.as_ref()).as_ref());
        let intr1_sig      = Signature::from_slice(intr1_keypair.sign(intr2.as_ref()).as_ref());
        let intr2_sig      = Signature::from_slice(intr2_keypair.sign(intr3.as_ref()).as_ref());
        let intr3_sig      = Signature::from_slice(intr3_keypair.sign(end.as_ref()).as_ref());

        assert!(root_sig.is_some());
        assert!(intr1_sig.is_some());
        assert!(intr2_sig.is_some());
        assert!(intr3_sig.is_some());

        let root_sig       = root_sig.unwrap();
        let intr1_sig      = intr1_sig.unwrap();
        let intr2_sig      = intr2_sig.unwrap();
        let intr3_sig      = intr3_sig.unwrap();
        let link1          = Link::new(intr1, root_sig);
        let link2          = Link::new(intr2, intr1_sig);
        let link3          = Link::new(intr3, intr2_sig);
        let link4          = Link::new(end,   intr3_sig);
        let chain          = trust_chain_v3!(&root_key_store, Root::new(root), link1, link2, link3, link4);

        assert_ok!(chain);

        let chain          = chain.unwrap();
        let test_data      = b"test data";
        let end_sig        = Signature::from(end_keypair.sign(test_data));
        let verify_res     = chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_res);

        let cb             = chain.as_bytes();

        assert_eq!(cb[0..4], TC_V3_HEADER);
        assert_eq!(cb[4], 0x05);// subsequent chain length
        assert_key(&cb,  5, root.as_ref(),0);// root public key, 32 bytes
        assert_key(&cb, 37, intr1.as_ref(),0);
        assert_sig(&cb, 69, root_sig.as_ref(),0);
        assert_key(&cb,133, intr2.as_ref(),0);
        assert_sig(&cb,165, intr1_sig.as_ref(),0);
        assert_key(&cb,229, intr3.as_ref(),0);
        assert_sig(&cb,261, intr2_sig.as_ref(),0);
        assert_key(&cb,325, end.as_ref(),0);
        assert_sig(&cb,357, intr3_sig.as_ref(),0);

        let parsed_chain   = trust_chain(&mut cb.as_slice(), &root_key_store);

        assert_ok!(parsed_chain);

        let parsed_chain   = parsed_chain.unwrap();
        let verify_parsed  = parsed_chain.verify_data(&end_sig, test_data);

        assert_ok!(verify_parsed);
    }
}

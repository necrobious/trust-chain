use sodiumoxide::crypto::sign::ed25519::{self,PublicKey,Signature};
use nom::{be_u8,be_u16};
use super::error::TrustError;
use super::trust_chain::{RootKeysStore,TrustChain,PUBLICKEYBYTES,SIGNATUREBYTES,MAXCHAINLINKS};

named!(signature<Signature>, do_parse!(
    bytes: take!(SIGNATUREBYTES) >>
    sig: expr_opt!(Signature::from_slice(bytes)) >>
    (sig)
));


named!(public_key<PublicKey>, do_parse!(
    bytes: take!(PUBLICKEYBYTES) >>
    key: expr_opt!(PublicKey::from_slice(bytes)) >>
    (key)
));


fn chain_for (
    untrusted_root_key: PublicKey,
    root_keys_store:Box<RootKeysStore>,
    links:Vec<(PublicKey,Signature)>) -> Result<TrustChain,TrustError> {
    match links.len() {
        0 => TrustChain::root_only_chain(
                untrusted_root_key,
                root_keys_store
                ),
        1 => TrustChain::two_link_chain(
                untrusted_root_key,
                links[0].0,//public key
                links[0].1,//signature
                root_keys_store),
        2 => TrustChain::three_link_chain(
                untrusted_root_key,
                links[0].0,//public key
                links[1].0,//public key
                links[0].1,//signature
                links[1].1,//signature
                root_keys_store),
        3 => TrustChain::four_link_chain(
                untrusted_root_key,
                links[0].0,//public key
                links[1].0,//public key
                links[2].0,//public key
                links[0].1,//signature
                links[1].1,//signature
                links[2].1,//signature
                root_keys_store),
        4 => TrustChain::five_link_chain(
                untrusted_root_key,
                links[0].0,//public key
                links[1].0,//public key
                links[2].0,//public key
                links[3].0,//public key
                links[0].1,//signature
                links[1].1,//signature
                links[2].1,//signature
                links[3].1,//signature
                root_keys_store),
        _ => Err(TrustError::MaxChainLengthExceeded)
    }
}

named_args!(pub trust_chain(root_keys:Box<RootKeysStore>)<TrustChain>, do_parse!(
    _tag: tag!("TC") >>
    _ver: verify!(be_u16, |ver:u16| ver == 2) >>
    root: public_key >>
    chain_length: verify!(be_u8, |len:u8| len < MAXCHAINLINKS as u8) >>
    links: count!(tuple!(public_key,signature), chain_length as usize) >>
    chain: expr_res!(chain_for(root,root_keys,links)) >>
    (chain)
));

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


#[test]
fn root_only_chain_end_to_end_test () {
    let (pkey, skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(pkey));
    let chain_res = TrustChain::root_only_chain(pkey, root_key_store.clone());

    assert!(chain_res.is_ok());

    let chain = chain_res.unwrap();

    let test_data = b"test data";
    let sig = ed25519::sign_detached(test_data, &skey);

    let verify_res = chain.verify_data(&sig, test_data);

    assert!(verify_res.is_ok());

    let cb = chain.as_bytes();
    assert_eq!(cb[0],  0x54);// T
    assert_eq!(cb[1],  0x43);// C
    assert_eq!(cb[2],  0x00);// version 0x00, 0x02
    assert_eq!(cb[3],  0x02);//
    assert_key(&cb,4, &pkey.0,0);// root public key, 32 bytes
    assert_eq!(cb[36], 0x00);// subsequent chain length

    let parsed_chain_res = trust_chain(&cb, root_key_store);

    assert!(parsed_chain_res.is_ok());

    let parsed_chain = parsed_chain_res.unwrap().1;
    let verify_parsed_res = parsed_chain.verify_data(&sig, test_data);

    assert!(verify_parsed_res.is_ok());
}

#[test]
fn two_link_chain_end_to_end_test () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (end_pkey, end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&end_pkey.0, &root_skey);

    let chain_res = TrustChain::two_link_chain(
        root_pkey,
        end_pkey,
        root_sig,
        root_key_store.clone()
    );
    assert!(chain_res.is_ok());

    let chain = chain_res.unwrap();

    let test_data = b"test data";
    let sig = ed25519::sign_detached(test_data, &end_skey);

    let verify_res = chain.verify_data(&sig, test_data);

    assert!(verify_res.is_ok());

    let cb = chain.as_bytes();
    assert_eq!(cb[0],  0x54);// T
    assert_eq!(cb[1],  0x43);// C
    assert_eq!(cb[2],  0x00);// version 0x00, 0x02
    assert_eq!(cb[3],  0x02);//
    assert_key(&cb,4, &root_pkey.0,0);// root public key, 32 bytes
    assert_eq!(cb[36], 0x01);// subsequent chain length
    assert_key(&cb,37, &end_pkey.0,0);
    assert_sig(&cb,69, &root_sig.0,0);

    let parsed_chain_res = trust_chain(&cb, root_key_store);

    assert!(parsed_chain_res.is_ok());

    let parsed_chain = parsed_chain_res.unwrap().1;
    let verify_parsed_res = parsed_chain.verify_data(&sig, test_data);

    assert!(verify_parsed_res.is_ok());
}

#[test]
fn three_link_chain_end_to_end_test () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (intr_pkey, intr_skey) = ed25519::gen_keypair();
    let (end_pkey, end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&intr_pkey.0, &root_skey);
    let intr_sig = ed25519::sign_detached(&end_pkey.0, &intr_skey);

    let chain_res = TrustChain::three_link_chain(
        root_pkey,
        intr_pkey,
        end_pkey,
        root_sig,
        intr_sig,
        root_key_store.clone()
    );
    assert!(chain_res.is_ok());

    let chain = chain_res.unwrap();

    let test_data = b"test data";
    let sig = ed25519::sign_detached(test_data, &end_skey);

    let verify_res = chain.verify_data(&sig, test_data);

    assert!(verify_res.is_ok());

    let cb = chain.as_bytes();
    assert_eq!(cb[0],  0x54);// T
    assert_eq!(cb[1],  0x43);// C
    assert_eq!(cb[2],  0x00);// version 0x00, 0x02
    assert_eq!(cb[3],  0x02);//
    assert_key(&cb,4, &root_pkey.0,0);// root public key, 32 bytes
    assert_eq!(cb[36], 0x02);// subsequent chain length
    assert_key(&cb,37, &intr_pkey.0,0);
    assert_sig(&cb,69, &root_sig.0,0);
    assert_key(&cb,133, &end_pkey.0,0);
    assert_sig(&cb,165, &intr_sig.0,0);

    let parsed_chain_res = trust_chain(&cb, root_key_store);

    assert!(parsed_chain_res.is_ok());

    let parsed_chain = parsed_chain_res.unwrap().1;
    let verify_parsed_res = parsed_chain.verify_data(&sig, test_data);

    assert!(verify_parsed_res.is_ok());
}

#[test]
fn four_link_chain_end_to_end_test () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (intr1_pkey, intr1_skey) = ed25519::gen_keypair();
    let (intr2_pkey, intr2_skey) = ed25519::gen_keypair();
    let (end_pkey, end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&intr1_pkey.0, &root_skey);
    let intr1_sig = ed25519::sign_detached(&intr2_pkey.0, &intr1_skey);
    let intr2_sig = ed25519::sign_detached(&end_pkey.0, &intr2_skey);

    let chain_res = TrustChain::four_link_chain(
        root_pkey,
        intr1_pkey,
        intr2_pkey,
        end_pkey,
        root_sig,
        intr1_sig,
        intr2_sig,
        root_key_store.clone()
    );
    assert!(chain_res.is_ok());

    let chain = chain_res.unwrap();

    let test_data = b"test data";
    let sig = ed25519::sign_detached(test_data, &end_skey);

    let verify_res = chain.verify_data(&sig, test_data);

    assert!(verify_res.is_ok());

    let cb = chain.as_bytes();
    assert_eq!(cb[0],  0x54);// T
    assert_eq!(cb[1],  0x43);// C
    assert_eq!(cb[2],  0x00);// version 0x00, 0x02
    assert_eq!(cb[3],  0x02);//
    assert_key(&cb,4, &root_pkey.0,0);// root public key, 32 bytes
    assert_eq!(cb[36], 0x03);// subsequent chain length
    assert_key(&cb,37, &intr1_pkey.0,0);
    assert_sig(&cb,69, &root_sig.0,0);
    assert_key(&cb,133, &intr2_pkey.0,0);
    assert_sig(&cb,165, &intr1_sig.0,0);
    assert_key(&cb,229, &end_pkey.0,0);
    assert_sig(&cb,261, &intr2_sig.0,0);

    let parsed_chain_res = trust_chain(&cb, root_key_store);

    assert!(parsed_chain_res.is_ok());

    let parsed_chain = parsed_chain_res.unwrap().1;
    let verify_parsed_res = parsed_chain.verify_data(&sig, test_data);

    assert!(verify_parsed_res.is_ok());
}

#[test]
fn five_link_chain_end_to_end_test () {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (intr1_pkey, intr1_skey) = ed25519::gen_keypair();
    let (intr2_pkey, intr2_skey) = ed25519::gen_keypair();
    let (intr3_pkey, intr3_skey) = ed25519::gen_keypair();
    let (end_pkey, end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let root_sig = ed25519::sign_detached(&intr1_pkey.0, &root_skey);
    let intr1_sig = ed25519::sign_detached(&intr2_pkey.0, &intr1_skey);
    let intr2_sig = ed25519::sign_detached(&intr3_pkey.0, &intr2_skey);
    let intr3_sig = ed25519::sign_detached(&end_pkey.0, &intr3_skey);

    let chain_res = TrustChain::five_link_chain(
        root_pkey,
        intr1_pkey,
        intr2_pkey,
        intr3_pkey,
        end_pkey,
        root_sig,
        intr1_sig,
        intr2_sig,
        intr3_sig,
        root_key_store.clone()
    );
    assert!(chain_res.is_ok());

    let chain = chain_res.unwrap();

    let test_data = b"test data";
    let sig = ed25519::sign_detached(test_data, &end_skey);

    let verify_res = chain.verify_data(&sig, test_data);

    assert!(verify_res.is_ok());

    let cb = chain.as_bytes();
    assert_eq!(cb[0],  0x54);// T
    assert_eq!(cb[1],  0x43);// C
    assert_eq!(cb[2],  0x00);// version 0x00, 0x02
    assert_eq!(cb[3],  0x02);//
    assert_key(&cb,4, &root_pkey.0,0);// root public key, 32 bytes
    assert_eq!(cb[36], 0x04);// subsequent chain length
    assert_key(&cb,37, &intr1_pkey.0,0);
    assert_sig(&cb,69, &root_sig.0,0);
    assert_key(&cb,133, &intr2_pkey.0,0);
    assert_sig(&cb,165, &intr1_sig.0,0);
    assert_key(&cb,229, &intr3_pkey.0,0);
    assert_sig(&cb,261, &intr2_sig.0,0);
    assert_key(&cb,325, &end_pkey.0,0);
    assert_sig(&cb,357, &intr3_sig.0,0);

    let parsed_chain_res = trust_chain(&cb, root_key_store);

    assert!(parsed_chain_res.is_ok());

    let parsed_chain = parsed_chain_res.unwrap().1;
    let verify_parsed_res = parsed_chain.verify_data(&sig, test_data);

    assert!(verify_parsed_res.is_ok());
}


#[test]
fn pkey_should_parse () {
    let (pkey, _skey) = ed25519::gen_keypair();
    let res = public_key(&pkey.0);
    assert!(res.is_ok());
    assert_eq!(res.unwrap().1,pkey);
}

#[test]
fn sig_should_parse () {
    let (pkey, skey) = ed25519::gen_keypair();
    let sig = ed25519::sign_detached(&pkey.0, &skey);
    let psig = signature(&sig.0);
    assert!(psig.is_ok());
    assert_eq!(psig.unwrap().1,sig);
}

#[test]
fn bad_sig_data_should_fail () {
    let pkey = [0x00];
    let sig = signature(&pkey);
    assert!(sig.is_err());
}

#[test]
fn bad_pkey_data_should_fail () {
    let pkey = [0x00];
    let res = public_key(&pkey);
    assert!(res.is_err());
}

use ring::signature;
use crate::v3::TC_V3_HEADER;
use crate::v3::error::TrustError;
use crate::v3::signature::Signature;
use crate::v3::link::{Root, Link, TrustLink, Signed};
use crate::v3::keystore::RootKeysStore;
use core::convert::AsRef;
use core::fmt;
use std::convert::TryInto;

#[macro_export]
macro_rules! verify_signature_v3 {
    ($key:expr, $sig:expr, $data:expr) => {
        signature::UnparsedPublicKey::new(&signature::ED25519, $key)
            .verify(&[$data].concat(), $sig)
            .map_err(|_| TrustError::InvalidSignature)
    };
}

#[macro_export]
macro_rules! sign_v3 {
    ($keypair:expr, $data:expr) => {
        Signature::from_slice($keypair.sign(&[$data].concat()).as_ref());
    };
}

#[macro_export]
macro_rules! trust_chain_v3 {
    ($root_key_store:expr, $root:expr $(, $link:expr)*) => {
        TrustChain::new($root_key_store, $root)
            $(.and_then(|chain| chain.append($link)))*
    };
    //TODO:: the above case replaced all 5 of the cases below, however
    //       we lost the ability to bound the number of links at compile time
    //       and while construction will fail with a MaxChainLengthExceeded TrustError
    //       it would be better to bound the $link instances.
/*
    ($root_key_store:expr, $root:expr) => {
        TrustChain::new($root_key_store, $root)
    };
    ($root_key_store:expr, $root:expr, $link1:expr) => {
        TrustChain::new($root_key_store, $root)
            .and_then(|chain| chain.append($link1))
    };
    ($root_key_store:expr, $root:expr, $link1:expr, $link2:expr) => {
        TrustChain::new($root_key_store, $root)
            .and_then(|chain| chain.append($link1))
            .and_then(|chain| chain.append($link2))
    };
    ($root_key_store:expr, $root:expr, $link1:expr, $link2:expr, $link3:expr) => {
        TrustChain::new($root_key_store, $root)
            .and_then(|chain| chain.append($link1))
            .and_then(|chain| chain.append($link2))
            .and_then(|chain| chain.append($link3))
    };
    ($root_key_store:expr, $root:expr, $link1:expr, $link2:expr, $link3:expr, $link4:expr) => {
        TrustChain::new($root_key_store, $root)
            .and_then(|chain| chain.append($link1))
            .and_then(|chain| chain.append($link2))
            .and_then(|chain| chain.append($link3))
            .and_then(|chain| chain.append($link4))
    };
*/
}

#[derive(Copy,Clone,Debug,PartialEq)]
pub enum TrustChain {
    TC01(Root),
    TC02(Root, Link),
    TC03(Root, Link, Link),
    TC04(Root, Link, Link, Link),
    TC05(Root, Link, Link, Link, Link),
}

impl TrustChain {

    pub fn new <'ks> (
        root_key_store: &'ks (dyn RootKeysStore<'ks> + 'ks),
        root: Root ) -> Result<TrustChain, TrustError> {

        if !root_key_store.contains_root_key(root.key().as_ref()) {
            return Err(TrustError::NoRootKeyTrust)
        }

        Ok(Self::TC01(root))
    }

    pub fn iter <'c> (&self) -> TrustChainIterator {
        TrustChainIterator {
            chain: self,
            index: 0
        }
    }

    pub fn len (&self) -> usize {
        use TrustChain::*;
        match self {
            TC01(_)         => 1,
            TC02(_,_)       => 2,
            TC03(_,_,_)     => 3,
            TC04(_,_,_,_)   => 4,
            TC05(_,_,_,_,_) => 5,
        }

    }
    pub fn first <'c> (&'c self) -> &'c dyn TrustLink {
        use TrustChain::*;
        match self {
            TC01(l)         => l,
            TC02(l,_)       => l,
            TC03(l,_,_)     => l,
            TC04(l,_,_,_)   => l,
            TC05(l,_,_,_,_) => l,
        }
    }
    pub fn last <'c> (&'c self) -> &'c dyn TrustLink {
        use TrustChain::*;
        match self {
            TC01(l)         => l,
            TC02(_,l)       => l,
            TC03(_,_,l)     => l,
            TC04(_,_,_,l)   => l,
            TC05(_,_,_,_,l) => l,
        }
    }

    pub fn append (self, l:Link) -> Result<TrustChain, TrustError> {
        use TrustChain::*;

        verify_signature_v3!(self.last().key(),l.sig().as_ref(),l.key().as_ref())?;

        match self {
            TC01(r)         => Ok(TC02(r,l)),
            TC02(r,a)       => Ok(TC03(r,a,l)),
            TC03(r,a,b)     => Ok(TC04(r,a,b,l)),
            TC04(r,a,b,c)   => Ok(TC05(r,a,b,c,l)),
            TC05(_,_,_,_,_) => Err(TrustError::MaxChainLengthExceeded),
        }
    }

    pub fn verify_data (&self, untrusted_signature: &Signature, untrusted_data: &[u8]) -> Result<(),TrustError> {
        verify_signature_v3!(self.last().key(),untrusted_signature.as_ref(), untrusted_data)
    }

    pub fn as_bytes (&self) -> Vec<u8> {
        let mut out:Vec<u8> = Vec::with_capacity(4 + 1 + 32 + ( (32 + 64) * (self.len() -1) ));
        for b in TC_V3_HEADER.iter() { out.push(*b) }
        out.push(self.len().try_into().unwrap());// safe because we prevent creation beyond max chain length.
        for l in self.iter() {
            if l.is_root() {
                for b in l.key().as_ref().iter() { out.push(*b) }
            } else {
                for b in l.key().as_ref().iter() { out.push(*b) }
                for b in l.signature().unwrap().as_ref().iter() { out.push(*b) }
            }
        }
        out
    }

}

pub struct TrustChainIterator<'c> {
    chain: &'c TrustChain,
    index: u8,
}

impl <'c> Iterator for TrustChainIterator<'c> {
    type Item = &'c dyn TrustLink;

    fn next(&mut self) -> Option<&'c dyn TrustLink> {
        use TrustChain::*;

        match (self.index, self.chain) {
            (0, TC01(l))         => { self.index += 1; Some(l)},
            (0, TC02(l,_))       => { self.index += 1; Some(l)},
            (0, TC03(l,_,_))     => { self.index += 1; Some(l)},
            (0, TC04(l,_,_,_))   => { self.index += 1; Some(l)},
            (0, TC05(l,_,_,_,_)) => { self.index += 1; Some(l)},
            (1, TC02(_,l))       => { self.index += 1; Some(l)},
            (1, TC03(_,l,_))     => { self.index += 1; Some(l)},
            (1, TC04(_,l,_,_))   => { self.index += 1; Some(l)},
            (1, TC05(_,l,_,_,_)) => { self.index += 1; Some(l)},
            (2, TC03(_,_,l))     => { self.index += 1; Some(l)},
            (2, TC04(_,_,l,_))   => { self.index += 1; Some(l)},
            (2, TC05(_,_,l,_,_)) => { self.index += 1; Some(l)},
            (3, TC04(_,_,_,l))   => { self.index += 1; Some(l)},
            (3, TC05(_,_,_,l,_)) => { self.index += 1; Some(l)},
            (4, TC05(_,_,_,_,l)) => { self.index += 1; Some(l)},
            _ => None
        }
    }
}

impl fmt::Display for TrustChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex_str = self.as_bytes()
            .iter()
            .map(|b| format!("{:02x?}",b))
            .collect::<String>();
        write!(f, "{}", hex_str)
    }
}

#[cfg(test)]
mod tests {
    use crate::v3::PUBLICKEYBYTES;
    use crate::v3::key::PublicKey;
    use crate::v3::link::{Root, Link};
    use ring::rand::{SystemRandom, SecureRandom};
    use ring::signature;
    use ring::signature::KeyPair;
    use super::*;

    macro_rules! assert_err {
        ($res:expr) => {{
            if $res.is_ok() {
                assert!(false, format!("{:?}",$res.unwrap()));
            }
        }};
    }


    macro_rules! assert_ok {
        ($res:expr) => {{
            if $res.is_err() {
                assert!(false, format!("{:?}",$res.unwrap_err()));
            }
        }};
    }


    fn gen_keypair(rand: &dyn SecureRandom) -> Option<signature::Ed25519KeyPair> {
        let mut seed = [0u8; PUBLICKEYBYTES];
        rand.fill(&mut seed).ok().and_then(|_| signature::Ed25519KeyPair::from_seed_unchecked(&seed).ok())
    }

    #[test]
    fn root_only_chain_construction () {
        let rand           = SystemRandom::new();
        let keypair        = gen_keypair(&rand).unwrap();
        let pkey           = PublicKey::from_slice(keypair.public_key().as_ref());

        assert!(pkey.is_some());

        let root           = pkey.unwrap();
        let root_key_store = vec!(root);
        let chain          = TrustChain::new(&root_key_store, Root::new(root));

        assert_ok!(chain);

        let chain          = trust_chain_v3!(&root_key_store, Root::new(root));

        assert_ok!(chain);
    }

    #[test]
    fn two_link_chain_construction () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root_pkey      = PublicKey::from_slice(root_keypair.public_key().as_ref());
        let end_pkey       = PublicKey::from_slice(end_keypair.public_key().as_ref());

        assert!(root_pkey.is_some());
        assert!(end_pkey.is_some());

        let root           = root_pkey.unwrap();
        let end            = end_pkey.unwrap();
        let root_key_store = vec!(root);
        let sig            = sign_v3!(root_keypair, end.as_ref());

        assert!(sig.is_some());

        let link1          = Link::new(end, sig.unwrap());
        let chain          = trust_chain_v3!(&root_key_store, Root::new(root), link1);

        assert_ok!(chain);
    }


    #[test]
    fn three_link_chain_construction () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let intr_keypair   = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root_pkey      = PublicKey::from_slice(root_keypair.public_key().as_ref());
        let intr_pkey      = PublicKey::from_slice(intr_keypair.public_key().as_ref());
        let end_pkey       = PublicKey::from_slice(end_keypair.public_key().as_ref());

        assert!(root_pkey.is_some());
        assert!(intr_pkey.is_some());
        assert!(end_pkey.is_some());

        let root           = root_pkey.unwrap();
        let intr           = intr_pkey.unwrap();
        let end            = end_pkey.unwrap();
        let root_key_store = vec!(root);
        let root_sig       = sign_v3!(root_keypair, intr.as_ref());
        let intr_sig       = sign_v3!(intr_keypair, end.as_ref());

        assert!(root_sig.is_some());
        assert!(intr_sig.is_some());

        let link1          = Link::new(intr, root_sig.unwrap());
        let link2          = Link::new(end,  intr_sig.unwrap());
        let chain          = trust_chain_v3!(&root_key_store, Root::new(root), link1, link2);

        assert_ok!(chain);

        let broken_chain   = trust_chain_v3!(&root_key_store, Root::new(root), link2, link1);

        assert_err!(broken_chain);
    }

/*
    #[test]
    fn four_link_chain_construction () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let intr1_keypair  = gen_keypair(&rand).unwrap();
        let intr2_keypair  = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root_pkey      = PublicKey(root_keypair.public_key().as_ref());
        let intr1_pkey     = PublicKey(intr1_keypair.public_key().as_ref());
        let intr2_pkey     = PublicKey(intr2_keypair.public_key().as_ref());
        let end_pkey       = PublicKey(end_keypair.public_key().as_ref());
        let root_key_store = vec!(root_pkey);
        let now            = Local::today();
        let before         = date_from(now.pred()).unwrap();//date_from(Utc.ymd(2020, 1, 13)).unwrap();
        let after          = date_from(now.succ()).unwrap();//date_from(Utc.ymd(2020, 1, 14)).unwrap();
        let expiry         = Expiry::new(NotBefore(before),NotAfter(after)).unwrap();
        let root_sig       = sign_v3!(root_keypair, expiry, intr1.as_ref());
        let intr1_sig       = sign_v3!(intr1_keypair, expiry, intr2.as_ref());
        let intr2_sig       = sign_v3!(intr2_keypair, expiry, end.as_ref());
//        let root_sig       = root_keypair.sign(intr1_pkey.as_ref());
//        let intr1_sig      = intr1_keypair.sign(intr2_pkey.as_ref());
//        let intr2_sig      = intr2_keypair.sign(end_pkey.as_ref());

        let chain = TrustChain::four_link_chain(
            root_pkey,
            intr1_pkey,
            intr2_pkey,
            end_pkey,
            Signature::from_bytes(root_sig.as_ref()),
            Signature::from_bytes(intr1_sig.as_ref()),
            Signature::from_bytes(intr2_sig.as_ref()),
            &root_key_store
        );
        assert_ok!(chain);
    }

    #[test]
    fn five_link_chain_construction () {
        let rand           = SystemRandom::new();
        let root_keypair   = gen_keypair(&rand).unwrap();
        let intr1_keypair  = gen_keypair(&rand).unwrap();
        let intr2_keypair  = gen_keypair(&rand).unwrap();
        let intr3_keypair  = gen_keypair(&rand).unwrap();
        let end_keypair    = gen_keypair(&rand).unwrap();
        let root_pkey      = PublicKey(root_keypair.public_key().as_ref());
        let intr1_pkey     = PublicKey(intr1_keypair.public_key().as_ref());
        let intr2_pkey     = PublicKey(intr2_keypair.public_key().as_ref());
        let intr3_pkey     = PublicKey(intr3_keypair.public_key().as_ref());
        let end_pkey       = PublicKey(end_keypair.public_key().as_ref());
        let root_key_store = vec!(root_pkey);
        let root_sig       = root_keypair.sign(intr1_pkey.as_ref());
        let intr1_sig      = intr1_keypair.sign(intr2_pkey.as_ref());
        let intr2_sig      = intr2_keypair.sign(intr3_pkey.as_ref());
        let intr3_sig      = intr3_keypair.sign(end_pkey.as_ref());

        let chain = TrustChain::five_link_chain(
            root_pkey,
            intr1_pkey,
            intr2_pkey,
            intr3_pkey,
            end_pkey,
            Signature::from_bytes(root_sig.as_ref()),
            Signature::from_bytes(intr1_sig.as_ref()),
            Signature::from_bytes(intr2_sig.as_ref()),
            Signature::from_bytes(intr3_sig.as_ref()),
            &root_key_store
        );
        assert_ok!(chain);
    }
*/

}

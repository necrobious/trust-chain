use crate::v3::key::PublicKey;

pub trait RootKeysStore<'ks> {
    fn contains_root_key <'a> (&'ks self, candidate: &'a [u8]) -> bool;
}

impl <'ks> RootKeysStore<'ks> for Vec<PublicKey> {
    fn contains_root_key <'a> (&'ks self, candidate: &'a [u8]) -> bool {
        for trusted_key in self.iter() {
            if  trusted_key.as_ref() == candidate { return true }
        }
        false
    }
}


#[cfg(test)]
mod tests {
    use ring::rand::{SystemRandom, SecureRandom};
    use crate::v3::PUBLICKEYBYTES;
    use super::*;

    #[test]
    fn keystore_should_find_test_key () {
        let rand = SystemRandom::new();
        let mut bytes = [0u8;PUBLICKEYBYTES];
        assert!( rand.fill(&mut bytes).is_ok() );

        let key_opt = PublicKey::from_slice(&bytes);
        assert!( key_opt.is_some() );

        let ks:Vec<PublicKey> = vec!(key_opt.unwrap());

        assert!(ks.contains_root_key(&bytes))
    }

}

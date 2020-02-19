use crate::v3::error::TrustError;
use crate::v3::date::{Date,DateError};
use core::cmp::{PartialOrd, Ordering};


#[derive(Debug,Copy,Clone,Eq)]
pub struct NotBefore(pub Date);

impl NotBefore {
    pub fn date (&self) -> Date {self.0}
}

impl Ord for NotBefore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for NotBefore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NotBefore {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[derive(Debug,Copy,Clone,Eq)]
pub struct NotAfter(pub Date);

impl NotAfter {
    pub fn date (&self) -> Date {self.0}
}

impl Ord for NotAfter {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for NotAfter {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NotAfter {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[derive(Debug,Copy,Clone,PartialEq)]
pub struct Expiry {
    not_before : NotBefore,
    not_after  : NotAfter,
}

impl Expiry {
    pub fn new (not_before: NotBefore, not_after: NotAfter) -> Result<Expiry,TrustError> {
        if not_before.date() > not_after.date() { return Err(TrustError::InvalidExpiry) }
        else { Ok(Expiry{not_before, not_after}) }
    }

    pub fn as_bytes (&self) -> [u8;6] {
        let nb = self.not_before.0.as_bytes();
        let na = self.not_after.0.as_bytes();
        [
            nb[0],nb[1],nb[2],
            na[0],na[1],na[2],
        ]
    }

    pub fn from_bytes (bytes: &[u8]) -> Result<Expiry,DateError> {
        if bytes.len() < 6 { return Err(DateError::InvalidDate) }
        Date::from_bytes(&bytes[0..3])
            .map(|nb| NotBefore(nb))
            .and_then(|nb|
                Date::from_bytes(&bytes[3..6])
                    .map(|na| Expiry{not_before:nb, not_after:NotAfter(na)})
            )
    }
}


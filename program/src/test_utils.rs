#[cfg(test)]
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};

#[cfg(test)]
pub fn random_pubkey() -> Pubkey {
    rand::random::<[u8; PUBKEY_BYTES]>()
}

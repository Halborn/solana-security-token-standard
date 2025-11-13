#[cfg(test)]
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};

#[cfg(test)]
pub fn random_pubkey() -> Pubkey {
    rand::random::<[u8; PUBKEY_BYTES]>()
}

#[cfg(test)]
pub fn random_32_bytes() -> [u8; 32] {
    rand::random::<[u8; 32]>()
}

#[cfg(test)]
pub fn random_32_bytes_vec(len: usize) -> Vec<[u8; 32]> {
    (0..len).map(|_| random_32_bytes()).collect()
}

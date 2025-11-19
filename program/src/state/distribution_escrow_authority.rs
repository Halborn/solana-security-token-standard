use pinocchio::{instruction::Seed, pubkey::Pubkey};

use crate::{
    constants::{seeds::DISTRIBUTION_ESCROW_AUTHORITY, ACTION_ID_LEN},
    merkle_tree_utils::MerkleTreeRoot,
    utils::find_distribution_escrow_authority_pda,
};

pub struct DistributionEscrowAuthority {}

impl DistributionEscrowAuthority {
    pub fn action_id_seed(action_id: u64) -> [u8; ACTION_ID_LEN] {
        action_id.to_le_bytes()
    }

    pub fn bump_seed(bump: u8) -> [u8; 1] {
        [bump]
    }

    /// Seeds for signing
    pub fn seeds<'a>(
        mint: &'a Pubkey,
        action_id_seed: &'a [u8],
        merkle_root: &'a MerkleTreeRoot,
        bump_seed: &'a [u8; 1],
    ) -> [Seed<'a>; 5] {
        [
            Seed::from(DISTRIBUTION_ESCROW_AUTHORITY),
            Seed::from(mint.as_ref()),
            Seed::from(action_id_seed),
            Seed::from(merkle_root.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Finds the PDA for the Distribution Escrow Authority
    pub fn find_pda(mint: &Pubkey, action_id: u64, merkle_root: &MerkleTreeRoot) -> (Pubkey, u8) {
        find_distribution_escrow_authority_pda(mint, action_id, merkle_root, &crate::id())
    }
}

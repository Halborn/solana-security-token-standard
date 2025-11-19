use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN,
    instructions::rate_account::shared::parse_action_id_argument,
    merkle_tree_utils::{MerkleTreeRoot, EMPTY_MERKLE_ROOT, MERKLE_ROOT_LEN},
};

/// Arguments to create a Distribution Escrow
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CreateDistributionEscrowArgs {
    /// Action ID for the distribution operation
    pub action_id: u64,
    /// Merkle tree root
    #[idl_type("[u8; 32]")]
    pub merkle_root: MerkleTreeRoot,
}

impl CreateDistributionEscrowArgs {
    /// action_id + merkle_root
    pub const LEN: usize = ACTION_ID_LEN + MERKLE_ROOT_LEN;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let action_id = parse_action_id_argument(&data[..ACTION_ID_LEN])?;

        let merkle_root =
            <MerkleTreeRoot>::try_from(&data[ACTION_ID_LEN..(MERKLE_ROOT_LEN + ACTION_ID_LEN)])
                .map_err(|_| ProgramError::InvalidArgument)?;

        if merkle_root == EMPTY_MERKLE_ROOT {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(Self {
            action_id,
            merkle_root,
        })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.extend_from_slice(self.merkle_root.as_ref());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::random_32_bytes;
    use rstest::rstest;

    #[rstest]
    #[case(42u64, random_32_bytes())]
    #[case(1u64, random_32_bytes())]
    #[case(u64::MAX, random_32_bytes())]
    fn test_create_distribution_escrow_args_to_bytes(
        #[case] action_id: u64,
        #[case] merkle_root: MerkleTreeRoot,
    ) {
        let original = CreateDistributionEscrowArgs {
            action_id,
            merkle_root,
        };

        let bytes = original.to_bytes_inner();
        let deserialized = CreateDistributionEscrowArgs::try_from_bytes(&bytes)
            .expect("Should deserialize CreateDistributionEscrowArgs");

        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.merkle_root, deserialized.merkle_root);
    }

    #[rstest]
    #[case(0u64, random_32_bytes(), "Zero action_id should be invalid")]
    #[case(1u64, [0u8; 32], "Empty merkle root should be invalid")]
    fn test_create_distribution_escrow_args_validation(
        #[case] action_id: u64,
        #[case] merkle_root: MerkleTreeRoot,
        #[case] description: &str,
    ) {
        let original = CreateDistributionEscrowArgs {
            action_id,
            merkle_root,
        };

        assert!(
            CreateDistributionEscrowArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

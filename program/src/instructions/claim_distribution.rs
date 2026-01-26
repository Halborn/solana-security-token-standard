use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN,
    instructions::rate_account::shared::parse_action_id_argument,
    merkle_tree_utils::{MerkleTreeRoot, ProofData, MERKLE_ROOT_LEN},
    state::{ProofDataDeserializer, ProofDataValidator},
};

/// Arguments to claim a distribution
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct ClaimDistributionArgs {
    /// Action ID of the distribution
    pub action_id: u64,
    /// Eligible amount to claim
    pub amount: u64,
    /// Merkle root of the distribution
    #[idl_type("[u8; 32]")]
    pub merkle_root: MerkleTreeRoot,
    /// Merkle tree leaf index
    pub leaf_index: u32,
    /// Merkle proof of the claimer
    /// Provided either by argument or Proof account
    #[idl_type("Option<Vec<[u8; 32]>>")]
    pub merkle_proof: Option<ProofData>,
}

impl ProofDataDeserializer for ClaimDistributionArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidArgument
    }
}

impl ProofDataValidator for ClaimDistributionArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidArgument
    }
}

impl ClaimDistributionArgs {
    /// action_id (8 bytes) + amount (8 bytes) + merkle_root (32 bytes) + leaf_index (4 bytes) + proof (1 byte for Option prefix)
    pub const MIN_LEN: usize = ACTION_ID_LEN + 8 + MERKLE_ROOT_LEN + 4 + 1;

    /// Deserialize arguments from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;
        let action_id = parse_action_id_argument(&data[..ACTION_ID_LEN])?;
        offset += ACTION_ID_LEN;

        let amount = u64::from_le_bytes(
            data[ACTION_ID_LEN..offset + 8]
                .try_into()
                .map_err(|_| ProgramError::InvalidArgument)?,
        );
        offset += 8;

        if amount == 0 {
            return Err(ProgramError::InvalidArgument);
        }

        let merkle_root = MerkleTreeRoot::try_from(&data[offset..offset + MERKLE_ROOT_LEN])
            .map_err(|_| ProgramError::InvalidArgument)?;
        Self::validate_non_zero_node(&merkle_root)?;

        offset += MERKLE_ROOT_LEN;
        let leaf_index = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| ProgramError::InvalidArgument)?,
        );

        offset += 4;
        let proof_option_prefix = data[offset];
        let merkle_proof = match proof_option_prefix {
            0 => None,
            1 => {
                let proof_data = Self::try_proof_data_from_bytes(&data[offset + 1..])?;
                Self::validate_proof_data_len(&proof_data)?;
                Self::validate_proof_data(&proof_data)?;
                Some(proof_data)
            }
            _ => return Err(ProgramError::InvalidInstructionData),
        };

        Ok(Self {
            action_id,
            amount,
            merkle_root,
            leaf_index,
            merkle_proof,
        })
    }

    /// Pack the arguments into bytes
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.extend_from_slice(self.amount.to_le_bytes().as_ref());
        data.extend_from_slice(self.merkle_root.as_ref());
        data.extend_from_slice(self.leaf_index.to_le_bytes().as_ref());
        // Add option prefix for merkle_proof
        data.push(match &self.merkle_proof {
            Some(_) => 1u8,
            None => 0u8,
        });
        if let Some(proof) = &self.merkle_proof {
            // Add proof length prefix
            data.extend_from_slice((proof.len() as u32).to_le_bytes().as_ref());
            // Add nodes
            for node in proof {
                data.extend_from_slice(node.as_ref());
            }
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        merkle_tree_utils::EMPTY_MERKLE_TREE_NODE,
        test_utils::{random_32_bytes, random_32_bytes_vec},
    };

    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(42u64, 1000u64, random_32_bytes(), 0u32, None)]
    #[case(
        u64::MAX,
        u64::MAX,
        random_32_bytes(),
        1u32,
        Some(random_32_bytes_vec(3))
    )]
    fn test_claim_distribution_args_to_bytes(
        #[case] action_id: u64,
        #[case] amount: u64,
        #[case] merkle_root: MerkleTreeRoot,
        #[case] leaf_index: u32,
        #[case] merkle_proof: Option<ProofData>,
    ) {
        let original = ClaimDistributionArgs {
            action_id,
            amount,
            merkle_root,
            leaf_index,
            merkle_proof,
        };

        let bytes = original.to_bytes_inner();
        let deserialized = ClaimDistributionArgs::try_from_bytes(&bytes)
            .expect("Should deserialize ClaimDistributionArgs");

        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.amount, deserialized.amount);
        assert_eq!(original.merkle_root, deserialized.merkle_root);
        assert_eq!(original.merkle_proof, deserialized.merkle_proof);
    }

    #[rstest]
    #[case(
        0u64,
        1000u64,
        random_32_bytes(),
        0u32,
        None,
        "Zero action_id should be invalid"
    )]
    #[case(
        42u64,
        0u64,
        random_32_bytes(),
        0u32,
        None,
        "Zero amount should be invalid"
    )]
    #[case(
        42u64,
        1u64,
        EMPTY_MERKLE_TREE_NODE,
        0u32,
        None,
        "Zero merkle root should be invalid"
    )]
    #[case(42u64, 1u64, random_32_bytes(), 0u32, Some(vec![EMPTY_MERKLE_TREE_NODE]), "Zero proof node should be invalid")]
    #[case(
        42u64,
        1u64,
        random_32_bytes(),
        0u32,
        Some(random_32_bytes_vec(33)),
        "Proof exceeding MAX_PROOF_LEVELS should be invalid"
    )]
    fn test_claim_distribution_args_invalid_deserialization(
        #[case] action_id: u64,
        #[case] amount: u64,
        #[case] merkle_root: MerkleTreeRoot,
        #[case] leaf_index: u32,
        #[case] merkle_proof: Option<ProofData>,
        #[case] description: &str,
    ) {
        let original = ClaimDistributionArgs {
            action_id,
            amount,
            merkle_root,
            leaf_index,
            merkle_proof,
        };
        let bytes = original.to_bytes_inner();

        assert!(
            ClaimDistributionArgs::try_from_bytes(&bytes).is_err(),
            "{}",
            description
        );
    }
}

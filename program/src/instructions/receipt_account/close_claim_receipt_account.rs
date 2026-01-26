use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN,
    instructions::rate_account::shared::parse_action_id_argument,
    merkle_tree_utils::ProofData,
    state::{ProofDataDeserializer, ProofDataValidator},
};

/// Arguments to closing Receipt account of claim_distribution operation
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CloseClaimReceiptArgs {
    /// Action ID of the claim_distribution operation
    pub action_id: u64,
    /// Merkle proof data of the claimed distribution
    /// Provided either by argument or Proof account
    #[idl_type("Option<Vec<[u8; 32]>>")]
    pub merkle_proof: Option<ProofData>,
}

impl ProofDataDeserializer for CloseClaimReceiptArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidArgument
    }
}

impl ProofDataValidator for CloseClaimReceiptArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidArgument
    }
}

impl CloseClaimReceiptArgs {
    // action_id (8 bytes) + option prefix (1 byte)
    pub const MIN_LEN: usize = ACTION_ID_LEN + 1;

    /// Parse CloseClaimReceiptArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut offset = ACTION_ID_LEN;
        let action_id = parse_action_id_argument(&data[..offset])?;

        let proof_option_prefix = data[offset];
        offset += 1;
        let merkle_proof = match proof_option_prefix {
            0 => None,
            1 => {
                let proof_data = Self::try_proof_data_from_bytes(&data[offset..])?;
                Self::validate_proof_data_len(&proof_data)?;
                Self::validate_proof_data(&proof_data)?;
                Some(proof_data)
            }
            _ => return Err(ProgramError::InvalidInstructionData),
        };

        Ok(Self {
            action_id,
            merkle_proof,
        })
    }

    /// Pack the arguments into bytes
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.action_id.to_le_bytes());
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
    #[case(42u64, None)]
    #[case(1u64, Some(random_32_bytes_vec(3)))]
    #[case(u64::MAX, Some(random_32_bytes_vec(32)))]
    fn test_close_claim_receipt_args_try_from_bytes(
        #[case] action_id: u64,
        #[case] merkle_proof: Option<ProofData>,
    ) {
        let original = CloseClaimReceiptArgs {
            action_id,
            merkle_proof,
        };

        let bytes = original.to_bytes_inner();
        let deserialized = CloseClaimReceiptArgs::try_from_bytes(&bytes)
            .expect("Should deserialize CloseClaimReceiptArgs");
        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.merkle_proof, deserialized.merkle_proof);
    }

    #[rstest]
    #[case(0u64, None, "Zero action_id should be invalid")]
    #[case(5u64, Some(vec![EMPTY_MERKLE_TREE_NODE, random_32_bytes(), random_32_bytes()]), "CloseClaimReceiptArgs proof_data with zero node should be invalid")]
    #[case(5u64, Some(vec![]), "CloseClaimReceiptArgs with empty proof_data should be invalid")]
    #[case(
        5u64,
        Some(random_32_bytes_vec(33)),
        "CloseClaimReceiptArgs with proof_data exceeding MAX_PROOF_LEVELS should be invalid"
    )]
    fn test_close_claim_receipt_args_validation(
        #[case] action_id: u64,
        #[case] merkle_proof: Option<ProofData>,
        #[case] description: &str,
    ) {
        let original = CloseClaimReceiptArgs {
            action_id,
            merkle_proof,
        };

        assert!(
            CloseClaimReceiptArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN,
    instructions::rate_account::shared::parse_action_id_argument,
    merkle_tree_utils::ProofData,
    state::{Proof, ProofDataDeserializer, ProofDataValidator},
};

/// Arguments to create Proof account
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CreateProofArgs {
    /// Action ID for the proof creation
    pub action_id: u64,
    /// Merkle proof data
    #[idl_type("Vec<[u8; 32]>")]
    pub data: ProofData,
}

impl ProofDataValidator for CreateProofArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidAccountData
    }
}

impl ProofDataDeserializer for CreateProofArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidArgument
    }
}

impl CreateProofArgs {
    /// action_id (8 bytes) + vec prefix (4 bytes)
    pub const MIN_LEN: usize = ACTION_ID_LEN + Proof::VEC_LEN_PREFIX;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let action_id = parse_action_id_argument(&data[..ACTION_ID_LEN])?;
        let proof_data = Self::try_proof_data_from_bytes(&data[ACTION_ID_LEN..])?;
        Self::validate_proof_data(&proof_data)?;
        Ok(Self {
            action_id,
            data: proof_data,
        })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.extend_from_slice((self.data.len() as u32).to_le_bytes().as_ref());
        for node in &self.data {
            data.extend_from_slice(node.as_ref());
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
    #[case(5u64, random_32_bytes_vec(3))]
    #[case(u64::MAX, random_32_bytes_vec(2))]
    fn test_create_proof_args_to_bytes_inner_try_from_bytes(
        #[case] action_id: u64,
        #[case] proof_data: ProofData,
    ) {
        let original = CreateProofArgs {
            action_id,
            data: proof_data,
        };

        let bytes = original.to_bytes_inner();
        let deserialized =
            CreateProofArgs::try_from_bytes(&bytes).expect("Should deserialize proof arguments");

        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.data, deserialized.data);
    }

    #[rstest]
    #[case(
        0u64,
        random_32_bytes_vec(3),
        "ProofArgs with zero action_id should be invalid"
    )]
    #[case(5u64, vec![EMPTY_MERKLE_TREE_NODE, random_32_bytes(), random_32_bytes()], "ProofArgs proof_data with zero node should be invalid")]
    #[case(u64::MAX, vec![], "ProofArgs with empty data should be invalid")]
    fn test_create_proof_args_validation(
        #[case] action_id: u64,
        #[case] proof_data: ProofData,
        #[case] description: &str,
    ) {
        let original = CreateProofArgs {
            action_id,
            data: proof_data,
        };
        let bytes = original.to_bytes_inner();
        assert!(
            CreateProofArgs::try_from_bytes(&bytes).is_err(),
            "{}",
            description
        );
    }
    #[test]
    fn test_try_from_bytes_fails_on_too_short_buffer() {
        let short = vec![0u8; CreateProofArgs::MIN_LEN - 1];
        assert!(CreateProofArgs::try_from_bytes(&short).is_err());
    }
}

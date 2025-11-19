use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN,
    instructions::rate_account::shared::parse_action_id_argument,
    merkle_tree_utils::{ProofNode, MERKLE_TREE_NODE_LEN},
    state::{ProofDataDeserializer, ProofDataValidator},
};

/// Arguments to update Proof account data
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct UpdateProofArgs {
    /// Action ID for the proof creation
    pub action_id: u64,
    /// Proof node data to update
    #[idl_type("[u8; 32]")]
    pub data: ProofNode,
    /// Offset to update Proof node at
    pub offset: u32,
}

impl ProofDataValidator for UpdateProofArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidAccountData
    }
}

impl ProofDataDeserializer for UpdateProofArgs {
    fn error() -> ProgramError {
        ProgramError::InvalidArgument
    }
}

impl UpdateProofArgs {
    /// action_id (8 bytes) + node data (32 bytes) + offset (4 bytes)
    pub const LEN: usize = ACTION_ID_LEN + MERKLE_TREE_NODE_LEN + 4;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut bytes_offset = ACTION_ID_LEN;
        let action_id = parse_action_id_argument(&data[..bytes_offset])?;

        let proof_node = Self::try_proof_node_from_bytes(
            &data[bytes_offset..bytes_offset + MERKLE_TREE_NODE_LEN],
        )?;
        Self::validate_proof_node_data(&proof_node)?;

        bytes_offset += MERKLE_TREE_NODE_LEN;

        let offset = data
            .get(bytes_offset..bytes_offset + 4)
            .and_then(|slice| slice.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(ProgramError::InvalidArgument)?;

        Ok(Self {
            action_id,
            data: proof_node,
            offset,
        })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.extend_from_slice(self.data.as_ref());
        data.extend_from_slice(self.offset.to_le_bytes().as_ref());
        data
    }
}

#[cfg(test)]
mod tests {
    use crate::{merkle_tree_utils::EMPTY_MERKLE_TREE_NODE, test_utils::random_32_bytes};

    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(5u64, random_32_bytes(), 10u32)]
    #[case(u64::MAX, random_32_bytes(), u32::MAX)]
    #[case(1u64, random_32_bytes(), 0u32)]
    fn test_update_proof_args_to_bytes_inner_try_from_bytes(
        #[case] action_id: u64,
        #[case] proof_node: ProofNode,
        #[case] offset: u32,
    ) {
        let original = UpdateProofArgs {
            action_id,
            data: proof_node,
            offset,
        };

        let bytes = original.to_bytes_inner();
        let deserialized =
            UpdateProofArgs::try_from_bytes(&bytes).expect("Should deserialize UpdateProofArgs");

        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.data, deserialized.data);
    }

    #[rstest]
    #[case(
        0u64,
        random_32_bytes(),
        10u32,
        "UpdateProofArgs with zero action_id should be invalid"
    )]
    #[case(
        42u64,
        EMPTY_MERKLE_TREE_NODE,
        10u32,
        "UpdateProofArgs with zero proof node should be invalid"
    )]
    fn test_update_proof_args_validation(
        #[case] action_id: u64,
        #[case] proof_node: ProofNode,
        #[case] offset: u32,
        #[case] description: &str,
    ) {
        let original = UpdateProofArgs {
            action_id,
            data: proof_node,
            offset,
        };
        let bytes = original.to_bytes_inner();
        assert!(
            UpdateProofArgs::try_from_bytes(&bytes).is_err(),
            "{}",
            description
        );
    }

    #[test]
    fn test_update_proof_fails_on_too_short_buffer() {
        let short = vec![0u8; UpdateProofArgs::LEN - 1];
        assert!(UpdateProofArgs::try_from_bytes(&short).is_err());
    }
}

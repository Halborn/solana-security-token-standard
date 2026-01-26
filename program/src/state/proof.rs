//! Proof account state
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{create_program_address, Pubkey},
    ProgramResult,
};
use shank::ShankAccount;

use crate::{
    constants::seeds::PROOF_ACCOUNT,
    merkle_tree_utils::{
        MerkleTreeNode, ProofData, ProofNode, EMPTY_MERKLE_TREE_NODE, MAX_PROOF_LEVELS,
        MERKLE_TREE_NODE_LEN,
    },
    modules::{verify_account_initialized, verify_pda_keys_match},
    state::{
        AccountDeserialize, AccountSerialize, Discriminator, ProgramAccount,
        SecurityTokenDiscriminators,
    },
    utils::find_proof_pda,
};

#[repr(C)]
#[derive(Debug, ShankAccount)]
pub struct Proof {
    /// Bump seed for PDA
    pub bump: u8,
    /// Merkle proof data
    #[idl_type("Vec<[u8; 32]>")]
    pub data: ProofData,
}

pub trait ProofDataDeserializer {
    fn error() -> ProgramError;

    fn try_proof_data_from_bytes(data: &[u8]) -> Result<ProofData, ProgramError> {
        if data.len() < Proof::VEC_LEN_PREFIX {
            return Err(Self::error());
        }

        let proof_nodes_len = u32::from_le_bytes(
            data[0..Proof::VEC_LEN_PREFIX]
                .try_into()
                .map_err(|_| Self::error())?,
        ) as usize;

        if proof_nodes_len == 0 {
            return Err(Self::error());
        }

        if data.len() < Proof::VEC_LEN_PREFIX + (proof_nodes_len * MERKLE_TREE_NODE_LEN) {
            return Err(Self::error());
        }

        let mut proof_data: Vec<ProofNode> = Vec::with_capacity(proof_nodes_len);

        let mut offset = Proof::VEC_LEN_PREFIX;
        for _ in 0..proof_nodes_len {
            let node_chunk =
                Self::try_proof_node_from_bytes(&data[offset..offset + MERKLE_TREE_NODE_LEN])?;
            proof_data.push(node_chunk);
            offset += MERKLE_TREE_NODE_LEN;
        }

        Ok(proof_data)
    }

    /// Deserialize a single Proof node from bytes
    fn try_proof_node_from_bytes(data: &[u8]) -> Result<ProofNode, ProgramError> {
        let node =
            <ProofNode>::try_from(&data[0..MERKLE_TREE_NODE_LEN]).map_err(|_| Self::error())?;

        Ok(node)
    }
}

pub trait ProofDataValidator {
    fn error() -> ProgramError;

    /// Validate proof data length is within valid bounds
    fn validate_proof_data_len(data: &ProofData) -> ProgramResult {
        if data.is_empty() {
            return Err(Self::error());
        }
        if data.len() > MAX_PROOF_LEVELS {
            return Err(Self::error());
        }
        Ok(())
    }

    /// Validate all proof nodes are non-zero
    fn validate_proof_data(proof_data: &ProofData) -> ProgramResult {
        proof_data
            .iter()
            .try_for_each(Self::validate_proof_node_data)?;
        Ok(())
    }

    /// Validate given proof node is non-zero
    fn validate_proof_node_data(proof_node: &ProofNode) -> ProgramResult {
        Self::validate_non_zero_node(proof_node)
    }

    /// Validate non-zero node
    fn validate_non_zero_node(node: &MerkleTreeNode) -> ProgramResult {
        if Self::is_zero_node(node) {
            return Err(Self::error());
        }
        Ok(())
    }

    fn is_zero_node(node: &ProofNode) -> bool {
        node.eq(&EMPTY_MERKLE_TREE_NODE)
    }
}

impl ProofDataValidator for Proof {
    fn error() -> ProgramError {
        ProgramError::InvalidAccountData
    }
}

impl ProofDataDeserializer for Proof {
    fn error() -> ProgramError {
        ProgramError::InvalidAccountData
    }
}

impl Discriminator for Proof {
    const DISCRIMINATOR: u8 = SecurityTokenDiscriminators::ProofDiscriminator as u8;
}

impl AccountSerialize for Proof {
    fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.bump);
        // Write vector length (4 bytes)
        data.extend(&(self.data.len() as u32).to_le_bytes());
        // Write each node
        for node in &self.data {
            data.extend_from_slice(node.as_ref());
        }
        data
    }
}

impl AccountDeserialize for Proof {
    fn try_from_bytes_inner(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN - 1 {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = 0;
        let bump = data[offset];
        offset += 1;
        let proof_data = Self::try_proof_data_from_bytes(&data[offset..])?;

        Ok(Self {
            bump,
            data: proof_data,
        })
    }
}

impl ProgramAccount for Proof {
    fn space(&self) -> u64 {
        self.serialized_len() as u64
    }
}

impl Proof {
    pub const VEC_LEN_PREFIX: usize = 4;
    /// Minimum size without any data
    /// Discriminator (1 byte) + bump (1 byte) + vector length prefix (4 bytes)
    pub const MIN_LEN: usize = 1 + 1 + Self::VEC_LEN_PREFIX;

    /// Calculate the actual size needed for serialization
    pub fn serialized_len(&self) -> usize {
        Self::MIN_LEN + (self.data.len() * MERKLE_TREE_NODE_LEN)
    }

    /// Create new Proof account
    pub fn new(data: &[ProofNode], bump: u8) -> Result<Self, ProgramError> {
        let proof = Self {
            data: data.to_vec(),
            bump,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Update proof data at given offset, or append if offset equals data length
    pub fn update_data_at_offset(&mut self, new_node: ProofNode, offset: usize) -> ProgramResult {
        if offset > self.data.len() {
            return Err(ProgramError::InvalidAccountData);
        }

        if offset == self.data.len() {
            self.data.push(new_node);
        } else {
            self.data[offset] = new_node;
        }
        self.validate()?;
        Ok(())
    }

    /// Validate the proof data
    pub fn validate(&self) -> ProgramResult {
        Self::validate_proof_data_len(&self.data)?;
        Self::validate_proof_data(&self.data)?;

        Ok(())
    }

    /// Parse from account info
    pub fn from_account_info(account_info: &AccountInfo) -> Result<Proof, ProgramError> {
        if account_info.data_len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        if !account_info.is_owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        let data_ref = account_info.try_borrow_data()?;
        let proof = Self::try_from_bytes(&data_ref)?;
        Ok(proof)
    }

    /// Helper function to get proof data either from account or argument
    /// Proof data can be provided either via account or instruction argument
    /// If both are provided, error is returned
    pub fn get_proof_data_from_instruction(
        eligible_token_account: &Pubkey,
        action_id: u64,
        proof_account: &AccountInfo,
        proof_data_argument: Option<ProofData>,
    ) -> Result<ProofData, ProgramError> {
        match (proof_account.key(), proof_data_argument) {
            (key, None) if key.eq(&crate::id()) => {
                // Neither proof account nor proof data provided
                Err(ProgramError::InvalidInstructionData)
            }
            (key, None) => {
                // Proof provided via account
                verify_account_initialized(proof_account)?;
                let proof_state = Proof::from_account_info(proof_account)?;
                let expected_proof_pda =
                    proof_state.derive_pda(eligible_token_account, action_id)?;
                verify_pda_keys_match(key, &expected_proof_pda)?;
                Ok(proof_state.data)
            }
            (key, Some(merkle_proof_arg)) => {
                // Proof provided from arguments
                // Sanity check - ensure proof account is not provided along with proof argument
                if key.ne(&crate::id()) {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(merkle_proof_arg)
            }
        }
    }

    pub fn bump_seed(&self) -> [u8; 1] {
        [self.bump]
    }

    /// Create seeds for signing
    pub fn seeds<'a>(
        &'a self,
        token_account_address: &'a Pubkey,
        action_id_seed: &'a [u8],
        bump_seed: &'a [u8; 1],
    ) -> [Seed<'a>; 4] {
        [
            Seed::from(PROOF_ACCOUNT),
            Seed::from(token_account_address.as_ref()),
            Seed::from(action_id_seed),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Optimized derive Proof account PDA
    pub fn derive_pda(
        &self,
        token_account_address: &Pubkey,
        action_id: u64,
    ) -> Result<Pubkey, ProgramError> {
        create_program_address(
            &[
                PROOF_ACCOUNT,
                token_account_address.as_ref(),
                &action_id.to_le_bytes(),
                &self.bump_seed(),
            ],
            &crate::id(),
        )
    }

    /// Find Proof account PDA
    pub fn find_pda(
        token_account_address: &Pubkey,
        action_id: u64,
        program_id: &Pubkey,
    ) -> (Pubkey, u8) {
        find_proof_pda(token_account_address, action_id, program_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{random_32_bytes, random_32_bytes_vec};
    use rstest::rstest;

    #[rstest]
    #[case(5u8, &random_32_bytes_vec(3))]
    #[case(u8::MAX, &random_32_bytes_vec(2))]
    fn test_proof_create(#[case] bump: u8, #[case] proof_data: &[ProofNode]) {
        let proof = Proof::new(proof_data, bump).expect("Should create proof");
        proof.validate().expect("Proof should be valid");
    }

    #[rstest]
    #[case(5u8, &random_32_bytes_vec(3))]
    #[case(u8::MAX, &random_32_bytes_vec(2))]
    fn test_proof_serialize_deserialize(#[case] bump: u8, #[case] proof_data: &[ProofNode]) {
        let proof = Proof::new(proof_data, bump).expect("Should create proof");

        let serialized = proof.to_bytes();
        assert_eq!(serialized.len(), proof.serialized_len());
        let deserialized = Proof::try_from_bytes(&serialized).expect("Should deserialize proof");

        assert_eq!(deserialized.data, proof_data);
        assert_eq!(deserialized.bump, bump);
    }

    #[rstest]
    #[case(5u8, &[[0u8; MERKLE_TREE_NODE_LEN], random_32_bytes(), random_32_bytes()], "Should not create proof with zero node")]
    #[case(u8::MAX, &[], "Should not create proof with empty data")]
    fn test_proof_should_not_create_invalid_proof(
        #[case] bump: u8,
        #[case] proof_data: &[ProofNode],
        #[case] description: &str,
    ) {
        let proof_error = Proof::new(proof_data, bump).expect_err(description);
        assert_eq!(proof_error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_proof_update_at_offset() {
        let bump = 10u8;
        let proof_data = random_32_bytes_vec(2);
        let mut proof = Proof::new(&proof_data, bump).expect("Should create proof");
        proof.validate().expect("Proof should be valid");

        let new_node = random_32_bytes();
        let offset = 0usize; // update first node
        proof
            .update_data_at_offset(new_node, offset)
            .expect("Should update node at offset 0");

        assert_eq!(proof.data[offset], new_node);
        assert_eq!(proof.data[1], proof_data[1]);
        assert_eq!(proof.data.len(), 2);
    }

    #[test]
    fn test_proof_should_not_create_proof_with_too_many_levels() {
        let bump = 5u8;

        // 33 levels should fail validation (exceeds MAX_PROOF_LEVELS)
        let proof_33_levels = random_32_bytes_vec(33);
        let proof_error = Proof::new(&proof_33_levels, bump)
            .expect_err("Proof with 33 levels should fail validation");
        assert_eq!(proof_error, ProgramError::InvalidAccountData);

        // 32 levels should succeed (at the limit)
        let proof_32_levels = random_32_bytes_vec(32);
        let result = Proof::new(&proof_32_levels, bump);
        assert!(
            result.is_ok(),
            "Proof with 32 levels should pass validation"
        );
    }

    #[test]
    fn test_proof_append_new_node() {
        let bump = 10u8;
        let proof_data = random_32_bytes_vec(2);
        let mut proof = Proof::new(&proof_data, bump).expect("Should create proof");
        proof.validate().expect("Proof should be valid");

        // Append new node
        let append_node = random_32_bytes();
        let append_offset = proof.data.len(); // append at end
        proof
            .update_data_at_offset(append_node, append_offset)
            .expect("Should append new node");
        assert_eq!(proof.data[append_offset], append_node);
        assert_eq!(proof.data.len(), 3);
    }
}

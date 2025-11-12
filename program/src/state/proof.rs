//! Receipt account state
use pinocchio::{
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{create_program_address, Pubkey},
    ProgramResult,
};
use shank::ShankAccount;

use crate::{
    constants::{seeds::PROOF_ACCOUNT, MERKLE_TREE_NODE_LEN},
    state::{
        AccountDeserialize, AccountSerialize, Discriminator, ProgramAccount,
        SecurityTokenDiscriminators,
    },
    utils::find_proof_pda,
};

type MerkleTreeNode = [u8; MERKLE_TREE_NODE_LEN];

#[repr(C)]
#[derive(Debug, ShankAccount)]
pub struct Proof {
    /// Bump seed for PDA
    bump: u8,
    /// Merkle proof data
    #[idl_type("Vec<[u8; 32]>")]
    data: Vec<MerkleTreeNode>,
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
        data.extend_from_slice(self.data.as_flattened());
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

        // Read proofs len (first 4 bytes)
        let proof_nodes_len = u32::from_le_bytes(
            data[offset..(offset + Self::VEC_LEN_PREFIX)]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;
        offset += Self::VEC_LEN_PREFIX;

        if data.len() < offset + (proof_nodes_len * MERKLE_TREE_NODE_LEN) {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut proof_data: Vec<MerkleTreeNode> = Vec::with_capacity(proof_nodes_len);

        for _ in 0..proof_nodes_len {
            let node_chunk =
                <MerkleTreeNode>::try_from(&data[offset..offset + MERKLE_TREE_NODE_LEN])
                    .map_err(|_| ProgramError::InvalidAccountData)?;

            proof_data.push(node_chunk);
            offset += MERKLE_TREE_NODE_LEN;
        }

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
    /// Minimum size without any data
    /// Discriminator (1 byte) + bump (1 byte) + vector length prefix (4 bytes)
    pub const VEC_LEN_PREFIX: usize = 4;
    pub const MIN_LEN: usize = 1 + 1 + Self::VEC_LEN_PREFIX;

    /// Calculate the actual size needed for serialization
    pub fn serialized_len(&self) -> usize {
        Self::MIN_LEN + (self.data.len() * MERKLE_TREE_NODE_LEN)
    }

    /// Create new Proof account
    pub fn new(data: &[MerkleTreeNode], bump: u8) -> Result<Self, ProgramError> {
        let proof = Self {
            data: data.to_vec(),
            bump,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Validate the proof data
    pub fn validate(&self) -> ProgramResult {
        if self.data.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        };

        let zero_proof_node = [0u8; MERKLE_TREE_NODE_LEN];
        self.data.iter().try_for_each(|node| {
            if node.eq(&zero_proof_node) {
                return Err(ProgramError::InvalidAccountData);
            }
            Ok(())
        })?;

        Ok(())
    }

    pub fn bump_seed(&self) -> [u8; 1] {
        [self.bump]
    }

    /// Get seeds for signing
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
    use crate::test_utils::random_pubkey;
    use rstest::rstest;

    #[rstest]
    #[case(5u8, &[random_pubkey(), random_pubkey(), random_pubkey()])]
    #[case(u8::MAX, &[random_pubkey(), random_pubkey()])]
    fn test_proof_create(#[case] bump: u8, #[case] proof_data: &[MerkleTreeNode]) {
        let proof = Proof::new(proof_data, bump).expect("Should create proof");
        proof.validate().expect("Proof should be valid");
    }

    #[rstest]
    #[case(5u8, &[random_pubkey(), random_pubkey(), random_pubkey()])]
    #[case(u8::MAX, &[random_pubkey(), random_pubkey()])]
    fn test_proof_serialize_deserialize(#[case] bump: u8, #[case] proof_data: &[MerkleTreeNode]) {
        let proof = Proof::new(proof_data, bump).expect("Should create proof");

        let serialized = proof.to_bytes();
        assert_eq!(serialized.len(), proof.serialized_len());
        let deserialized = Proof::try_from_bytes(&serialized).expect("Should deserialize proof");

        assert_eq!(deserialized.data, proof_data);
        assert_eq!(deserialized.bump, bump);
    }

    #[rstest]
    #[case(5u8, &[[0u8; MERKLE_TREE_NODE_LEN], random_pubkey(), random_pubkey()], "Should not create proof with zero node")]
    #[case(u8::MAX, &[], "Should not create proof with empty data")]
    fn test_proof_should_not_create_invalid_proof(
        #[case] bump: u8,
        #[case] proof_data: &[MerkleTreeNode],
        #[case] description: &str,
    ) {
        let proof_error = Proof::new(proof_data, bump).expect_err(description);
        assert_eq!(proof_error, ProgramError::InvalidAccountData);
    }
}

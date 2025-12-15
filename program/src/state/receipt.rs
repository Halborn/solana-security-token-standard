//! Receipt account state
use pinocchio::{
    account_info::AccountInfo, instruction::Seed, program_error::ProgramError, pubkey::Pubkey,
    ProgramResult,
};

use crate::{
    constants::seeds::RECEIPT_ACCOUNT,
    merkle_tree_utils::ProofData,
    state::{
        AccountDeserialize, AccountSerialize, Discriminator, ProgramAccount,
        SecurityTokenDiscriminators,
    },
    utils::{find_claim_receipt_pda, find_common_action_receipt_pda, hash_from_proof_data},
};

/// Receipt account structure
/// To follow consistency with other account types, we define Receipt using common pattern, even though it stores only discriminator
#[repr(C)]
#[derive(Debug)]
pub struct Receipt {}

impl Discriminator for Receipt {
    const DISCRIMINATOR: u8 = SecurityTokenDiscriminators::ReceiptDiscriminator as u8;
}

impl AccountSerialize for Receipt {
    fn to_bytes_inner(&self) -> Vec<u8> {
        vec![]
    }
}

impl AccountDeserialize for Receipt {
    fn try_from_bytes_inner(_data: &[u8]) -> Result<Self, ProgramError> {
        Ok(Self {})
    }
}

impl ProgramAccount for Receipt {
    fn space(&self) -> u64 {
        Self::LEN as u64
    }
}

impl Receipt {
    /// Discriminator
    pub const LEN: usize = 1;

    pub fn new() -> Result<Self, ProgramError> {
        Ok(Self {})
    }

    pub fn from_account_info(account_info: &AccountInfo) -> Result<Receipt, ProgramError> {
        if account_info.data_len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if !account_info.is_owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        let data_ref = account_info.try_borrow_data()?;
        let receipt = Self::try_from_bytes(&data_ref)?;
        Ok(receipt)
    }

    /// Issue new Receipt
    /// Create PDA account and write data into it
    pub fn issue(
        receipt_account: &AccountInfo,
        payer: &AccountInfo,
        seeds: &[Seed],
    ) -> ProgramResult {
        let receipt = Receipt::new()?;
        receipt.init(payer, receipt_account, seeds)?;
        receipt.write_data(receipt_account)?;

        Ok(())
    }

    /// Seeds for common operation connected to action id and mint (e.g. Split, Convert)
    pub fn common_action_seeds<'a>(
        mint: &'a Pubkey,
        action_id_seed: &'a [u8],
        bump_seed: &'a [u8; 1],
    ) -> [Seed<'a>; 4] {
        [
            Seed::from(RECEIPT_ACCOUNT),
            Seed::from(mint.as_ref()),
            Seed::from(action_id_seed),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Find receipt PDA for common operation connected to action id and mint (e.g. Split, Convert)
    pub fn find_common_action_pda(mint: &Pubkey, action_id: u64) -> (Pubkey, u8) {
        find_common_action_receipt_pda(mint, action_id, &crate::id())
    }

    /// Seeds for Claim operation
    pub fn claim_action_seeds<'a>(
        mint: &'a Pubkey,
        token_account: &'a Pubkey,
        action_id_seed: &'a [u8],
        proof_hash_seed: &'a [u8; 32],
        bump_seed: &'a [u8; 1],
    ) -> [Seed<'a>; 6] {
        [
            Seed::from(RECEIPT_ACCOUNT),
            Seed::from(mint.as_ref()),
            Seed::from(token_account.as_ref()),
            Seed::from(action_id_seed),
            Seed::from(proof_hash_seed.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Helper to compute proof hash for claim_action_seeds
    pub fn proof_seed(proof: &ProofData) -> [u8; 32] {
        hash_from_proof_data(proof)
    }

    /// Find receipt PDA for Claim operation
    pub fn find_claim_action_pda(
        mint: &Pubkey,
        token_account: &Pubkey,
        action_id: u64,
        proof: &ProofData,
    ) -> (Pubkey, u8) {
        find_claim_receipt_pda(mint, token_account, action_id, proof, &crate::id())
    }
}

//! Receipt account state
use pinocchio::{
    account_info::AccountInfo, instruction::Seed, program_error::ProgramError, pubkey::Pubkey,
    ProgramResult,
};

use crate::{
    constants::seeds::RECEIPT_ACCOUNT,
    state::{
        AccountDeserialize, AccountSerialize, Discriminator, ProgramAccount,
        SecurityTokenDiscriminators,
    },
    utils::{find_claim_receipt_pda, find_common_action_receipt_pda},
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
        action_id_seed: &'a [u8],
        token_account: &'a Pubkey,
        proof_seed: &'a [u8],
        bump_seed: &'a [u8; 1],
    ) -> [Seed<'a>; 6] {
        [
            Seed::from(RECEIPT_ACCOUNT),
            Seed::from(mint.as_ref()),
            Seed::from(action_id_seed),
            Seed::from(token_account.as_ref()),
            Seed::from(proof_seed),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Find receipt PDA for Claim operation
    pub fn find_claim_action_pda(
        mint: &Pubkey,
        action_id: u64,
        token_account: &Pubkey,
        proof: &[u8; 32],
    ) -> (Pubkey, u8) {
        find_claim_receipt_pda(mint, action_id, token_account, proof, &crate::id())
    }
}

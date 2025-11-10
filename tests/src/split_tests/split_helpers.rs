use security_token_client::{
    instructions::{Split, SplitInstructionArgs, SPLIT_DISCRIMINATOR},
    types::SplitArgs,
};
use solana_program_test::*;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use crate::helpers::{create_verification_config, send_tx};

/// Build and send Split instruction
pub async fn execute_split(
    banks_client: &BanksClient,
    verification_config_pda: Pubkey,
    mint: Pubkey,
    mint_authority_pda: Pubkey,
    permanent_delegate_pda: Pubkey,
    rate_pda: Pubkey,
    receipt_pda: Pubkey,
    token_account: Pubkey,
    payer: &Keypair,
    action_id: u64,
) -> Result<(), BanksClientError> {
    let split_args = SplitArgs { action_id };
    let split_ix = Split {
        verification_config: verification_config_pda,
        instructions_sysvar: solana_program::sysvar::instructions::id(),
        mint: mint,
        mint_account: mint,
        mint_authority: mint_authority_pda,
        permanent_delegate: permanent_delegate_pda,
        rate_account: rate_pda,
        receipt_account: receipt_pda,
        token_account,
        token_program: Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
        system_program: solana_program::system_program::id(),
        payer: payer.pubkey(),
    }
    .instruction(SplitInstructionArgs { split_args });

    send_tx(banks_client, vec![split_ix], &payer.pubkey(), vec![payer]).await
}

pub fn uniq_pubkey() -> Pubkey {
    Pubkey::new_unique()
}

pub async fn create_split_verification_config(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
    owner: Option<&Keypair>,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        SPLIT_DISCRIMINATOR,
        program_addresses,
        owner,
    )
    .await
}

use security_token_client::{
    instructions::{Split, SplitInstructionArgs, MINT_DISCRIMINATOR, SPLIT_DISCRIMINATOR},
    types::SplitArgs,
};
use solana_program_test::*;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use crate::helpers::{
    assert_transaction_success, find_verification_config_pda,
    initialize_verification_config_for_payer, send_tx,
};

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

pub fn find_split_verification_config_pda(mint: Pubkey) -> (Pubkey, u8) {
    find_verification_config_pda(mint, SPLIT_DISCRIMINATOR)
}

pub async fn create_verification_config(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    instruction_discriminator: u8,
    program_addresses: Vec<Pubkey>,
    owner: Option<&Keypair>,
) -> Pubkey {
    let mint_pubkey = mint_keypair.pubkey();
    let (verification_config_pda, _vc_bump) =
        find_verification_config_pda(mint_pubkey, instruction_discriminator);

    let init_vc_args = security_token_client::types::InitializeVerificationConfigArgs {
        instruction_discriminator,
        program_addresses,
        cpi_mode: false,
    };
    let payer = owner.unwrap_or(&context.payer);
    let result = initialize_verification_config_for_payer(
        &context.banks_client,
        &payer,
        mint_keypair,
        mint_authority_pda,
        verification_config_pda,
        &init_vc_args,
    )
    .await;

    assert_transaction_success(result);
    verification_config_pda
}

pub async fn create_split_verification_config(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        SPLIT_DISCRIMINATOR,
        program_addresses,
        None,
    )
    .await
}

pub async fn create_mint_verification_config(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        MINT_DISCRIMINATOR,
        program_addresses,
        None,
    )
    .await
}

pub async fn create_mint_verification_config_for_owner(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
    owner: &Keypair,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        MINT_DISCRIMINATOR,
        program_addresses,
        Some(owner),
    )
    .await
}

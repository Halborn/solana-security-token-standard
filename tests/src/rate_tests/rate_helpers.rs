use security_token_client::{
    instructions::{
        CloseRateAccount, CloseRateAccountInstructionArgs, CreateRateAccount,
        CreateRateAccountInstructionArgs, UpdateRateAccount, UpdateRateAccountInstructionArgs,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{CloseRateArgs, CreateRateArgs, InitializeMintArgs, MintArgs, UpdateRateArgs},
};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::helpers::{
    find_mint_authority_pda, find_mint_freeze_authority_pda, initialize_mint_for_creator, send_tx,
};

pub async fn create_security_token_mint(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &solana_sdk::signature::Keypair,
    mint_creator: Option<&Keypair>,
    decimals: u8,
) -> (Pubkey, Pubkey, Pubkey) {
    let spl_token_2022_program =
        Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

    let payer = mint_creator.unwrap_or(&context.payer).insecure_clone();
    let mint_authority = payer.pubkey();

    let (mint_authority_pda, _bump) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &mint_authority);

    let (freeze_authority_pda, _bump) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals,
            mint_authority: mint_authority.clone(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
    };

    initialize_mint_for_creator(
        context,
        &mint_keypair,
        mint_authority_pda,
        &payer,
        &mint_args,
    )
    .await;

    (
        mint_authority_pda,
        freeze_authority_pda,
        spl_token_2022_program,
    )
}

pub async fn create_rate_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    mint_from: Pubkey,
    mint_to: Pubkey,
    create_rate_args: CreateRateArgs,
    payer: Option<&Keypair>,
) -> (Pubkey, Result<(), BanksClientError>) {
    let (rate_pda, _bump) = find_rate_pda(create_rate_args.action_id, &mint_from, &mint_to);

    let payer_keypair = match payer {
        Some(p) => p,
        None => &context.payer,
    };
    let payer_pubkey = payer_keypair.pubkey();

    let create_rate_ix = CreateRateAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        rate_account: rate_pda,
        mint_from,
        mint_to,
        payer: payer_pubkey,
        system_program: solana_system_interface::program::ID,
    }
    .instruction(CreateRateAccountInstructionArgs { create_rate_args });

    let result = send_tx(
        &context.banks_client,
        vec![create_rate_ix],
        &payer_pubkey,
        vec![&payer_keypair],
    )
    .await;

    (rate_pda, result)
}

pub async fn close_rate_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    mint_from: Pubkey,
    mint_to: Pubkey,
    close_rate_args: CloseRateArgs,
) -> Result<(), BanksClientError> {
    let (rate_pda, _bump) = find_rate_pda(close_rate_args.action_id, &mint_from, &mint_to);

    let close_rate_ix = CloseRateAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        rate_account: rate_pda,
        mint_from,
        mint_to,
        destination: context.payer.pubkey(),
    }
    .instruction(CloseRateAccountInstructionArgs { close_rate_args });

    let payer = &context.payer;
    send_tx(
        &context.banks_client,
        vec![close_rate_ix],
        &payer.pubkey(),
        vec![&payer],
    )
    .await
}

pub async fn update_rate_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    mint_from: Pubkey,
    mint_to: Pubkey,
    update_rate_args: UpdateRateArgs,
) -> Result<(), BanksClientError> {
    let (rate_pda, _bump) = find_rate_pda(update_rate_args.action_id, &mint_from, &mint_to);

    let update_rate_ix = UpdateRateAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        rate_account: rate_pda,
        mint_from,
        mint_to,
    }
    .instruction(UpdateRateAccountInstructionArgs { update_rate_args });

    let payer = &context.payer;
    send_tx(
        &context.banks_client,
        vec![update_rate_ix],
        &payer.pubkey(),
        vec![&payer],
    )
    .await
}

pub fn find_rate_pda(action_id: u64, mint_pubkey1: &Pubkey, mint_pubkey2: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"rate",
            action_id.to_le_bytes().as_ref(),
            mint_pubkey1.as_ref(),
            mint_pubkey2.as_ref(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

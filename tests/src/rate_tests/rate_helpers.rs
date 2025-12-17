use security_token_client::{
    instructions::{
        CloseRateAccount, CloseRateAccountInstructionArgs, CreateRateAccount,
        CreateRateAccountInstructionArgs, UpdateRateAccount, UpdateRateAccountInstructionArgs,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{CloseRateArgs, CreateRateArgs, Rounding, UpdateRateArgs},
};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::{
    program_error::ProgramError,
    signature::{Keypair, Signer},
};

use crate::helpers::{find_rate_pda, send_tx};

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
    destination: Option<&Keypair>,
    close_rate_args: CloseRateArgs,
) -> Result<(), BanksClientError> {
    let (rate_pda, _bump) = find_rate_pda(close_rate_args.action_id, &mint_from, &mint_to);

    let destination_pubkey = destination.map_or(context.payer.pubkey(), |d| d.pubkey());
    let destination_keypair = destination.unwrap_or(&context.payer);

    let close_rate_ix = CloseRateAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        rate_account: rate_pda,
        mint_from,
        mint_to,
        destination: destination_pubkey,
    }
    .instruction(CloseRateAccountInstructionArgs { close_rate_args });

    send_tx(
        &context.banks_client,
        vec![close_rate_ix],
        &destination_pubkey,
        vec![&destination_keypair],
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

pub fn calculate_rate_amount(
    numerator: u8,
    denominator: u8,
    rounding: u8,
    amount: u64,
) -> Result<u64, ProgramError> {
    let into_rounding_enum = match rounding {
        0 => Rounding::Down,
        1 => Rounding::Up,
        _ => return Err(ProgramError::InvalidArgument),
    };
    match into_rounding_enum {
        Rounding::Up => {
            let result = amount
                .checked_mul(numerator as u64)
                .ok_or(ProgramError::ArithmeticOverflow)?
                .div_ceil(denominator as u64);
            Ok(result)
        }
        Rounding::Down => {
            let result = amount
                .checked_mul(numerator as u64)
                .ok_or(ProgramError::ArithmeticOverflow)?
                .checked_div(denominator as u64)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            Ok(result)
        }
    }
}

use security_token_client::{instructions::{CreateRateAccount, CreateRateAccountInstructionArgs}, programs::SECURITY_TOKEN_PROGRAM_ID, types::{CreateRateArgs, InitializeMintArgs, MintArgs}};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signer;

use crate::helpers::{initialize_mint};

pub async fn create_security_token_mint(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &solana_sdk::signature::Keypair,
    decimals: u8,
) -> (Pubkey, Pubkey, Pubkey) {
    let spl_token_2022_program =
        Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
    };
    initialize_mint(&mint_keypair, context, mint_authority_pda, &mint_args).await;

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
) -> (Pubkey, Result<(), BanksClientError>) {
    let (rate_pda, _bump) = find_rate_pda(
        create_rate_args.action_id,
        &mint_from,
        &mint_to,
    );

    let create_rate_ix = CreateRateAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        rate_account: rate_pda,
        mint_from: mint_from,
        mint_to: mint_to,
        payer: context.payer.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(CreateRateAccountInstructionArgs { create_rate_args });

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let create_rate_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[create_rate_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(create_rate_transaction)
        .await;

    (rate_pda, result)
}

pub fn find_rate_pda(
    action_id: u64,
    mint_pubkey1: &Pubkey,
    mint_pubkey2: &Pubkey,
) -> (Pubkey, u8) {
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
use borsh::BorshDeserialize;
use rstest::rstest;
use security_token_client::{accounts::Rate, instructions::{CreateRateAccount, CreateRateAccountInstructionArgs}, programs::SECURITY_TOKEN_PROGRAM_ID, types::{CreateRateArgs, InitializeMintArgs, MintArgs, RateArgs, Rounding}};
use security_token_program::state::SecurityTokenDiscriminators;
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Signer, Keypair};

use crate::helpers::{assert_transaction_success, initialize_mint, start_with_context};

async fn create_security_token_mint(
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

async fn create_rate_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    rate_mint_pubkey1: Pubkey,
    rate_mint_pubkey2: Pubkey,
    create_rate_args: CreateRateArgs,
) -> (Pubkey, Result<(), BanksClientError>) {
    let (rate_pda, _bump) = find_rate_pda(
        create_rate_args.action_id,
        &rate_mint_pubkey1,
        &rate_mint_pubkey2,
    );

    let create_rate_ix = CreateRateAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        rate_account: rate_pda,
        rate_mint_account1: rate_mint_pubkey1,
        rate_mint_account2: rate_mint_pubkey2,
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

fn find_rate_pda(
    action_id: u64,
    mint_pubkey1: &Pubkey,
    mint_pubkey2: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"security_token.accounts.rate",
            action_id.to_le_bytes().as_ref(),
            mint_pubkey1.as_ref(),
            mint_pubkey2.as_ref(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

#[tokio::test]
async fn test_create_rate_account_operation_split_mints() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &mint_keypair, decimals).await;

    // Setup verification config for CreateRateAccount
    // let verification_config_pda =
    //     create_verification_config(&mut context, &mint_keypair, mint_authority_pda)
    //         .await;

    // Create rate account for split operation (same mint)
    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    // Split operation (single mint)
    let rate_mint_pubkey = mint_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };

    let (rate_pda, result) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        rate_mint_pubkey,
        rate_mint_pubkey,
        create_rate_args
    ).await;
    assert_transaction_success(result);

    // Verify the rate account was created
    let rate_account = context
        .banks_client
        .get_account(rate_pda)
        .await
        .unwrap()
        .expect("Rate account should exist");

    let len = rate_account.data.len();
    println!("Rate account data length: {}", len);
    println!("Rate account data: {:?}", &rate_account.data);

    let rate = Rate::try_from_slice(&rate_account.data).expect("Should deserialize Rate state");

    assert_eq!(
        rate_account.owner, SECURITY_TOKEN_PROGRAM_ID,
        "Rate account should be owned by security token program"
    );

    // Verify account size
    assert_eq!(
        rate_account.data.len(),
        5,
        "Rate account should be 5 bytes (discriminator + rounding + numerator + denominator + bump)"
    );

    // Verify discriminator
    assert_eq!(
        rate.discriminator, SecurityTokenDiscriminators::RateDiscriminator as u8,
        "Rate account discriminator should match"
    );

    // Verify rate data
    assert_eq!(rate.rounding as u8, rounding, "Rounding should match");
    assert_eq!(rate.numerator, numerator, "Numerator should match");
    assert_eq!(rate.denominator, denominator, "Denominator should match");

    println!("✓ Test Case 1: Created rate account for split operation (same mint)");
}

#[tokio::test]
async fn test_create_rate_account_operation_conversion_mints() {
    let mut context = &mut start_with_context().await;

    let mint_keypair1 = Keypair::new();
    let mint_keypair2 = Keypair::new();
    let decimals = 6u8;

    // Conversion operation (different mints)
    let (mint_authority_pda1, _, _) = create_security_token_mint(&mut context, &mint_keypair1, decimals).await;
    let (_mint_authority_pda2, _, _) = create_security_token_mint(&mut context, &mint_keypair2, decimals).await;

    let action_id = 100u64;
    let rounding = Rounding::Down as u8;
    let numerator = 5u8;
    let denominator = 10u8;

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };

    let (rate_pda, result) = create_rate_account(
        context,
        mint_keypair1.pubkey(),
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_keypair1.pubkey(),
        mint_keypair2.pubkey(),
        create_rate_args
    ).await;
    assert_transaction_success(result);

    let rate_account = context
        .banks_client
        .get_account(rate_pda)
        .await
        .unwrap()
        .expect("Rate account should exist");

    let rate = Rate::try_from_slice(&rate_account.data).expect("Should deserialize Rate state");

    assert_eq!(rate.rounding as u8, rounding, "Rounding should match");
    assert_eq!(rate.numerator, numerator, "Numerator should match");
    assert_eq!(rate.denominator, denominator, "Denominator should match");
}

#[rstest]
#[case(0u64, 1u8, 5u8, 10u8, "Zero action_id should be invalid")]
#[case(1u64, 3u8, 5u8, 10u8, "Rounding enum (3u8) should be invalid")]
#[case(1u64, 0u8, 0u8, 10u8, "Zero numerator should be invalid")]
#[case(1u64, 0u8, 2u8, 0u8, "Zero denominator should be invalid")]
#[tokio::test]
async fn test_create_rate_account_invalid_operation(
    #[case] action_id: u64,
    #[case] rounding: u8,
    #[case] numerator: u8,
    #[case] denominator: u8,
    #[case] description: &str,
) {
    let mut context = &mut start_with_context().await;
    let mint_keypair = Keypair::new();
    let decimals = 9u8;

    let (mint_authority_pda, _, _) = create_security_token_mint(&mut context, &mint_keypair, decimals).await;

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };

    let (_rate_pda, result) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_keypair.pubkey(),
        mint_keypair.pubkey(),
        create_rate_args
    ).await;

    assert!(result.is_err(), "{}", description);
}

// TODO: test duplicate rate account creation
// TODO: test rate with both split and conversion mints creation
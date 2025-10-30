use borsh::BorshDeserialize;
use rstest::rstest;
use security_token_client::{
    accounts::Rate,
    instructions::{CreateRateAccount, CreateRateAccountInstructionArgs},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{CloseRateArgs, CreateRateArgs, RateArgs, Rounding},
};
use security_token_program::state::SecurityTokenDiscriminators;
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::{
    helpers::{assert_account_exists, assert_transaction_success, send_tx, start_with_context},
    rate_tests::rate_helpers::{
        close_rate_account, create_rate_account, create_security_token_mint, find_rate_pda,
    },
};

#[tokio::test]
async fn test_should_create_rate_account_operation_for_split_mints() {
    let mut context = &mut start_with_context().await;

    let mint_from_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    // Split operation (single mint)
    let mint_from = mint_from_keypair.pubkey();

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
        mint_from,
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from,
        mint_from,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);

    // Verify the rate account was created
    let rate_account = assert_account_exists(context, rate_pda, true)
        .await
        .unwrap();

    let len = rate_account.data.len();
    println!("Rate account data length: {}", len);
    println!("Rate account data: {:?}", &rate_account.data);

    let rate = Rate::try_from_slice(&rate_account.data).expect("Should deserialize Rate state");

    assert_eq!(
        rate_account.owner, SECURITY_TOKEN_PROGRAM_ID,
        "Rate account should be owned by security token program"
    );
    assert_eq!(
        rate_account.data.len(),
        5,
        "Rate account should be 5 bytes (discriminator + rounding + numerator + denominator + bump)"
    );
    assert_eq!(
        rate.discriminator,
        SecurityTokenDiscriminators::RateDiscriminator as u8,
        "Rate account discriminator should match"
    );

    // Verify rate data
    assert_eq!(rate.rounding as u8, rounding, "Rounding should match");
    assert_eq!(rate.numerator, numerator, "Numerator should match");
    assert_eq!(rate.denominator, denominator, "Denominator should match");
}

#[tokio::test]
async fn test_should_create_rate_account_operation_with_conversion_mints() {
    let mut context = &mut start_with_context().await;

    let mint_from_keypair = Keypair::new();
    let mint_to_keypair = Keypair::new();
    let decimals = 6u8;

    // Conversion operation (different mints)
    let (mint_authority_pda1, _, _) =
        create_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;
    let (_mint_authority_pda2, _, _) =
        create_security_token_mint(&mut context, &mint_to_keypair, None, decimals).await;

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
        mint_from_keypair.pubkey(),
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_from_keypair.pubkey(),
        mint_to_keypair.pubkey(),
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);
    let rate_account = assert_account_exists(context, rate_pda, true)
        .await
        .unwrap();

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
async fn test_should_fail_invalid_create_rate_account_instruction(
    #[case] action_id: u64,
    #[case] rounding: u8,
    #[case] numerator: u8,
    #[case] denominator: u8,
    #[case] description: &str,
) {
    let mut context = &mut start_with_context().await;
    let mint_keypair = Keypair::new();
    let decimals = 9u8;

    let (mint_authority_pda, _, _) =
        create_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

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
        create_rate_args,
        None,
    )
    .await;

    assert!(result.is_err(), "{}", description);
}

#[tokio::test]
async fn test_should_not_create_rate_account_twice() {
    let mut context = &mut start_with_context().await;

    let mint_from_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;

    let action_id = 42u64;
    let mint_from = mint_from_keypair.pubkey();
    let mint_to = mint_from.clone();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    let (rate_pda, result) = create_rate_account(
        context,
        mint_from,
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from,
        mint_to,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result);
    assert_account_exists(context, rate_pda, true).await;

    // Try creating the same Rate account again, should fail
    let (_, result) = create_rate_account(
        context,
        mint_from,
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from,
        mint_to,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not create the same Rate account again"
    );
}

#[tokio::test]
async fn test_should_create_both_split_and_conversion_rate_accounts() {
    let mut context = &mut start_with_context().await;

    let mint_from_keypair = Keypair::new();
    let mint_to_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda1, _, _) =
        create_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;
    let (_mint_authority_pda2, _, _) =
        create_security_token_mint(&mut context, &mint_to_keypair, None, decimals).await;

    let action_id = 42u64;
    let mint_from = mint_from_keypair.pubkey();
    let mint_to = mint_to_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    // Rate account for split (the same mint)
    let (rate_pda1, result1) = create_rate_account(
        context,
        mint_from,
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_from,
        mint_from,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result1);

    // Rate account for conversion (different mints)
    let (rate_pda2, result2) = create_rate_account(
        context,
        mint_from,
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_from,
        mint_to,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result2);

    assert_account_exists(context, rate_pda1, true).await;
    assert_account_exists(context, rate_pda2, true).await;
}

#[tokio::test]
async fn test_should_not_create_rate_account_for_not_initial_mint() {
    let mut context = &mut start_with_context().await;

    let initial_mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &initial_mint_keypair, None, decimals).await;

    // Try to create Rate account by providing second mint
    // Even though it belongs to the same payer, it is not the initial mint and tx should fail
    let second_mint_keypair = Keypair::new();
    create_security_token_mint(&mut context, &second_mint_keypair, None, decimals).await;
    let mint_from = second_mint_keypair.pubkey();
    let mint_to = mint_from.clone();

    let create_rate_args = CreateRateArgs {
        action_id: 42u64,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    let (_, result) = create_rate_account(
        context,
        initial_mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from,
        mint_to,
        create_rate_args,
        None,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not create Rate account for not initial mint"
    );
}

#[tokio::test]
async fn test_should_not_create_invalid_pda_rate_account() {
    let mut context = &mut start_with_context().await;

    let initial_mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &initial_mint_keypair, None, decimals).await;

    let create_rate_args = CreateRateArgs {
        action_id: 42u64,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    let invalid_rate_pda = Pubkey::new_unique();
    let payer_pubkey = context.payer.pubkey();

    let create_rate_ix = CreateRateAccount {
        mint: initial_mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        instructions_sysvar_or_creator: payer_pubkey,
        rate_account: invalid_rate_pda,
        mint_from: initial_mint_keypair.pubkey(),
        mint_to: initial_mint_keypair.pubkey(),
        payer: payer_pubkey,
        system_program: solana_system_interface::program::ID,
    }
    .instruction(CreateRateAccountInstructionArgs { create_rate_args });

    let result = send_tx(
        &context.banks_client,
        vec![create_rate_ix],
        &payer_pubkey,
        vec![&context.payer],
    )
    .await;

    assert!(
        result.is_err(),
        "Should not create Rate account for wrong PDA"
    );
}

#[tokio::test]
async fn test_should_not_create_rate_account_with_invalid_system_program_id() {
    let mut context = &mut start_with_context().await;

    let initial_mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &initial_mint_keypair, None, decimals).await;

    let create_rate_args = CreateRateArgs {
        action_id: 42u64,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    let (rate_pda, _bump) = find_rate_pda(
        create_rate_args.action_id,
        &initial_mint_keypair.pubkey(),
        &initial_mint_keypair.pubkey(),
    );

    let payer_pubkey = context.payer.pubkey();
    let invalid_program_id = Pubkey::new_unique();

    let create_rate_ix = CreateRateAccount {
        mint: initial_mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        instructions_sysvar_or_creator: payer_pubkey,
        rate_account: rate_pda,
        mint_from: initial_mint_keypair.pubkey(),
        mint_to: initial_mint_keypair.pubkey(),
        payer: payer_pubkey,
        system_program: invalid_program_id,
    }
    .instruction(CreateRateAccountInstructionArgs { create_rate_args });

    let result = send_tx(
        &context.banks_client,
        vec![create_rate_ix],
        &payer_pubkey,
        vec![&context.payer],
    )
    .await;

    assert!(
        result.is_err(),
        "Should not create Rate account with invalid system program id"
    );
}

#[tokio::test]
async fn test_should_re_create_closed_rate_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

    let action_id = 42u64;
    let rate_mint_pubkey = mint_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    let (rate_pda, result) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        rate_mint_pubkey,
        rate_mint_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result);
    assert_account_exists(context, rate_pda, true).await;

    // Close and then try to re-create it
    let result = close_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        rate_mint_pubkey,
        rate_mint_pubkey,
        CloseRateArgs { action_id },
    )
    .await;
    assert_transaction_success(result);
    assert_account_exists(context, rate_pda, false).await;

    // Create Rate account with the same params again
    let (rate_pda, result) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        rate_mint_pubkey,
        rate_mint_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result);
    assert_account_exists(context, rate_pda, true).await;
}

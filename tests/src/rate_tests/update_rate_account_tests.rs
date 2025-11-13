use borsh::BorshDeserialize;
use rstest::rstest;
use security_token_client::{
    accounts::Rate,
    types::{CloseRateArgs, CreateRateArgs, RateArgs, Rounding, UpdateRateArgs},
};
use solana_program_test::*;
use solana_sdk::{
    native_token::sol_str_to_lamports,
    signature::{Keypair, Signer},
};

use crate::{
    helpers::{assert_account_exists, create_minimal_security_token_mint, find_rate_pda},
    rate_tests::rate_helpers::{close_rate_account, create_rate_account},
};
use crate::{
    helpers::{
        assert_transaction_success, find_mint_authority_pda, start_with_context,
        start_with_context_and_accounts,
    },
    rate_tests::rate_helpers::update_rate_account,
};

#[tokio::test]
async fn test_should_update_existing_rate_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_keypair.pubkey();
    let mint_to_pubkey = mint_from_pubkey.clone();

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
        mint_from_pubkey,
        mint_to_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);

    let new_rounding = Rounding::Down as u8;
    let new_numerator = 4u8;
    let new_denominator = 3u8;

    let update_rate_args = UpdateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: new_rounding,
            numerator: new_numerator,
            denominator: new_denominator,
        },
    };

    let result = update_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        update_rate_args,
    )
    .await;

    assert_transaction_success(result);

    // Verify updated state
    let rate_account = Rate::try_from_slice(
        &context
            .banks_client
            .get_account(rate_pda)
            .await
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap();

    assert_eq!(
        rate_account.rounding as u8, new_rounding,
        "Rounding should match"
    );
    assert_eq!(
        rate_account.numerator, new_numerator,
        "Numerator should match"
    );
    assert_eq!(
        rate_account.denominator, new_denominator,
        "Denominator should match"
    );
}

#[rstest]
#[case(1u64, 3u8, 5u8, 10u8, "Invalid rounding value")]
#[case(1u64, 0u8, 0u8, 10u8, "Zero numerator should be invalid")]
#[case(1u64, 0u8, 5u8, 0u8, "Zero denominator should be invalid")]
#[tokio::test]
async fn test_should_fail_invalid_update_rate_account(
    #[case] action_id: u64,
    #[case] rounding: u8,
    #[case] numerator: u8,
    #[case] denominator: u8,
    #[case] description: &str,
) {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, decimals).await;
    let mint_from_pubkey = mint_keypair.pubkey();
    let mint_to_pubkey = mint_from_pubkey.clone();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Up as u8,
            numerator: 3u8,
            denominator: 2u8,
        },
    };

    let (_rate_pda, result) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);

    // Try update with invalid args
    let update_rate_args = UpdateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };

    let result = update_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        update_rate_args,
    )
    .await;

    assert!(result.is_err(), "{}", description);
}

#[tokio::test]
async fn test_should_not_update_not_owned_rate_account() {
    let owner2 = Keypair::new();
    let owner2_balance = sol_str_to_lamports("1").unwrap();
    let additional_accounts = vec![(&owner2, owner2_balance)];
    let mut context = &mut start_with_context_and_accounts(additional_accounts).await;

    // First mint, context.payer is the authority
    let mint_from_keypair = Keypair::new();
    let mint_creator1 = context.payer.pubkey();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_minimal_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_from_keypair.pubkey();
    let mint_to_pubkey = mint_from_pubkey.clone();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };

    let (_, result) = create_rate_account(
        context,
        mint_from_keypair.pubkey(),
        mint_authority_pda,
        mint_creator1,
        mint_from_pubkey,
        mint_to_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);

    // Verify owner2 has been created
    let bal = context
        .banks_client
        .get_account(owner2.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(bal, owner2_balance, "Owner2 should have enough balance");

    // Second mint, owner2 is the authority
    let mint_keypair2 = Keypair::new();
    let mint_creator2 = owner2.pubkey();

    let decimals = 6u8;
    let (mint_authority_pda2, _, _) =
        create_minimal_security_token_mint(&mut context, &mint_keypair2, Some(&owner2), decimals)
            .await;

    let action_id = 42u64;
    let rounding = Rounding::Down as u8;
    let numerator = 4u8;
    let denominator = 3u8;

    let create_rate_args2 = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };

    let (_rate_pda, result) = create_rate_account(
        context,
        mint_keypair2.pubkey(),
        mint_authority_pda2,
        mint_creator2,
        mint_keypair2.pubkey(),
        mint_keypair2.pubkey(),
        create_rate_args2,
        Some(&owner2),
    )
    .await;
    assert_transaction_success(result);

    let update_rate_args = UpdateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Down as u8,
            numerator: 5,
            denominator: 20,
        },
    };

    // mint_creator1 (context.payer) tries to update Rate account of mint_keypair2 created mint_creator2
    let result = update_rate_account(
        context,
        mint_keypair2.pubkey(),
        mint_authority_pda2,
        mint_creator1,
        mint_keypair2.pubkey(),
        mint_keypair2.pubkey(),
        update_rate_args.clone(),
    )
    .await;
    assert!(result.is_err(), "Should not update not owned Rate account");

    let invalid_mint_authority_pda =
        find_mint_authority_pda(&mint_keypair2.pubkey(), &mint_creator1).0;
    let result = update_rate_account(
        context,
        mint_keypair2.pubkey(),
        invalid_mint_authority_pda,
        mint_creator1,
        mint_keypair2.pubkey(),
        mint_keypair2.pubkey(),
        update_rate_args.clone(),
    )
    .await;
    assert!(result.is_err(), "Should not update not owned Rate account");
}

#[tokio::test]
async fn test_should_not_update_not_existed_rate_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_creator = context.payer.pubkey().clone();
    let mint_from_pubkey = mint_keypair.pubkey();
    let mint_to_pubkey = mint_from_pubkey.clone();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda, _spl_token_2022_program) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

    // Random Rate account
    let action_id = 123u64;
    let (rate_pda, _bump) = find_rate_pda(action_id, &mint_from_pubkey, &mint_to_pubkey);

    // Rate account should not exist
    assert_account_exists(context, rate_pda, false).await;

    let update_rate_args = UpdateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Down as u8,
            numerator: 5,
            denominator: 20,
        },
    };

    let result = update_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        mint_creator,
        mint_from_pubkey,
        mint_to_pubkey,
        update_rate_args.clone(),
    )
    .await;
    assert!(
        result.is_err(),
        "Should not update not existed Rate account"
    );
}

#[tokio::test]
async fn test_should_not_update_closed_rate_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_creator = context.payer.pubkey().clone();
    let mint_from_pubkey = mint_keypair.pubkey();
    let mint_to_pubkey = mint_keypair.pubkey();
    let decimals = 6u8;
    let (mint_authority_pda, _, _) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Down as u8;
    let numerator = 4u8;
    let denominator = 3u8;

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
        mint_creator,
        mint_from_pubkey,
        mint_to_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);

    // Close and then try to update it
    let result = close_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        CloseRateArgs { action_id },
    )
    .await;
    assert_transaction_success(result);
    assert_account_exists(context, rate_pda, false).await;

    let update_rate_args = UpdateRateArgs {
        action_id,
        rate: RateArgs {
            rounding: Rounding::Down as u8,
            numerator: 5,
            denominator: 20,
        },
    };

    let result = update_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        mint_creator,
        mint_from_pubkey,
        mint_to_pubkey,
        update_rate_args.clone(),
    )
    .await;
    assert!(result.is_err(), "Should not update closed Rate account");
}

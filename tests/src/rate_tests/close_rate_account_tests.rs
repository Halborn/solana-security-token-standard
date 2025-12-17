use security_token_client::types::{CloseRateArgs, CreateRateArgs, RateConfig, Rounding};
use solana_program_test::*;
use solana_sdk::{
    native_token::sol_str_to_lamports,
    signature::{Keypair, Signer},
};

use crate::{
    helpers::{
        assert_account_exists, assert_transaction_success, create_minimal_security_token_mint,
        get_balance, start_with_context, start_with_context_and_accounts, TX_FEE,
    },
    rate_tests::rate_helpers::{close_rate_account, create_rate_account},
};

#[tokio::test]
async fn test_should_close_rate_account() {
    let mut context = &mut start_with_context().await;

    let mint_from_keypair = Keypair::new();
    let mint_to_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda_from, _) =
        create_minimal_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;
    let (mint_authority_pda_to, _) =
        create_minimal_security_token_mint(&mut context, &mint_to_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_from_keypair.pubkey();
    let mint_to_pubkey = mint_to_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateConfig {
            rounding,
            numerator,
            denominator,
        },
    };

    // For split (same mint)
    let (rate_pda1, result1) = create_rate_account(
        context,
        mint_from_keypair.pubkey(),
        mint_authority_pda_from,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result1);

    // For conversion (different mints)
    let (rate_pda2, result2) = create_rate_account(
        context,
        mint_to_keypair.pubkey(),
        mint_authority_pda_to,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result2);

    let rate_account1 = assert_account_exists(context, rate_pda1, true)
        .await
        .unwrap();
    let rate_account2 = assert_account_exists(context, rate_pda2, true)
        .await
        .unwrap();

    let payer_balance_before = get_balance(&context.banks_client, context.payer.pubkey()).await;

    // Close Rate account 1
    let result = close_rate_account(
        context,
        mint_from_keypair.pubkey(),
        mint_authority_pda_from,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        None,
        CloseRateArgs { action_id },
    )
    .await;
    assert_transaction_success(result);

    assert_account_exists(context, rate_pda1, false).await;
    assert_account_exists(context, rate_pda2, true).await;

    // Check payer received rent lamports from closed account
    let payer_balance_after_close1 =
        get_balance(&context.banks_client, context.payer.pubkey()).await;

    let rent_refund1 = payer_balance_after_close1 - payer_balance_before + TX_FEE;
    let rate_account_rent1 = rate_account1.lamports;
    assert_eq!(
        rent_refund1, rate_account_rent1,
        "Payer should receive rent lamports from closed Rate account 1"
    );

    // Close Rate account 2
    let result = close_rate_account(
        context,
        mint_to_keypair.pubkey(),
        mint_authority_pda_to,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        None,
        CloseRateArgs { action_id },
    )
    .await;
    assert_transaction_success(result);

    assert_account_exists(context, rate_pda1, false).await;
    assert_account_exists(context, rate_pda2, false).await;

    let payer_balance_after_close2 =
        get_balance(&context.banks_client, context.payer.pubkey()).await;

    let rent_refund2 = payer_balance_after_close2 - payer_balance_after_close1 + TX_FEE;
    let rate_account_rent2 = rate_account2.lamports;
    assert_eq!(
        rent_refund2, rate_account_rent2,
        "Payer should receive rent lamports from closed Rate account 2"
    );

    // Try closing already closed Rate account
    let result = close_rate_account(
        context,
        mint_from_keypair.pubkey(),
        mint_authority_pda_from,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        None,
        CloseRateArgs { action_id },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close already closed Rate account"
    );
}

#[tokio::test]
async fn test_should_not_close_not_owned_rate_account() {
    let payer2 = Keypair::new();
    let payer2_balance = sol_str_to_lamports("2").unwrap();
    let additional_accounts = vec![(&payer2, payer2_balance)];
    let mut context = &mut start_with_context_and_accounts(additional_accounts).await;

    // context.payer is the creator for mint1
    let mint_from_keypair = Keypair::new();
    let mint_creator1 = context.payer.pubkey();
    let decimals = 6u8;
    let (mint_authority_pda1, _) =
        create_minimal_security_token_mint(&mut context, &mint_from_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_from_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateConfig {
            rounding,
            numerator,
            denominator,
        },
    };

    let (_, result) = create_rate_account(
        context,
        mint_from_keypair.pubkey(),
        mint_authority_pda1,
        mint_creator1,
        mint_from_pubkey,
        mint_from_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(result);

    // Verify payer2 has been created
    let bal = context
        .banks_client
        .get_account(payer2.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(bal, payer2_balance, "Payer2 should have enough balance");

    // payer2 is the creator for mint2
    let mint_to_keypair = Keypair::new();
    let mint_creator2 = payer2.pubkey();

    let decimals = 6u8;
    let (mint_authority_pda2, _) =
        create_minimal_security_token_mint(&mut context, &mint_to_keypair, Some(&payer2), decimals)
            .await;

    let create_rate_args2 = CreateRateArgs {
        action_id,
        rate: RateConfig {
            rounding,
            numerator,
            denominator,
        },
    };
    let mint_to_pubkey = mint_to_keypair.pubkey();

    let (_rate_pda, result) = create_rate_account(
        context,
        mint_to_keypair.pubkey(),
        mint_authority_pda2,
        mint_creator2,
        mint_to_pubkey,
        mint_to_pubkey,
        create_rate_args2,
        Some(&payer2),
    )
    .await;
    assert_transaction_success(result);

    // context.payer tries to close payer2 Rate account
    let result = close_rate_account(
        context,
        mint_to_keypair.pubkey(),
        mint_authority_pda2,
        context.payer.pubkey(),
        mint_to_pubkey,
        mint_to_pubkey,
        None,
        CloseRateArgs { action_id },
    )
    .await;
    assert!(result.is_err(), "Should not close not owned Rate account");
    // Try different invalid variations
    let result = close_rate_account(
        context,
        mint_to_keypair.pubkey(),
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_to_pubkey,
        mint_to_pubkey,
        None,
        CloseRateArgs { action_id },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close Rate account with invalid accounts"
    );
    let result = close_rate_account(
        context,
        mint_to_keypair.pubkey(),
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        None,
        CloseRateArgs { action_id },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close Rate account with invalid accounts"
    );
    let result = close_rate_account(
        context,
        mint_from_keypair.pubkey(),
        mint_authority_pda1,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        None,
        CloseRateArgs { action_id: 999u64 },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close Rate account with invalid action_id"
    );
}

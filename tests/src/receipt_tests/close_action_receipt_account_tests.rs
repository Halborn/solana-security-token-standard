use security_token_client::types::{CloseActionReceiptArgs, CreateRateArgs, RateConfig, Rounding};
use solana_program_test::*;
use solana_sdk::{
    native_token::sol_str_to_lamports,
    signature::{Keypair, Signer},
};

use crate::{
    convert_tests::convert_helpers::{create_convert_verification_config, execute_convert},
    helpers::{
        assert_account_exists, assert_transaction_failure, assert_transaction_success,
        create_minimal_security_token_mint, create_mint_verification_config, create_spl_account,
        create_token_account_and_mint_tokens, find_permanent_delegate_pda, from_ui_amount,
        get_balance, mint_tokens_to, start_with_context, start_with_context_and_accounts, TX_FEE,
    },
    rate_tests::rate_helpers::create_rate_account,
    receipt_tests::receipt_helpers::{
        close_action_receipt_account, find_common_action_receipt_pda,
    },
    split_tests::split_helpers::{create_split_verification_config, execute_split},
};

#[tokio::test]
async fn test_should_close_action_receipt_account_after_split() {
    let mut context = &mut start_with_context().await;

    let mint_creator = context.payer.insecure_clone();
    let mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_keypair.pubkey();
    let _mint_to_pubkey = mint_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateConfig {
            rounding,
            numerator,
            denominator,
        },
    };

    // For split (same mint)
    let (rate_pda, result1) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result1);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda, _) = find_permanent_delegate_pda(&mint_keypair.pubkey());
    let (receipt_pda, _) = find_common_action_receipt_pda(&mint_from_pubkey, action_id);

    assert_account_exists(context, rate_pda, true)
        .await
        .unwrap();

    let split_verification_config_pda = create_split_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        None,
    )
    .await;

    let mint_verification_config_pda = create_mint_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey = create_spl_account(context, &mint_keypair, &mint_creator).await;

    let amount = from_ui_amount(1000, decimals);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        mint_from_pubkey,
        token_account_pubkey.clone(),
        mint_authority_pda.clone(),
        mint_verification_config_pda.clone(),
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Execute split
    let split_result = execute_split(
        &context.banks_client,
        split_verification_config_pda,
        mint_from_pubkey,
        mint_authority_pda,
        permanent_delegate_pda,
        rate_pda,
        receipt_pda,
        token_account_pubkey,
        &mint_creator,
        action_id,
    )
    .await;
    assert_transaction_success(split_result);

    // Check receipt account is created
    let receipt_account = assert_account_exists(context, receipt_pda, true)
        .await
        .expect("Receipt should be created");

    let balance_before = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    let result = close_action_receipt_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        mint_creator.pubkey(),
        receipt_pda,
        mint_from_pubkey,
        &mint_creator,
        CloseActionReceiptArgs { action_id },
    )
    .await;
    assert_transaction_success(result);

    assert_account_exists(context, receipt_pda, false).await;

    // Check rent lamports are refunded to payer
    let balance_after = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    let rent_refund = balance_after - balance_before + TX_FEE;
    let receipt_account_rent = receipt_account.lamports;
    assert_eq!(
        rent_refund, receipt_account_rent,
        "Payer should receive rent lamports from closed Receipt account"
    );

    // Try closing already closed Receipt account
    let result = close_action_receipt_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        mint_creator.pubkey(),
        receipt_pda,
        mint_from_pubkey,
        &mint_creator,
        CloseActionReceiptArgs { action_id },
    )
    .await;
    assert!(result.is_err(), "Should not close already closed Receipt");
}

#[tokio::test]
async fn test_should_close_action_receipt_account_after_convert() {
    let mut context = &mut start_with_context().await;

    let mint_creator = context.payer.insecure_clone();
    let mint_keypair_from = Keypair::new();
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_from = mint_keypair_from.pubkey();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals = 6u8;
    let (mint_authority_pda_from, _) =
        create_minimal_security_token_mint(&mut context, &mint_keypair_from, None, decimals).await;
    let (mint_authority_pda_to, _) =
        create_minimal_security_token_mint(&mut context, &mint_keypair_to, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_keypair_from.pubkey();
    let mint_to_pubkey = mint_keypair_to.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateConfig {
            rounding,
            numerator,
            denominator,
        },
    };

    let (rate_pda, result) = create_rate_account(
        context,
        mint_keypair_to.pubkey(),
        mint_authority_pda_to,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_to_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_from, _) = find_permanent_delegate_pda(&mint_keypair_from.pubkey());
    let (receipt_pda, _) = find_common_action_receipt_pda(&mint_to_pubkey, action_id);

    assert_account_exists(context, rate_pda, true)
        .await
        .unwrap();

    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_to,
        mint_authority_pda_to.clone(),
        vec![],
        None,
    )
    .await;

    let mint_verification_config_pda_from = create_mint_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    let initial_ui_amount = 1000u64;
    let (_initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        &mint_creator,
        &mint_creator,
        decimals,
        initial_ui_amount,
    )
    .await;

    let token_account_pubkey_to =
        create_spl_account(context, &mint_keypair_to, &mint_creator).await;

    let ui_amount_to_convert = 1u64;
    let amount_to_convert = from_ui_amount(ui_amount_to_convert, decimals);
    let convert_result = execute_convert(
        &context.banks_client,
        convert_verification_config_pda,
        mint_pubkey_from,
        mint_pubkey_to,
        token_account_pubkey_from,
        token_account_pubkey_to,
        mint_authority_pda_to,
        permanent_delegate_pda_from,
        rate_pda,
        receipt_pda,
        &mint_creator,
        action_id,
        amount_to_convert,
    )
    .await;
    assert_transaction_success(convert_result);

    // Check receipt account is created
    let receipt_account = assert_account_exists(context, receipt_pda, true)
        .await
        .expect("Receipt should be created");

    let balance_before = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    let result = close_action_receipt_account(
        context,
        mint_keypair_to.pubkey(),
        mint_authority_pda_to,
        mint_creator.pubkey(),
        receipt_pda,
        mint_to_pubkey,
        &mint_creator,
        CloseActionReceiptArgs { action_id },
    )
    .await;
    assert_transaction_success(result);

    assert_account_exists(context, receipt_pda, false).await;

    // Check rent lamports are refunded to payer
    let balance_after = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    let rent_refund = balance_after - balance_before + TX_FEE;
    let receipt_account_rent = receipt_account.lamports;
    assert_eq!(
        rent_refund, receipt_account_rent,
        "Payer should receive rent lamports from closed Receipt account"
    );

    // Try closing already closed Receipt account
    let result = close_action_receipt_account(
        context,
        mint_keypair_to.pubkey(),
        mint_authority_pda_to,
        mint_creator.pubkey(),
        receipt_pda,
        mint_to_pubkey,
        &mint_creator,
        CloseActionReceiptArgs { action_id },
    )
    .await;
    assert!(result.is_err(), "Should not close already closed Receipt");
}

#[tokio::test]
async fn test_should_not_close_not_owned_receipt_account() {
    let kp2 = Keypair::new();
    let mut context =
        &mut start_with_context_and_accounts(vec![(&kp2, sol_str_to_lamports("2").unwrap())]).await;

    let kp1: Keypair = context.payer.insecure_clone();

    let creator_keypairs = [kp1.insecure_clone(), kp2.insecure_clone()];

    let decimals: u8 = 6;
    let mut action_id = 0u64;
    let mut creator_resources = Vec::with_capacity(creator_keypairs.len());

    for mint_creator in &creator_keypairs {
        let mint_keypair = Keypair::new();
        let (mint_authority_pda, _) = create_minimal_security_token_mint(
            &mut context,
            &mint_keypair,
            Some(mint_creator),
            decimals,
        )
        .await;

        action_id += 1;
        let rounding = Rounding::Up as u8;
        let numerator = 3u8;
        let denominator = 2u8;
        let mint_pubkey = mint_keypair.pubkey();

        let create_rate_args = CreateRateArgs {
            action_id,
            rate: RateConfig {
                rounding,
                numerator,
                denominator,
            },
        };

        let (rate_pda, result) = create_rate_account(
            context,
            mint_pubkey,
            mint_authority_pda,
            mint_creator.pubkey(),
            mint_pubkey,
            mint_pubkey,
            create_rate_args.clone(),
            Some(mint_creator),
        )
        .await;
        assert_transaction_success(result);

        // Derive permanent delegate & receipt PDAs
        let (permanent_delegate_pda, _) = find_permanent_delegate_pda(&mint_pubkey);
        let (receipt_pda, _) = find_common_action_receipt_pda(&mint_pubkey, action_id);

        assert_account_exists(context, rate_pda, true)
            .await
            .unwrap();

        let split_verification_config_pda = create_split_verification_config(
            context,
            &mint_keypair,
            mint_authority_pda.clone(),
            vec![],
            Some(mint_creator),
        )
        .await;

        let mint_verification_config_pda = create_mint_verification_config(
            context,
            &mint_keypair,
            mint_authority_pda.clone(),
            vec![],
            Some(mint_creator),
        )
        .await;

        let token_account_pubkey = create_spl_account(context, &mint_keypair, &mint_creator).await;

        let amount = from_ui_amount(1000, decimals);
        let result = mint_tokens_to(
            &mut context.banks_client,
            amount,
            mint_pubkey,
            token_account_pubkey.clone(),
            mint_authority_pda.clone(),
            mint_verification_config_pda.clone(),
            &mint_creator,
        )
        .await;
        assert_transaction_success(result);

        // Execute split
        let split_result = execute_split(
            &context.banks_client,
            split_verification_config_pda,
            mint_pubkey,
            mint_authority_pda,
            permanent_delegate_pda,
            rate_pda,
            receipt_pda,
            token_account_pubkey,
            &mint_creator,
            action_id,
        )
        .await;
        assert_transaction_success(split_result);

        assert_account_exists(context, receipt_pda, true)
            .await
            .expect("Receipt should be created");

        let ix_data = (
            mint_keypair.pubkey(),
            mint_authority_pda,
            mint_creator.pubkey(),
            receipt_pda,
            mint_pubkey,
            mint_creator.insecure_clone(),
            CloseActionReceiptArgs { action_id },
        );
        creator_resources.push(ix_data);
        println!("Prepared resources for creator {}", mint_creator.pubkey());
    }

    let [(
        mint_pubkey_1,
        mint_authority_pda_1,
        mint_creator_pubkey_1,
        receipt_pda_1,
        mint_from_pubkey_1,
        mint_creator_1,
        close_receipt_args_1,
    ), (
        mint_pubkey_2,
        mint_authority_pda_2,
        mint_creator_pubkey_2,
        receipt_pda_2,
        mint_from_pubkey_2,
        mint_creator_2,
        close_receipt_args_2,
    )] = &creator_resources[..]
    else {
        panic!("Expected exactly two creator resources");
    };

    let result = close_action_receipt_account(
        context,
        *mint_pubkey_1,
        *mint_authority_pda_1,
        *mint_creator_pubkey_1,
        *receipt_pda_2,
        *mint_from_pubkey_1,
        &mint_creator_1,
        close_receipt_args_1.clone(),
    )
    .await;
    assert!(result.is_err(), "Should not close not owned Receipt");
    let result = close_action_receipt_account(
        context,
        *mint_pubkey_1,
        *mint_authority_pda_1,
        *mint_creator_pubkey_2,
        *receipt_pda_2,
        *mint_from_pubkey_2,
        &mint_creator_1,
        close_receipt_args_2.clone(),
    )
    .await;
    assert!(result.is_err(), "Should not close not owned Receipt");

    // Double check valid close of Receipt accounts
    let result1 = close_action_receipt_account(
        context,
        *mint_pubkey_1,
        *mint_authority_pda_1,
        *mint_creator_pubkey_1,
        *receipt_pda_1,
        *mint_from_pubkey_1,
        &mint_creator_1,
        close_receipt_args_1.clone(),
    )
    .await;
    assert_transaction_success(result1);

    let result2 = close_action_receipt_account(
        context,
        *mint_pubkey_2,
        *mint_authority_pda_2,
        *mint_creator_pubkey_2,
        *receipt_pda_2,
        *mint_from_pubkey_2,
        &mint_creator_2,
        close_receipt_args_2.clone(),
    )
    .await;
    assert_transaction_success(result2);
}

#[tokio::test]
async fn test_should_not_close_wrong_account_type() {
    let mut context = &mut start_with_context().await;

    let mint_creator = context.payer.insecure_clone();
    let mint_keypair = Keypair::new();
    let decimals = 6u8;
    let (mint_authority_pda, _) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, decimals).await;

    let action_id = 42u64;
    let rounding = Rounding::Up as u8;
    let numerator = 3u8;
    let denominator = 2u8;
    let mint_from_pubkey = mint_keypair.pubkey();

    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateConfig {
            rounding,
            numerator,
            denominator,
        },
    };

    // Create a Rate account (wrong type for Receipt)
    let (rate_pda, result) = create_rate_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        context.payer.pubkey(),
        mint_from_pubkey,
        mint_from_pubkey,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(result);

    assert_account_exists(context, rate_pda, true)
        .await
        .unwrap();

    // Try to close Rate account as if it were a Receipt account
    let result = close_action_receipt_account(
        context,
        mint_keypair.pubkey(),
        mint_authority_pda,
        mint_creator.pubkey(),
        rate_pda, // Passing Rate PDA instead of Receipt PDA
        mint_from_pubkey,
        &mint_creator,
        CloseActionReceiptArgs { action_id },
    )
    .await;
    assert_transaction_failure(result);
}

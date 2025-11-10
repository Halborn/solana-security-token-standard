use rstest::*;
use security_token_client::{
    accounts::Receipt,
    types::{CreateRateArgs, RateArgs, Rounding},
};
use solana_pubkey::Pubkey;
use solana_sdk::{native_token::sol_str_to_lamports, signature::Keypair, signer::Signer};

use crate::{
    helpers::{
        assert_account_exists, assert_transaction_success, create_mint_verification_config,
        create_spl_account, find_permanent_delegate_pda, find_receipt_pda, from_ui_amount,
        get_token_account_state, mint_tokens_to, start_with_context,
        start_with_context_and_accounts,
    },
    rate_tests::rate_helpers::{
        calculate_rate_amount, create_rate_account, create_security_token_mint,
    },
    split_tests::split_helpers::{create_split_verification_config, execute_split, uniq_pubkey},
};

#[tokio::test]
async fn test_should_split_with_mint_successfully() {
    let context = &mut start_with_context().await;

    // Create mint + authority
    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let decimals = 6u8;
    let mint_creator = &context.payer.insecure_clone();
    let _mint_creator_pubkey = mint_creator.pubkey();

    let (mint_authority_pda, _, _) =
        create_security_token_mint(context, &mint_keypair, Some(mint_creator), decimals).await;

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
    println!("Tokens amount before split: {:?}", amount);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        mint_pubkey.clone(),
        token_account_pubkey.clone(),
        mint_authority_pda.clone(),
        mint_verification_config_pda.clone(),
        mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Create Rate (split: same mint, +50% mint tokens expected)
    let action_id = 77u64;
    let rounding = Rounding::Up as u8;
    let numerator = 2u8;
    let denominator = 1u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, rate_create_result) = create_rate_account(
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
    assert_transaction_success(rate_create_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda, _pd_bump) = find_permanent_delegate_pda(&mint_keypair.pubkey());
    let (receipt_pda, receipt_bump) = find_receipt_pda(&mint_pubkey, action_id);

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

    // Verify token account balance increased according to rate
    let expected_amount = calculate_rate_amount(numerator, denominator, rounding, amount).unwrap();
    let token_account_after =
        get_token_account_state(&mut context.banks_client, token_account_pubkey).await;
    println!(
        "Tokens amount after split: {:?}",
        token_account_after.base.amount
    );
    assert_eq!(token_account_after.base.amount, expected_amount);

    // Verify receipt account exists
    let receipt_account = assert_account_exists(context, receipt_pda, true)
        .await
        .expect("Receipt should be created");
    let receipt_state =
        Receipt::from_bytes(&receipt_account.data).expect("Should deserialize Receipt");
    assert_eq!(
        receipt_state.action_id, action_id,
        "Receipt action_id mismatch"
    );
    assert_eq!(receipt_state.bump, receipt_bump, "Receipt bump mismatch");
    assert_eq!(receipt_state.mint, mint_pubkey, "Receipt mint mismatch");
}

#[tokio::test]
async fn test_should_split_with_burn_successfully() {
    let context = &mut start_with_context().await;

    // Create mint + authority
    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let decimals = 6u8;
    let mint_creator = &context.payer.insecure_clone();
    let _mint_creator_pubkey = mint_creator.pubkey();

    let (mint_authority_pda, _, _) =
        create_security_token_mint(context, &mint_keypair, Some(mint_creator), decimals).await;

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
    println!("Tokens amount before split: {:?}", amount);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        mint_pubkey.clone(),
        token_account_pubkey.clone(),
        mint_authority_pda.clone(),
        mint_verification_config_pda.clone(),
        mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Create Rate (split: same mint, -50% burn is expected)
    let action_id = 77u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 2u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, rate_create_result) = create_rate_account(
        context,
        mint_pubkey,
        mint_authority_pda,
        context.payer.pubkey(),
        mint_pubkey,
        mint_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(rate_create_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey);
    let (receipt_pda, receipt_bump) = find_receipt_pda(&mint_pubkey, action_id);

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

    // Verify token account balance decreased according to rate
    let expected_amount = calculate_rate_amount(numerator, denominator, rounding, amount).unwrap();
    let token_account_after =
        get_token_account_state(&mut context.banks_client, token_account_pubkey).await;
    println!(
        "Tokens amount after split: {:?}",
        token_account_after.base.amount
    );
    assert_eq!(token_account_after.base.amount, expected_amount);

    // Verify receipt account exists
    let receipt_account = assert_account_exists(context, receipt_pda, true)
        .await
        .unwrap();
    let receipt_state =
        Receipt::from_bytes(&receipt_account.data).expect("Should deserialize Receipt");
    assert_eq!(
        receipt_state.action_id, action_id,
        "Receipt action_id mismatch"
    );
    assert_eq!(receipt_state.bump, receipt_bump, "Receipt bump mismatch");
    assert_eq!(receipt_state.mint, mint_pubkey, "Receipt mint mismatch");
}

#[tokio::test]
async fn test_should_not_split_twice() {
    let context = &mut start_with_context().await;

    // Create mint + authority
    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let decimals = 6u8;
    let mint_creator = &context.payer.insecure_clone();
    let _mint_creator_pubkey = mint_creator.pubkey();

    let (mint_authority_pda, _, _) =
        create_security_token_mint(context, &mint_keypair, Some(mint_creator), decimals).await;

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
    println!("Tokens amount before split: {:?}", amount);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        mint_pubkey.clone(),
        token_account_pubkey.clone(),
        mint_authority_pda.clone(),
        mint_verification_config_pda.clone(),
        mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let action_id = 77u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 2u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, rate_create_result) = create_rate_account(
        context,
        mint_pubkey,
        mint_authority_pda,
        context.payer.pubkey(),
        mint_pubkey,
        mint_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(rate_create_result);

    let (permanent_delegate_pda, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey);
    let (receipt_pda, _receipt_bump) = find_receipt_pda(&mint_pubkey, action_id);

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

    // Verify receipt account exists
    assert_account_exists(context, receipt_pda, true)
        .await
        .expect("Receipt should be created");

    // Execute the same split action again
    let second_split = execute_split(
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
    assert!(
        second_split.is_err(),
        "Second split with same action_id should fail due to existing receipt"
    );
}

#[tokio::test]
async fn test_should_not_split_token_zero_amount() {
    let context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let decimals = 6u8;
    let mint_creator = &context.payer.insecure_clone();
    let _mint_creator_pubkey = mint_creator.pubkey();

    let (mint_authority_pda, _, _) =
        create_security_token_mint(context, &mint_keypair, Some(mint_creator), decimals).await;

    let split_verification_config_pda = create_split_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        None,
    )
    .await;

    create_mint_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        None,
    )
    .await;

    // Create token account, no minting
    let token_account_pubkey = create_spl_account(context, &mint_keypair, &mint_creator).await;

    let action_id = 42u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 2u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, rate_create_result) = create_rate_account(
        context,
        mint_pubkey,
        mint_authority_pda,
        context.payer.pubkey(),
        mint_pubkey,
        mint_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(rate_create_result);

    let (permanent_delegate_pda, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey);
    let (receipt_pda, _receipt_bump) = find_receipt_pda(&mint_pubkey, action_id);

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
    assert!(
        split_result.is_err(),
        "Split should fail for token account with zero balance"
    );
}

#[rstest]
// mint, mint_authority, permanent_delegate, token_account, rate, receipt
#[case(
    Some(uniq_pubkey()),
    None,
    None,
    None,
    None,
    "Should fail with invalid mint account"
)]
#[case(
    None,
    Some(uniq_pubkey()),
    None,
    None,
    None,
    "Should fail with invalid mint authority"
)]
#[case(
    None,
    None,
    Some(uniq_pubkey()),
    None,
    None,
    "Should fail with invalid permanent delegate"
)]
#[case(
    None,
    None,
    None,
    Some(uniq_pubkey()),
    None,
    "Should fail with invalid rate account"
)]
#[case(
    None,
    None,
    None,
    None,
    Some(uniq_pubkey()),
    "Should fail with invalid receipt"
)]
#[tokio::test]
async fn test_should_not_split_with_invalid_random_accounts(
    #[case] invalid_mint: Option<Pubkey>,
    #[case] invalid_mint_authority: Option<Pubkey>,
    #[case] invalid_permanent_delegate: Option<Pubkey>,
    #[case] invalid_rate_account: Option<Pubkey>,
    #[case] invalid_receipt: Option<Pubkey>,
    #[case] description: &str,
) {
    let context = &mut start_with_context().await;

    let valid_mint_keypair = Keypair::new();
    let valid_mint_pubkey = valid_mint_keypair.pubkey();
    let decimals = 6u8;
    let valid_mint_creator = &context.payer.insecure_clone();
    let valid_mint_creator_pubkey = valid_mint_creator.pubkey();

    let (valid_mint_authority_pda, _, _) = create_security_token_mint(
        context,
        &valid_mint_keypair,
        Some(valid_mint_creator),
        decimals,
    )
    .await;

    let (valid_permanent_delegate_pda, _pd_bump) = find_permanent_delegate_pda(&valid_mint_pubkey);

    let valid_split_verification_config_pda = create_split_verification_config(
        context,
        &valid_mint_keypair,
        valid_mint_authority_pda.clone(),
        vec![],
        None,
    )
    .await;

    let valid_mint_verification_config_pda = create_mint_verification_config(
        context,
        &valid_mint_keypair,
        valid_mint_authority_pda.clone(),
        vec![],
        None,
    )
    .await;

    // Create valid token account with tokens
    let valid_token_account_pubkey =
        create_spl_account(context, &valid_mint_keypair, &valid_mint_creator).await;

    let amount = from_ui_amount(1000, decimals);
    println!("Tokens amount before split: {:?}", amount);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        valid_mint_pubkey.clone(),
        valid_token_account_pubkey.clone(),
        valid_mint_authority_pda.clone(),
        valid_mint_verification_config_pda.clone(),
        valid_mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let action_id = 42u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 2u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (valid_rate_pda, rate_create_result) = create_rate_account(
        context,
        valid_mint_pubkey,
        valid_mint_authority_pda,
        valid_mint_creator_pubkey,
        valid_mint_pubkey,
        valid_mint_pubkey,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(rate_create_result);

    let (valid_receipt_pda, _receipt_bump) = find_receipt_pda(&valid_mint_pubkey, action_id);

    // Execute split
    let split_result = execute_split(
        &context.banks_client,
        valid_split_verification_config_pda,
        invalid_mint.unwrap_or(valid_mint_pubkey),
        invalid_mint_authority.unwrap_or(valid_mint_authority_pda),
        invalid_permanent_delegate.unwrap_or(valid_permanent_delegate_pda),
        invalid_rate_account.unwrap_or(valid_rate_pda),
        invalid_receipt.unwrap_or(valid_receipt_pda),
        valid_token_account_pubkey,
        &valid_mint_creator,
        action_id,
    )
    .await;
    assert!(split_result.is_err(), "{}", description);
}

#[tokio::test]
async fn test_should_not_split_not_owned_mint_or_token_account() {
    let mint_creator2 = Keypair::new();
    let mint_creator2_balance = sol_str_to_lamports("10").unwrap();
    let context =
        &mut start_with_context_and_accounts(vec![(&mint_creator2, mint_creator2_balance)]).await;

    let mint_keypair1 = Keypair::new();
    let mint_pubkey1 = mint_keypair1.pubkey();
    let decimals = 6u8;
    let mint_creator1 = &context.payer.insecure_clone();
    let mint_creator_pubkey1 = mint_creator1.pubkey();

    let (mint_authority_pda1, _, _) =
        create_security_token_mint(context, &mint_keypair1, Some(mint_creator1), decimals).await;

    let (permanent_delegate_pda1, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey1);

    let split_verification_config_pda1 = create_split_verification_config(
        context,
        &mint_keypair1,
        mint_authority_pda1.clone(),
        vec![],
        None,
    )
    .await;

    let mint_verification_config_pda1 = create_mint_verification_config(
        context,
        &mint_keypair1,
        mint_authority_pda1.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey1 = create_spl_account(context, &mint_keypair1, &mint_creator1).await;

    let amount = from_ui_amount(1000, decimals);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        mint_pubkey1.clone(),
        token_account_pubkey1.clone(),
        mint_authority_pda1.clone(),
        mint_verification_config_pda1.clone(),
        mint_creator1,
    )
    .await;
    assert_transaction_success(result);

    let action_id = 42u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 2u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda1, rate_create_result) = create_rate_account(
        context,
        mint_pubkey1,
        mint_authority_pda1,
        mint_creator_pubkey1,
        mint_pubkey1,
        mint_pubkey1,
        create_rate_args.clone(),
        None,
    )
    .await;
    assert_transaction_success(rate_create_result);

    let (receipt_pda, _receipt_bump) = find_receipt_pda(&mint_pubkey1, action_id);

    // Create security mint for mint creator 2
    let mint_creator_pubkey2 = mint_creator2.pubkey();
    let mint_keypair2 = Keypair::new();
    let mint_pubkey2 = mint_keypair2.pubkey();

    let (mint_authority_pda2, _, _) =
        create_security_token_mint(context, &mint_keypair2, Some(&mint_creator2), decimals).await;

    let (_permanent_delegate_pda2, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey2);

    let mint_verification_config_pda2 = create_mint_verification_config(
        context,
        &mint_keypair2,
        mint_authority_pda2.clone(),
        vec![],
        Some(&mint_creator2),
    )
    .await;

    let token_account_pubkey2 = create_spl_account(context, &mint_keypair2, &mint_creator2).await;

    let amount = from_ui_amount(1000, decimals);
    let result = mint_tokens_to(
        &mut context.banks_client,
        amount,
        mint_pubkey2.clone(),
        token_account_pubkey2.clone(),
        mint_authority_pda2.clone(),
        mint_verification_config_pda2.clone(),
        &mint_creator2,
    )
    .await;
    assert_transaction_success(result);

    let (rate_pda2, rate_create_result) = create_rate_account(
        context,
        mint_pubkey2,
        mint_authority_pda2,
        mint_creator_pubkey2,
        mint_pubkey2,
        mint_pubkey2,
        create_rate_args.clone(),
        Some(&mint_creator2),
    )
    .await;
    assert_transaction_success(rate_create_result);

    // Try executing split for not owned mint or token account
    let split_result = execute_split(
        &context.banks_client,
        split_verification_config_pda1,
        mint_pubkey1,
        mint_authority_pda1,
        permanent_delegate_pda1,
        rate_pda1,
        receipt_pda,
        token_account_pubkey2, // token account not owned by mint 2 creator
        &mint_creator1,
        action_id,
    )
    .await;
    assert!(
        split_result.is_err(),
        "Should not split with not owned token account"
    );

    let split_result = execute_split(
        &context.banks_client,
        split_verification_config_pda1,
        mint_pubkey1,
        mint_authority_pda1,
        permanent_delegate_pda1,
        rate_pda2, // Use rate from mint 2
        receipt_pda,
        token_account_pubkey1,
        &mint_creator1,
        action_id,
    )
    .await;
    assert!(split_result.is_err(), "Should not split at wrong rate");
}

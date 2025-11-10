use security_token_client::{
    accounts::Receipt,
    types::{CreateRateArgs, RateArgs, Rounding},
};
use solana_sdk::{native_token::sol_str_to_lamports, signature::Keypair, signer::Signer};
use std::ops::Mul;

use crate::{
    convert_tests::convert_helpers::{
        build_creator_resources, create_convert_verification_config, execute_convert,
    },
    helpers::{
        assert_account_exists, assert_transaction_success, create_mint_verification_config,
        create_spl_account, create_token_account_and_mint_tokens, find_permanent_delegate_pda,
        find_receipt_pda, from_ui_amount, get_token_account_state, mint_tokens_to,
        start_with_context, start_with_context_and_accounts,
    },
    rate_tests::rate_helpers::{create_rate_account, create_security_token_mint},
};

#[tokio::test]
async fn test_should_convert_successfully() {
    let context = &mut start_with_context().await;

    let mint_creator = &context.payer.insecure_clone();
    let mint_creator_pubkey = mint_creator.pubkey();

    // Create two mints for conversion
    // Source mint (will be burned)
    let mint_keypair_from = Keypair::new();
    let mint_pubkey_from = mint_keypair_from.pubkey();
    let decimals_from = 6u8;
    let (mint_authority_pda_from, _, _) = create_security_token_mint(
        context,
        &mint_keypair_from,
        Some(mint_creator),
        decimals_from,
    )
    .await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from = create_mint_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        Some(mint_creator),
    )
    .await;

    // Pre-mint tokens to source
    let initial_ui_amount = 1000u64;
    let (initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        mint_creator,
        mint_creator,
        decimals_from,
        initial_ui_amount,
    )
    .await;

    // Target mint (will be minted)
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 9u8;
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to)
            .await;

    // Convert verification config for conversion mint_from => mint_to
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_to,
        mint_authority_pda_to.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey_to = create_spl_account(context, &mint_keypair_to, mint_creator).await;

    // Create Rate for 2/1 conversion
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
    let (rate_pda, create_rate_result) = create_rate_account(
        context,
        mint_pubkey_to,
        mint_authority_pda_to,
        mint_creator_pubkey,
        mint_pubkey_from,
        mint_pubkey_to,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(create_rate_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_from, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey_from);
    let (receipt_pda, receipt_bump) = find_receipt_pda(&mint_pubkey_to, action_id);

    let ui_amount_to_convert = 900u64;
    let amount_to_convert = from_ui_amount(ui_amount_to_convert, decimals_from);
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

    // Verify token account balances after conversion

    // source token account (mint_from) should be decreased by amount_to_convert
    let expected_amount_from = initial_amount - amount_to_convert;
    let token_account_from_after =
        get_token_account_state(&mut context.banks_client, token_account_pubkey_from).await;
    println!(
        "Source token amount after conversion: {:?}",
        token_account_from_after.base.amount
    );
    assert_eq!(token_account_from_after.base.amount, expected_amount_from);

    // target token account (mint_to) should be increased twofold (ui_amount_to_convert * 2)
    // Initial target amount was 0.
    let expected_amount_to = from_ui_amount(ui_amount_to_convert.mul(2), decimals_to);
    let token_account_to_after =
        get_token_account_state(&mut context.banks_client, token_account_pubkey_to).await;
    println!(
        "Target token amount after conversion: {:?}",
        token_account_to_after.base.amount
    );
    assert_eq!(token_account_to_after.base.amount, expected_amount_to);

    // // Verify receipt account has been created
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
    assert_eq!(receipt_state.mint, mint_pubkey_to, "Receipt mint mismatch");
}

#[tokio::test]
async fn test_should_not_convert_twice() {
    let context = &mut start_with_context().await;

    let mint_creator = &context.payer.insecure_clone();
    let mint_creator_pubkey = mint_creator.pubkey();

    // Create two mints for conversion
    // Source mint (will be burned)
    let mint_keypair_from = Keypair::new();
    let mint_pubkey_from = mint_keypair_from.pubkey();
    let decimals_from = 6u8;
    let (mint_authority_pda_from, _, _) = create_security_token_mint(
        context,
        &mint_keypair_from,
        Some(mint_creator),
        decimals_from,
    )
    .await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from = create_mint_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    // Pre-mint tokens to source
    let initial_ui_amount = 1000u64;
    let (_initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        mint_creator,
        mint_creator,
        decimals_from,
        initial_ui_amount,
    )
    .await;

    // Target mint (will be minted)
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 9u8;
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to)
            .await;

    // Convert verification config for conversion mint_from => mint_to
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_to,
        mint_authority_pda_to.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey_to = create_spl_account(context, &mint_keypair_to, mint_creator).await;

    // Create Rate for 2/1 conversion
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
    let (rate_pda, create_rate_result) = create_rate_account(
        context,
        mint_pubkey_to,
        mint_authority_pda_to,
        mint_creator_pubkey,
        mint_pubkey_from,
        mint_pubkey_to,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(create_rate_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_from, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey_from);
    let (receipt_pda, receipt_bump) = find_receipt_pda(&mint_pubkey_to, action_id);

    let ui_amount_to_convert = 900u64;
    let amount_to_convert = from_ui_amount(ui_amount_to_convert, decimals_from);
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

    // // Verify receipt account has been created
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
    assert_eq!(receipt_state.mint, mint_pubkey_to, "Receipt mint mismatch");

    let second_conversion = execute_convert(
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

    assert!(
        second_conversion.is_err(),
        "Second convert operation with same action_id should fail due to existing receipt"
    );
}

#[tokio::test]
async fn test_should_not_convert_insufficient_tokens_amount() {
    let context = &mut start_with_context().await;

    let mint_creator = &context.payer.insecure_clone();
    let mint_creator_pubkey = mint_creator.pubkey();

    // Create two mints for conversion
    // Source mint
    let mint_keypair_from = Keypair::new();
    let mint_pubkey_from = mint_keypair_from.pubkey();
    let decimals_from = 6u8;
    let (mint_authority_pda_from, _, _) = create_security_token_mint(
        context,
        &mint_keypair_from,
        Some(mint_creator),
        decimals_from,
    )
    .await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from = create_mint_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    // Create source token account WITHOUT minting tokens
    let token_account_pubkey_from =
        create_spl_account(context, &mint_keypair_from, mint_creator).await;

    // Target mint
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 9u8;
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to)
            .await;

    // Verification config for conversion
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_to,
        mint_authority_pda_to.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey_to = create_spl_account(context, &mint_keypair_to, mint_creator).await;

    // Create Rate
    let action_id = 77u64;
    let rounding = Rounding::Up as u8;
    let numerator = 1u8;
    let denominator = 10u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, create_rate_result) = create_rate_account(
        context,
        mint_pubkey_to,
        mint_authority_pda_to,
        mint_creator_pubkey,
        mint_pubkey_from,
        mint_pubkey_to,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(create_rate_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_from, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey_from);
    let (receipt_pda, _receipt_bump) = find_receipt_pda(&mint_pubkey_from, action_id);

    let ui_amount_to_convert = 10u64;
    let amount_to_convert = from_ui_amount(ui_amount_to_convert, decimals_from);
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
    assert!(
        convert_result.is_err(),
        "Should fail due to insufficient tokens in source account"
    );

    // Mint some tokens below the conversion amount
    let ui_amount = 1u64;
    let result = mint_tokens_to(
        &mut context.banks_client,
        from_ui_amount(ui_amount, decimals_from),
        mint_pubkey_from.clone(),
        token_account_pubkey_from.clone(),
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let amount_to_convert = from_ui_amount(ui_amount_to_convert, decimals_from);
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
    assert!(
        convert_result.is_err(),
        "Should still fail due to insufficient tokens in source account"
    );
}

#[tokio::test]
async fn test_should_fail_when_conversion_target_amount_zero() {
    let context = &mut start_with_context().await;

    let mint_creator = &context.payer.insecure_clone();
    let mint_creator_pubkey = mint_creator.pubkey();

    // Create two mints for conversion
    // Source mint
    let mint_keypair_from = Keypair::new();
    let mint_pubkey_from = mint_keypair_from.pubkey();
    let decimals_from = 6u8;
    let (mint_authority_pda_from, _, _) = create_security_token_mint(
        context,
        &mint_keypair_from,
        Some(mint_creator),
        decimals_from,
    )
    .await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from = create_mint_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    // Pre-mint tokens to source
    let initial_ui_amount = 1000u64;
    let (_initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        mint_creator,
        mint_creator,
        decimals_from,
        initial_ui_amount,
    )
    .await;

    // Target mint
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 3u8;
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to)
            .await;

    // Verification config for conversion
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_to,
        mint_authority_pda_to.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey_to = create_spl_account(context, &mint_keypair_to, mint_creator).await;

    // Create Rate
    let action_id = 77u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 255u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, create_rate_result) = create_rate_account(
        context,
        mint_pubkey_to,
        mint_authority_pda_to,
        mint_creator_pubkey,
        mint_pubkey_from,
        mint_pubkey_to,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(create_rate_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_from, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey_from);
    let (receipt_pda, _receipt_bump) = find_receipt_pda(&mint_pubkey_from, action_id);

    // convert small amount of tokens that would lead to 0 target tokens
    let amount_to_convert = 1_000u64;
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
    assert!(
        convert_result.is_err(),
        "Should not convert due to zero target amount"
    );
}

#[tokio::test]
async fn test_should_not_panic_when_overflow_occur() {
    let context = &mut start_with_context().await;

    let mint_creator = &context.payer.insecure_clone();
    let mint_creator_pubkey = mint_creator.pubkey();

    // Create two mints for conversion
    // Source mint
    let mint_keypair_from = Keypair::new();
    let mint_pubkey_from = mint_keypair_from.pubkey();
    let decimals_from = 6u8;
    let (mint_authority_pda_from, _, _) = create_security_token_mint(
        context,
        &mint_keypair_from,
        Some(mint_creator),
        decimals_from,
    )
    .await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from = create_mint_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    // Pre-mint MAX tokens tokens to source
    let initial_ui_amount = u64::MAX / 10u64.pow(decimals_from as u32);
    let (_initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        mint_creator,
        mint_creator,
        decimals_from,
        initial_ui_amount,
    )
    .await;

    // Target mint
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 9u8; // more decimals so u64::MAX will result in overflow
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to)
            .await;

    // Verification config for conversion
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_to,
        mint_authority_pda_to.clone(),
        vec![],
        None,
    )
    .await;

    let token_account_pubkey_to = create_spl_account(context, &mint_keypair_to, mint_creator).await;

    // Create Rate 1:1, so we try to convert u64::MAX 6 decimals to u64::MAX 9 decimals, which should overflow
    let action_id = 77u64;
    let rounding = Rounding::Down as u8;
    let numerator = 1u8;
    let denominator = 1u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    let (rate_pda, create_rate_result) = create_rate_account(
        context,
        mint_pubkey_to,
        mint_authority_pda_to,
        mint_creator_pubkey,
        mint_pubkey_from,
        mint_pubkey_to,
        create_rate_args,
        None,
    )
    .await;
    assert_transaction_success(create_rate_result);

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_from, _pd_bump) = find_permanent_delegate_pda(&mint_pubkey_from);
    let (receipt_pda, _receipt_bump) = find_receipt_pda(&mint_pubkey_from, action_id);

    // convert small amount of tokens that would lead to 0 target tokens
    let amount_to_convert = u64::MAX;
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
    assert!(
        convert_result.is_err(),
        "Should not convert due to overflow"
    );
}

#[tokio::test]
async fn test_should_not_convert_token_from_wrong_mint() {
    let kp2 = Keypair::new();
    let mint_creator2_balance = sol_str_to_lamports("10").unwrap();

    let context = &mut start_with_context_and_accounts(vec![(&kp2, mint_creator2_balance)]).await;

    let kp1 = context.payer.insecure_clone();
    let creator_keypairs = [kp1.insecure_clone(), kp2.insecure_clone()];

    let decimals: u8 = 6;
    let mut creator_resources = Vec::with_capacity(creator_keypairs.len());

    for kp in &creator_keypairs {
        creator_resources.push(build_creator_resources(context, kp, decimals).await);
    }

    let [(
        mint_creator_1,
        mint_creator_pubkey_1,
        mint_keypair_1,
        mint_pubkey_1,
        mint_authority_pda_1,
        _convert_verification_config_pda_1,
        _mint_verification_config_pda_1,
        token_account_owner_1_mint_1,
    ), (
        mint_creator_2,
        mint_creator_pubkey_2,
        mint_keypair_2,
        mint_pubkey_2,
        mint_authority_pda_2,
        convert_verification_config_pda_2,
        _mint_verification_config_pda_2,
        token_account_owner_2_mint_2,
    )] = <[_; 2]>::try_from(creator_resources).expect("Expect 2 creator resources");

    // create token missing token accounts for both creators
    let token_account_owner_1_mint_2 =
        create_spl_account(context, &mint_keypair_2, &mint_creator_1).await;
    let token_account_owner_2_mint_1 =
        create_spl_account(context, &mint_keypair_1, &mint_creator_2).await;

    // Create Rate for 1/1 conversion for both mints
    let action_id = 1u64;
    let rounding = Rounding::Up as u8;
    let numerator = 1u8;
    let denominator = 1u8;
    let create_rate_args = CreateRateArgs {
        action_id,
        rate: RateArgs {
            rounding,
            numerator,
            denominator,
        },
    };
    // Conversion from mint2 to mint1
    let (rate_conversion_from_2_to_1, create_rate_result1) = create_rate_account(
        context,
        mint_pubkey_1,
        mint_authority_pda_1,
        mint_creator_pubkey_1,
        mint_pubkey_2,
        mint_pubkey_1,
        create_rate_args.clone(),
        Some(&mint_creator_1),
    )
    .await;
    assert_transaction_success(create_rate_result1);
    // Conversion from mint1 to mint2
    let (rate_conversion_from_1_to_2, create_rate_result2) = create_rate_account(
        context,
        mint_pubkey_2,
        mint_authority_pda_2,
        mint_creator_pubkey_2,
        mint_pubkey_1,
        mint_pubkey_2,
        create_rate_args.clone(),
        Some(&mint_creator_2),
    )
    .await;
    assert_transaction_success(create_rate_result2);

    // Attempt to convert by mint_creator_1 using mint_creator_2's mint and token account

    // Derive permanent delegate & receipt PDAs
    let (permanent_delegate_pda_1, _) = find_permanent_delegate_pda(&mint_pubkey_1);
    let (_permanent_delegate_pda_2, _) = find_permanent_delegate_pda(&mint_pubkey_2);
    let (receipt_pda1, _) = find_receipt_pda(&mint_pubkey_1, action_id);
    let (receipt_pda2, _) = find_receipt_pda(&mint_pubkey_2, action_id);

    let ui_amount_to_convert = 1u64;
    let amount_to_convert = from_ui_amount(ui_amount_to_convert, decimals);

    // Wrong Rate
    {
        let convert_result = execute_convert(
            &context.banks_client,
            convert_verification_config_pda_2,
            mint_pubkey_1,                // from
            mint_pubkey_2,                // to
            token_account_owner_1_mint_1, // from mint1 ata
            token_account_owner_1_mint_2, // to mint2 ata
            mint_authority_pda_2,         // mint mint2
            permanent_delegate_pda_1,     // burn mint1
            rate_conversion_from_2_to_1,  // wrong rate
            receipt_pda2,
            &mint_creator_1,
            action_id,
            amount_to_convert,
        )
        .await;
        assert!(
            convert_result.is_err(),
            "Should fail due to wrong Rate account used for conversion"
        );
    }
    // Wrong token_account_to
    {
        let convert_result = execute_convert(
            &context.banks_client,
            convert_verification_config_pda_2,
            mint_pubkey_1,                // from
            mint_pubkey_2,                // to
            token_account_owner_1_mint_1, // from mint1 ata
            token_account_owner_2_mint_1, // wrong mint ata
            mint_authority_pda_2,         // mint mint2
            permanent_delegate_pda_1,     // burn mint1
            rate_conversion_from_1_to_2,
            receipt_pda2,
            &mint_creator_1,
            action_id,
            amount_to_convert,
        )
        .await;
        assert!(
            convert_result.is_err(),
            "Should fail due to wrong token_account_to used for conversion"
        );
    }
    // Wrong token_account_from
    {
        let convert_result = execute_convert(
            &context.banks_client,
            convert_verification_config_pda_2,
            mint_pubkey_1,                // from
            mint_pubkey_2,                // to
            token_account_owner_1_mint_2, // wrong mint1
            token_account_owner_2_mint_2, // to mint2
            mint_authority_pda_2,         // mint mint2
            permanent_delegate_pda_1,     // burn mint1
            rate_conversion_from_1_to_2,
            receipt_pda2,
            &mint_creator_1,
            action_id,
            amount_to_convert,
        )
        .await;
        assert!(
            convert_result.is_err(),
            "Should fail due to wrong token_account_from used for conversion"
        );
    }
    // Wrong receipt PDA
    {
        let convert_result = execute_convert(
            &context.banks_client,
            convert_verification_config_pda_2,
            mint_pubkey_1,                // from
            mint_pubkey_2,                // to
            token_account_owner_1_mint_1, // from mint1 ata
            token_account_owner_1_mint_2, // to mint2 ata
            mint_authority_pda_2,         // mint mint2
            permanent_delegate_pda_1,     // burn mint1
            rate_conversion_from_1_to_2,
            receipt_pda1, // wrong receipt
            &mint_creator_1,
            action_id,
            amount_to_convert,
        )
        .await;
        assert!(
            convert_result.is_err(),
            "Should fail due to wrong Receipt used for conversion"
        );
    }

    // Everything is correct. Operation should succeed
    {
        let convert_result = execute_convert(
            &context.banks_client,
            convert_verification_config_pda_2,
            mint_pubkey_1,                // from
            mint_pubkey_2,                // to
            token_account_owner_1_mint_1, // from mint1 ata
            token_account_owner_1_mint_2, // to mint2 ata
            mint_authority_pda_2,         // mint mint2
            permanent_delegate_pda_1,     // burn mint1
            rate_conversion_from_1_to_2,
            receipt_pda2,
            &mint_creator_1,
            action_id,
            amount_to_convert,
        )
        .await;
        assert_transaction_success(convert_result);
    }
}

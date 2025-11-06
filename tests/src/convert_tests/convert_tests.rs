use std::ops::Mul;

use rstest::*;
use security_token_client::{
    accounts::Receipt,
    types::{CreateRateArgs, RateArgs, Rounding},
};
use solana_pubkey::Pubkey;
use solana_sdk::{native_token::sol_str_to_lamports, signature::Keypair, signer::Signer};

use crate::{
    convert_tests::convert_helpers::{
        create_convert_verification_config, execute_convert,
    }, helpers::{
        assert_account_exists, assert_transaction_success, create_mint_verification_config, create_token_account, create_token_account_and_mint_tokens, find_permanent_delegate_pda, find_receipt_pda, from_ui_amount, get_token_account_state, start_with_context, start_with_context_and_accounts
    }, rate_tests::rate_helpers::{
        create_rate_account, create_security_token_mint,
    }
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
    let (mint_authority_pda_from, _, _) =
        create_security_token_mint(context, &mint_keypair_from, Some(mint_creator), decimals_from).await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from =
        create_mint_verification_config(context, &mint_keypair_from, mint_authority_pda_from.clone(), vec![], None)
            .await;

    // Pre-mint tokens to source
    let initial_ui_amount = 1000u64;
    let (initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        mint_pubkey_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        mint_creator_pubkey,
        mint_creator,
        decimals_from,
        initial_ui_amount,
    ).await;

    // Target mint (will be minted)
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 9u8;
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to).await;

    // Convert verification config for conversion mint_from => mint_to
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    let (result, token_account_pubkey_to) = create_token_account(&context.banks_client, &mint_creator_pubkey, &mint_pubkey_to, mint_creator).await;
    assert_transaction_success(result);

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
        mint_pubkey_from,
        mint_authority_pda_from,
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
    let (receipt_pda, receipt_bump) = find_receipt_pda(&mint_pubkey_from, action_id);


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
    assert_eq!(receipt_state.mint, mint_pubkey_from, "Receipt mint mismatch");
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
    let (mint_authority_pda_from, _, _) =
        create_security_token_mint(context, &mint_keypair_from, Some(mint_creator), decimals_from).await;

    // Verification config for pre-minting some source tokens to initiate conversion
    let mint_verification_config_pda_from =
        create_mint_verification_config(context, &mint_keypair_from, mint_authority_pda_from.clone(), vec![], None)
            .await;

    // Pre-mint tokens to source
    let initial_ui_amount = 1000u64;
    let (_initial_amount, token_account_pubkey_from) = create_token_account_and_mint_tokens(
        context,
        mint_pubkey_from,
        mint_authority_pda_from.clone(),
        mint_verification_config_pda_from.clone(),
        mint_creator_pubkey,
        mint_creator,
        decimals_from,
        initial_ui_amount,
    ).await;

    // Target mint (will be minted)
    let mint_keypair_to = Keypair::new();
    let mint_pubkey_to = mint_keypair_to.pubkey();
    let decimals_to = 9u8;
    let (mint_authority_pda_to, _, _) =
        create_security_token_mint(context, &mint_keypair_to, Some(mint_creator), decimals_to).await;

    // Convert verification config for conversion mint_from => mint_to
    let convert_verification_config_pda = create_convert_verification_config(
        context,
        &mint_keypair_from,
        mint_authority_pda_from.clone(),
        vec![],
        None,
    )
    .await;

    let (result, token_account_pubkey_to) = create_token_account(&context.banks_client, &mint_creator_pubkey, &mint_pubkey_to, mint_creator).await;
    assert_transaction_success(result);

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
        mint_pubkey_from,
        mint_authority_pda_from,
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
    let (receipt_pda, receipt_bump) = find_receipt_pda(&mint_pubkey_from, action_id);


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
    assert_eq!(receipt_state.mint, mint_pubkey_from, "Receipt mint mismatch");

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

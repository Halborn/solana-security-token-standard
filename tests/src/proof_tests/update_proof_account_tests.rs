use security_token_client::{
    accounts::Proof,
    types::{CreateProofArgs, UpdateProofArgs},
};
use security_token_program::state::SecurityTokenDiscriminators;
use solana_program_test::*;
use solana_sdk::signature::{Keypair, Signer};

use crate::{
    helpers::{
        assert_transaction_success, create_minimal_security_token_mint, create_spl_account,
        get_account, get_balance, start_with_context, TX_FEE,
    },
    proof_tests::proof_helpers::{
        create_create_proof_account_verification_config,
        create_update_proof_account_verification_config, execute_create_proof_account,
        execute_update_proof_account, find_proof_pda,
    },
};

#[tokio::test]
async fn test_should_update_proof_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let payer = context.payer.insecure_clone();
    let decimals = 6u8;
    let mint_authority_pda =
        create_minimal_security_token_mint(&mut context, &mint_keypair, Some(&payer), decimals)
            .await
            .0;

    let verification_config_for_create_proof = create_create_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let verification_config_for_update_proof = create_update_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let token_account_pubkey = create_spl_account(context, &mint_keypair, &payer).await;
    let action_id = 42u64;
    let proof_data = vec![[1u8; 32], [2u8; 32]];

    let create_proof_args = CreateProofArgs {
        action_id,
        data: proof_data,
    };
    let (proof_account, bump) = find_proof_pda(&token_account_pubkey, action_id);

    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_create_proof,
        proof_account,
        mint_pubkey,
        token_account_pubkey,
        create_proof_args.clone(),
        &payer,
    )
    .await;
    assert_transaction_success(result);

    let payer_balance_before = get_balance(&context.banks_client, payer.pubkey()).await;

    // Update first node
    let update_proof_args = UpdateProofArgs {
        action_id,
        data: [9u8; 32],
        offset: 0,
    };
    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        proof_account,
        mint_pubkey,
        token_account_pubkey,
        update_proof_args.clone(),
        &payer,
    )
    .await;
    assert_transaction_success(result);

    let account_after_update = get_account(context, proof_account).await.unwrap();
    let proof_after_update = Proof::from_bytes(&account_after_update.data)
        .expect("Should deserialize Proof after update");
    let account_after_update_rent = account_after_update.lamports;

    // Ensure only proof data was updated and other fields remain unchanged
    assert_eq!(
        proof_after_update.discriminator,
        SecurityTokenDiscriminators::ProofDiscriminator as u8
    );
    assert_eq!(proof_after_update.bump, bump);
    assert_eq!(proof_after_update.data.len(), 2);
    assert_eq!(proof_after_update.data[1], [2u8; 32]);
    // first node should be updated
    assert_eq!(proof_after_update.data[0], [9u8; 32]);

    // Balance should decrease only by transaction fee
    let payer_balance_after_update = get_balance(&context.banks_client, payer.pubkey()).await;
    assert_eq!(
        payer_balance_after_update,
        payer_balance_before - TX_FEE,
        "Payer should only spend transaction fee"
    );

    // Append at the end
    let append_proof_args = UpdateProofArgs {
        action_id,
        data: [10u8; 32],
        offset: proof_after_update.data.len() as u32,
    };

    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        proof_account,
        mint_pubkey,
        token_account_pubkey,
        append_proof_args.clone(),
        &payer,
    )
    .await;
    assert_transaction_success(result);

    let account_after_append = get_account(context, proof_account).await.unwrap();
    let proof_after_append = Proof::from_bytes(&account_after_append.data)
        .expect("Should deserialize Proof after append");
    let account_after_append_rent = account_after_append.lamports;
    let rent_diff = account_after_append_rent - account_after_update_rent;
    assert!(
        rent_diff > 0,
        "Rent should increase after appending data to the proof account"
    );
    assert!(
        account_after_append.data.len() - account_after_update.data.len() == 32,
        "Account data size should increase by 32 bytes"
    );

    assert_eq!(proof_after_append.data.len(), 3);
    assert_eq!(proof_after_append.data[0], [9u8; 32]);
    assert_eq!(proof_after_append.data[1], [2u8; 32]);
    assert_eq!(proof_after_append.data[2], [10u8; 32]);

    // Balance should decrease only by transaction fee
    let payer_balance_after_append = get_balance(&context.banks_client, payer.pubkey()).await;
    assert_eq!(
        payer_balance_after_append,
        payer_balance_after_update - TX_FEE - rent_diff,
        "Payer should spend lamports for the account rent increase and transaction fee"
    );
}

#[tokio::test]
async fn test_should_not_update_proof_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let payer = context.payer.insecure_clone();
    let decimals = 6u8;
    let mint_authority_pda =
        create_minimal_security_token_mint(&mut context, &mint_keypair, Some(&payer), decimals)
            .await
            .0;

    let verification_config_for_create_proof = create_create_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let verification_config_for_update_proof = create_update_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let valid_token_account_pubkey = create_spl_account(context, &mint_keypair, &payer).await;
    let create_proof_action_id = 1u64;
    let initial_proof_data = vec![[1u8; 32], [2u8; 32]];
    let create_proof_args = CreateProofArgs {
        action_id: create_proof_action_id,
        data: initial_proof_data,
    };
    let (valid_proof_account, _) =
        find_proof_pda(&valid_token_account_pubkey, create_proof_action_id);

    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_create_proof,
        valid_proof_account,
        mint_pubkey,
        valid_token_account_pubkey,
        create_proof_args.clone(),
        &payer,
    )
    .await;
    assert_transaction_success(result);

    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        valid_proof_account,
        mint_pubkey,
        valid_token_account_pubkey,
        UpdateProofArgs {
            action_id: 2u64, // invalid action_id
            data: [9u8; 32],
            offset: 0u32,
        },
        &payer,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not update proof account: Invalid action_id"
    );

    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        valid_proof_account,
        mint_pubkey,
        valid_token_account_pubkey,
        UpdateProofArgs {
            action_id: create_proof_action_id,
            data: [0u8; 32], // invalid zero node data
            offset: 0u32,
        },
        &payer,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not update proof account: Invalid zero node data"
    );

    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        valid_proof_account,
        mint_pubkey,
        valid_token_account_pubkey,
        UpdateProofArgs {
            action_id: create_proof_action_id,
            data: [1u8; 32],
            offset: 10u32, // offset out of bounds
        },
        &payer,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not update proof account: Invalid out of bounds offset"
    );

    let mint_keypair2 = Keypair::new();
    let mint_pubkey2 = mint_keypair2.pubkey();
    let mint_authority_pda2 =
        create_minimal_security_token_mint(&mut context, &mint_keypair2, Some(&payer), decimals)
            .await
            .0;
    let verification_config_for_create_proof2 = create_create_proof_account_verification_config(
        context,
        &mint_keypair2,
        mint_authority_pda2.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let token_account_pubkey2 = create_spl_account(context, &mint_keypair2, &payer).await;
    let create_proof2_action_id = 2u64;
    let (proof_account2, _) = find_proof_pda(&token_account_pubkey2, create_proof2_action_id);

    // Create proof account for mint_keypair2
    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey2,
        verification_config_for_create_proof2,
        proof_account2,
        mint_pubkey2,
        token_account_pubkey2,
        CreateProofArgs {
            action_id: create_proof2_action_id,
            data: vec![[1u8; 32], [2u8; 32]],
        },
        &payer,
    )
    .await;
    assert_transaction_success(result);

    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        valid_proof_account,
        mint_pubkey,
        token_account_pubkey2, // token account from mint_keypair2
        UpdateProofArgs {
            action_id: 1u64,
            data: [1u8; 32],
            offset: 0u32,
        },
        &payer,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not update proof account: Invalid token account"
    );

    let result = execute_update_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_for_update_proof,
        proof_account2, // existing proof for another token account
        mint_pubkey,
        valid_token_account_pubkey,
        UpdateProofArgs {
            action_id: create_proof_action_id,
            data: [1u8; 32],
            offset: 0u32,
        },
        &payer,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not update proof account: Invalid proof account"
    );
}

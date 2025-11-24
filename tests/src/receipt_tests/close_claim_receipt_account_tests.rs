use security_token_client::types::{ClaimDistributionArgs, CloseClaimReceiptArgs, CreateProofArgs};
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::{
    claim_tests::claim_helpers::{
        create_distribution_for_users, create_leaves, create_token_accounts_for_owners,
        execute_claim_distribution, start_with_context_and_transfer_hook,
    },
    helpers::{
        assert_account_exists, assert_transaction_success, create_minimal_security_token_mint,
        create_spl_account, get_balance, TX_FEE,
    },
    proof_tests::proof_helpers::{
        create_create_proof_account_verification_config, execute_create_proof_account,
        find_proof_pda,
    },
    receipt_tests::receipt_helpers::{close_claim_receipt_account, find_claim_action_receipt_pda},
};

#[tokio::test]
async fn test_should_close_claim_receipt_proof_argument() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 0 as usize;
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let total_distribution_ui_amount = 1000u64;
    let eligible_accounts_and_amounts = [
        (&token_account_pubkey, 100u64),
        (&Pubkey::new_unique(), 200u64),
        (&Pubkey::new_unique(), 300u64),
    ];
    let leaves = create_leaves(
        &eligible_accounts_and_amounts,
        &distribution_mint_pubkey,
        decimals,
        action_id,
    );

    let (
        merkle_tree,
        permanent_delegate_authority,
        _distribution_escrow_token_account,
        claim_distribution_verification_config,
    ) = create_distribution_for_users(
        context,
        &distribution_mint_keypair,
        mint_authority_pda,
        &mint_creator,
        action_id,
        total_distribution_ui_amount,
        decimals,
        &leaves,
    )
    .await;

    let leaf = &leaves[owner_with_token_account_index];
    let eligible_token_account = &leaf.eligible_token_account;
    let eligible_amount = leaf.amount;
    let merkle_proof = merkle_tree.get_proof_of_leaf(owner_with_token_account_index);
    let merkle_root = merkle_tree.get_root();
    let (receipt_pda, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    // Initiate external settlement without token transfer to speed up test
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey,
        claim_distribution_verification_config,
        permanent_delegate_authority,
        distribution_mint_pubkey,
        *eligible_token_account,
        None,
        receipt_pda,
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: owner_with_token_account_index as u32,
            merkle_proof: Some(merkle_proof.clone()),
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verify receipt was created
    let receipt_account = assert_account_exists(context, receipt_pda, true)
        .await
        .expect("Receipt account should be created");

    let balance_before = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    // Close the claim receipt account
    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        receipt_pda,
        distribution_mint_pubkey,
        *eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof.clone()),
        },
    )
    .await;
    assert_transaction_success(result);

    // Verify receipt was closed
    assert_account_exists(context, receipt_pda, false).await;

    // Verify rent refunded
    let balance_after = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    let rent_refund = balance_after - balance_before + TX_FEE;
    let receipt_account_rent = receipt_account.lamports;
    assert_eq!(
        rent_refund, receipt_account_rent,
        "Payer should receive rent lamports from closed Receipt account"
    );

    // Close again should fail
    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        receipt_pda,
        distribution_mint_pubkey,
        *eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof.clone()),
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close already closed receipt account"
    );
}

#[tokio::test]
async fn test_should_close_claim_receipt_proof_account() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 0 as usize;
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let total_distribution_ui_amount = 1000u64;
    let eligible_accounts_and_amounts = [
        (&token_account_pubkey, 100u64),
        (&Pubkey::new_unique(), 200u64),
        (&Pubkey::new_unique(), 300u64),
    ];
    let leaves = create_leaves(
        &eligible_accounts_and_amounts,
        &distribution_mint_pubkey,
        decimals,
        action_id,
    );

    let (
        merkle_tree,
        permanent_delegate_authority,
        _distribution_escrow_token_account,
        claim_distribution_verification_config,
    ) = create_distribution_for_users(
        context,
        &distribution_mint_keypair,
        mint_authority_pda,
        &mint_creator,
        action_id,
        total_distribution_ui_amount,
        decimals,
        &leaves,
    )
    .await;

    let leaf = &leaves[owner_with_token_account_index];
    let eligible_token_account = &leaf.eligible_token_account;
    let eligible_amount = leaf.amount;
    let merkle_proof = merkle_tree.get_proof_of_leaf(owner_with_token_account_index);
    let merkle_root = merkle_tree.get_root();
    let (receipt_pda, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    let (proof_account, _) = find_proof_pda(&token_account_pubkey, action_id);
    let create_proof_verification_config = create_create_proof_account_verification_config(
        context,
        &distribution_mint_keypair,
        mint_authority_pda,
        vec![],
        Some(&mint_creator),
    )
    .await;

    let result = execute_create_proof_account(
        &context.banks_client,
        distribution_mint_pubkey,
        create_proof_verification_config,
        proof_account,
        distribution_mint_pubkey,
        token_account_pubkey,
        CreateProofArgs {
            action_id,
            data: merkle_proof,
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Initiate external settlement without token transfer to speed up test
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey,
        claim_distribution_verification_config,
        permanent_delegate_authority,
        distribution_mint_pubkey,
        *eligible_token_account,
        None,
        receipt_pda,
        Some(proof_account),
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: owner_with_token_account_index as u32,
            merkle_proof: None,
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verify receipt was created
    let receipt_account = assert_account_exists(context, receipt_pda, true)
        .await
        .expect("Receipt account should be created");

    let balance_before = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    // Close the claim receipt account with proof account
    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        receipt_pda,
        distribution_mint_pubkey,
        *eligible_token_account,
        Some(proof_account),
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: None,
        },
    )
    .await;
    assert_transaction_success(result);

    // Verify receipt was closed
    assert_account_exists(context, receipt_pda, false).await;

    // Verify rent refunded
    let balance_after = get_balance(&mut context.banks_client, mint_creator.pubkey()).await;

    let rent_refund = balance_after - balance_before + TX_FEE;
    let receipt_account_rent = receipt_account.lamports;
    assert_eq!(
        rent_refund, receipt_account_rent,
        "Payer should receive rent lamports from closed Receipt account"
    );
    // Close again should fail
    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        receipt_pda,
        distribution_mint_pubkey,
        *eligible_token_account,
        Some(proof_account),
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: None,
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close already closed receipt account"
    );
}

#[tokio::test]
async fn test_should_not_close_not_owned_receipt_account() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let action_id = 42u64;
    let total_distribution_ui_amount = 1000u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new()];
    let eligible_token_accounts =
        create_token_accounts_for_owners(context, &eligible_owners, &distribution_mint_keypair)
            .await;

    let eligible_accounts_and_amounts = [
        (&eligible_token_accounts[0], 100u64),
        (&eligible_token_accounts[1], 200u64),
    ];
    let leaves = create_leaves(
        &eligible_accounts_and_amounts,
        &distribution_mint_pubkey,
        decimals,
        action_id,
    );

    let (
        merkle_tree,
        permanent_delegate_authority,
        _distribution_escrow_token_account,
        claim_distribution_verification_config,
    ) = create_distribution_for_users(
        context,
        &distribution_mint_keypair,
        mint_authority_pda,
        &mint_creator,
        action_id,
        total_distribution_ui_amount,
        decimals,
        &leaves,
    )
    .await;

    let merkle_root = merkle_tree.get_root();
    let mut claim_result: Vec<(Vec<[u8; 32]>, Pubkey)> = Vec::new();
    for (i, leaf) in leaves.iter().enumerate() {
        let merkle_proof = merkle_tree.get_proof_of_leaf(i);
        let (receipt_pda, _) = find_claim_action_receipt_pda(
            &distribution_mint_pubkey,
            &leaf.eligible_token_account,
            action_id,
            &merkle_proof,
        );

        let result = execute_claim_distribution(
            &mut context.banks_client,
            distribution_mint_pubkey,
            claim_distribution_verification_config,
            permanent_delegate_authority,
            distribution_mint_pubkey,
            leaf.eligible_token_account,
            None,
            receipt_pda,
            None,
            ClaimDistributionArgs {
                action_id: action_id,
                amount: leaf.amount,
                merkle_root,
                leaf_index: i as u32,
                merkle_proof: Some(merkle_proof.clone()),
            },
            &mint_creator,
        )
        .await;
        assert_transaction_success(result);
        assert_account_exists(context, receipt_pda, true)
            .await
            .expect("Receipt account should be created");

        claim_result.push((merkle_proof, receipt_pda));
    }

    let [(merkle_proof0, receipt_pda0), (merkle_proof1, receipt_pda1)] = &claim_result[..] else {
        panic!("Expected two claim results");
    };

    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        *receipt_pda1,
        distribution_mint_pubkey,
        leaves[0].eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof0.clone()),
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close receipt account with invalid receipt account"
    );

    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        *receipt_pda0,
        distribution_mint_pubkey,
        leaves[0].eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof1.clone()),
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close receipt account with invalid proof"
    );

    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        *receipt_pda0,
        distribution_mint_pubkey,
        leaves[1].eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof0.clone()),
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Should not close receipt account with invalid eligible token account"
    );

    // Close both at the end
    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        *receipt_pda0,
        distribution_mint_pubkey,
        leaves[0].eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof0.clone()),
        },
    )
    .await;
    assert_transaction_success(result);
    let result = close_claim_receipt_account(
        context,
        distribution_mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        *receipt_pda1,
        distribution_mint_pubkey,
        leaves[1].eligible_token_account,
        None,
        &mint_creator,
        CloseClaimReceiptArgs {
            action_id,
            merkle_proof: Some(merkle_proof1.clone()),
        },
    )
    .await;
    assert_transaction_success(result);
}

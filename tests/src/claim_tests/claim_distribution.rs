use security_token_client::types::{ClaimDistributionArgs, CreateProofArgs};
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::{
    claim_tests::claim_helpers::{
        create_distribution_for_users, create_leaves, create_token_accounts_for_owners,
        execute_claim_distribution, start_with_context_and_transfer_hook,
    },
    helpers::{
        assert_account_exists, assert_transaction_success, create_minimal_security_token_mint,
        create_spl_account, from_ui_amount, get_token_account_state,
    },
    proof_tests::proof_helpers::{
        create_create_proof_account_verification_config, execute_create_proof_account,
        find_proof_pda,
    },
    receipt_tests::receipt_helpers::find_claim_action_receipt_pda,
};

#[tokio::test]
async fn test_should_claim_distribution_settlement_proof_argument() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 100_000u64;
    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 1;
    // Create token account for one owner and generate random pubkeys for others to speed up test
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let eligible_accounts_and_amounts = [
        (&Pubkey::new_unique(), 100u64),
        (&token_account_pubkey, 200u64),
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
        distribution_escrow_token_account,
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
    let (receipt_account, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    let result = execute_claim_distribution(
        &mut context.banks_client,                       // context
        distribution_mint_pubkey.clone(),                // mint
        claim_distribution_verification_config.clone(),  // verification config
        permanent_delegate_authority.clone(),            // permanent delegate authority
        distribution_mint_pubkey.clone(),                // distribution mint
        eligible_token_account.clone(),                  // eligible token account
        Some(distribution_escrow_token_account.clone()), // distribution escrow token account
        receipt_account.clone(),                         // receipt account
        None,                                            // proof account
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

    // Verify final balance of eligible token account
    let eligible_token_account_data =
        get_token_account_state(&mut context.banks_client, *eligible_token_account).await;
    assert_eq!(eligible_token_account_data.base.amount, eligible_amount);

    // Verify final balance of distribution escrow token account
    let distribution_escrow_token_account_data =
        get_token_account_state(&mut context.banks_client, distribution_escrow_token_account).await;
    assert_eq!(
        distribution_escrow_token_account_data.base.amount,
        from_ui_amount(total_distribution_ui_amount, decimals) - eligible_amount
    );

    // Verify receipt was created
    assert_account_exists(context, receipt_account, true)
        .await
        .expect("Receipt account should be created");
}

#[tokio::test]
async fn test_should_claim_distribution_settlement_proof_account() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 1000u64;
    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 0;
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let eligible_accounts_and_amounts = [
        (&token_account_pubkey, 123u64),
        (&Pubkey::new_unique(), 100u64),
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
        distribution_escrow_token_account,
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
    let (receipt_account, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    let create_proof_args = CreateProofArgs {
        action_id,
        data: merkle_proof,
    };
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
        create_proof_args.clone(),
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account.clone(),
        Some(proof_account),
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: owner_with_token_account_index as u32,
            merkle_proof: None, // Proof is provided via proof account
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verify final balance of eligible token account
    let eligible_token_account_data =
        get_token_account_state(&mut context.banks_client, *eligible_token_account).await;
    assert_eq!(eligible_token_account_data.base.amount, eligible_amount);

    // Verify final balance of distribution escrow token account
    let distribution_escrow_token_account_data =
        get_token_account_state(&mut context.banks_client, distribution_escrow_token_account).await;
    assert_eq!(
        distribution_escrow_token_account_data.base.amount,
        from_ui_amount(total_distribution_ui_amount, decimals) - eligible_amount
    );

    // Verify receipt was created
    assert_account_exists(context, receipt_account, true)
        .await
        .expect("Receipt account should be created");
}

#[tokio::test]
async fn test_should_claim_distribution_external_settlement_proof_argument() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 3u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 1000u64;
    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 0;
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let eligible_accounts_and_amounts = [
        (&token_account_pubkey, 123u64),
        (&Pubkey::new_unique(), 100u64),
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
        distribution_escrow_token_account,
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
    let (receipt_account, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account.clone(),
        None, // do not provide escrow token account to initiate external settlement
        receipt_account.clone(),
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: owner_with_token_account_index as u32,
            merkle_proof: Some(merkle_proof),
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verify final balance of eligible token account
    let eligible_token_account_data =
        get_token_account_state(&mut context.banks_client, *eligible_token_account).await;
    assert_eq!(
        eligible_token_account_data.base.amount, 0,
        "Should not transfer tokens to eligible token account in external settlement"
    );

    // Verify final balance of distribution escrow token account
    let distribution_escrow_token_account_data =
        get_token_account_state(&mut context.banks_client, distribution_escrow_token_account).await;
    assert_eq!(
        distribution_escrow_token_account_data.base.amount,
        from_ui_amount(total_distribution_ui_amount, decimals),
        "Should not transfer tokens from escrow token account in external settlement"
    );

    // Verify receipt was created
    assert_account_exists(context, receipt_account, true)
        .await
        .expect("Receipt account should be created");
}

#[tokio::test]
async fn test_should_claim_distribution_external_settlement_proof_account() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 3u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 1000u64;
    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 0;
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let eligible_accounts_and_amounts = [
        (&token_account_pubkey, 123u64),
        (&Pubkey::new_unique(), 100u64),
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
        distribution_escrow_token_account,
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
    let (receipt_account, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    let create_proof_args = CreateProofArgs {
        action_id,
        data: merkle_proof,
    };
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
        create_proof_args.clone(),
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account.clone(),
        None, // do not provide escrow token account to initiate external settlement
        receipt_account.clone(),
        Some(proof_account),
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: owner_with_token_account_index as u32,
            merkle_proof: None, // Proof is provided via proof account
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verify final balance of eligible token account
    let eligible_token_account_data =
        get_token_account_state(&mut context.banks_client, *eligible_token_account).await;
    assert_eq!(
        eligible_token_account_data.base.amount, 0,
        "Should not transfer tokens to eligible token account in external settlement"
    );

    // Verify final balance of distribution escrow token account
    let distribution_escrow_token_account_data =
        get_token_account_state(&mut context.banks_client, distribution_escrow_token_account).await;
    assert_eq!(
        distribution_escrow_token_account_data.base.amount,
        from_ui_amount(total_distribution_ui_amount, decimals),
        "Should not transfer tokens from escrow token account in external settlement"
    );

    // Verify receipt was created
    assert_account_exists(context, receipt_account, true)
        .await
        .expect("Receipt account should be created");
}

#[tokio::test]
async fn test_should_not_claim_distribution_twice() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 100_000u64;
    let action_id = 42u64;
    let eligible_owners = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let owner_with_token_account_index = 1;
    let token_account_pubkey = create_spl_account(
        context,
        &distribution_mint_keypair,
        &eligible_owners[owner_with_token_account_index],
    )
    .await;

    let eligible_accounts_and_amounts = [
        (&Pubkey::new_unique(), 100u64),
        (&token_account_pubkey, 200u64),
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
        distribution_escrow_token_account,
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
    let (receipt_account, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account,
        action_id,
        &merkle_proof,
    );

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account.clone(),
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

    // Try to claim again
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account.clone(),
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
    assert!(
        result.is_err(),
        "Should not be able to claim distribution twice"
    );
}

#[tokio::test]
async fn test_should_not_claim_distribution_with_invalid_leaf_data() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 100_000u64;
    let action_id = 42u64;
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
        distribution_escrow_token_account,
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
    let leaf0 = &leaves[0];
    let eligible_token_account0 = &leaf0.eligible_token_account;
    let eligible_amount0 = leaf0.amount;
    let merkle_proof0 = merkle_tree.get_proof_of_leaf(0);
    let (receipt_account0, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account0,
        action_id,
        &merkle_proof0,
    );

    let leaf1 = &leaves[1];
    let eligible_token_account1 = &leaf1.eligible_token_account;
    let eligible_amount1 = leaf1.amount;
    let merkle_proof1 = merkle_tree.get_proof_of_leaf(1);

    // Proof from leaf1
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account0.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount0,
            merkle_root,
            leaf_index: 0u32,
            merkle_proof: Some(merkle_proof1.clone()),
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not be able to claim distribution with invalid merkle proof"
    );

    // leaf index 1
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account0.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount0,
            merkle_root,
            leaf_index: 1u32,
            merkle_proof: Some(merkle_proof0.clone()),
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not be able to claim distribution with invalid leaf index"
    );

    // eligible token account of leaf1
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account1.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount0,
            merkle_root,
            leaf_index: 0u32,
            merkle_proof: Some(merkle_proof0.clone()),
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not be able to claim distribution of invalid token account"
    );

    // eligible amount of leaf1
    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account0.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount1,
            merkle_root,
            leaf_index: 0u32,
            merkle_proof: Some(merkle_proof0.clone()),
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not be able to claim distribution with incorrect amount"
    );
}

#[tokio::test]
async fn test_should_not_claim_distribution_with_insufficient_amount_in_escrow() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 1u64;
    let action_id = 42u64;
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
        distribution_escrow_token_account,
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
    let leaf0 = &leaves[0];
    let eligible_token_account0 = &leaf0.eligible_token_account;
    let eligible_amount0 = leaf0.amount;
    let merkle_proof0 = merkle_tree.get_proof_of_leaf(0);
    let (receipt_account0, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account0,
        action_id,
        &merkle_proof0,
    );

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account0.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        None,
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount0,
            merkle_root,
            leaf_index: 0u32,
            merkle_proof: Some(merkle_proof0),
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not be able to claim distribution with insufficient amount in token escrow"
    );
}

#[tokio::test]
async fn test_should_not_claim_distribution_with_invalid_proof_account() {
    let context = &mut start_with_context_and_transfer_hook().await;

    let distribution_mint_keypair = Keypair::new();
    let distribution_mint_pubkey = distribution_mint_keypair.pubkey();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;

    let (mint_authority_pda, _freeze_authority_pda) = create_minimal_security_token_mint(
        context,
        &distribution_mint_keypair,
        Some(&mint_creator),
        decimals,
    )
    .await;

    let total_distribution_ui_amount = 1000u64;
    let action_id = 42u64;
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
        distribution_escrow_token_account,
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
    let leaf = &leaves[0];
    let eligible_token_account0 = &leaf.eligible_token_account;
    let eligible_amount = leaf.amount;
    let merkle_proof0 = merkle_tree.get_proof_of_leaf(0);
    let merkle_proof1 = merkle_tree.get_proof_of_leaf(1);
    let (receipt_account0, _) = find_claim_action_receipt_pda(
        &distribution_mint_pubkey,
        eligible_token_account0,
        action_id,
        &merkle_proof0,
    );

    // Create proof account with proof data for leaf1
    let (proof_account, _) = find_proof_pda(&eligible_token_account0, action_id);
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
        eligible_token_account0.clone(),
        CreateProofArgs {
            action_id,
            data: merkle_proof1.clone(), // proof data from leaf1
        },
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account0.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        Some(proof_account),
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: 0u32,
            merkle_proof: None,
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not claim distribution with invalid proof account"
    );

    let result = execute_claim_distribution(
        &mut context.banks_client,
        distribution_mint_pubkey.clone(),
        claim_distribution_verification_config.clone(),
        permanent_delegate_authority.clone(),
        distribution_mint_pubkey.clone(),
        eligible_token_account0.clone(),
        Some(distribution_escrow_token_account.clone()),
        receipt_account0.clone(),
        Some(proof_account),
        ClaimDistributionArgs {
            action_id: action_id,
            amount: eligible_amount,
            merkle_root,
            leaf_index: 0u32,
            merkle_proof: Some(merkle_proof0),
        },
        &mint_creator,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not claim distribution with invalid proof account but valid proof argument"
    );
}

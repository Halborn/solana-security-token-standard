use rstest::rstest;
use security_token_client::types::CreateDistributionEscrowArgs;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use spl_associated_token_account::get_associated_token_address_with_program_id;

use crate::{
    claim_tests::{
        claim_helpers::{
            execute_create_distribution_escrow_account, find_distribution_escrow_authority_pda,
        },
        merkle_tree_helpers::{create_merkle_tree, Leaf},
    },
    helpers::{
        assert_transaction_success, create_minimal_security_token_mint, get_token_account_state,
        start_with_context,
    },
};

#[tokio::test]
async fn test_should_create_distribution_account() {
    let context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda) =
        create_minimal_security_token_mint(context, &mint_keypair, Some(&mint_creator), decimals)
            .await;

    let action_id = 42u64;
    let mint_pubkey = mint_keypair.pubkey();
    let leaves = vec![
        Leaf::new(Pubkey::new_unique(), mint_pubkey, action_id, 1000),
        Leaf::new(Pubkey::new_unique(), mint_pubkey, action_id, 2000),
    ];
    let tree = create_merkle_tree(&leaves);
    let merkle_root = tree.get_root();

    let distribution_mint = &mint_pubkey;
    let (distribution_escrow_authority, _) =
        find_distribution_escrow_authority_pda(distribution_mint, action_id, &merkle_root);

    let distribution_token_account = get_associated_token_address_with_program_id(
        &distribution_escrow_authority,
        distribution_mint,
        &spl_token_2022::ID,
    );

    let create_distribution_escrow_args = CreateDistributionEscrowArgs {
        action_id,
        merkle_root,
    };

    let result = execute_create_distribution_escrow_account(
        &context.banks_client,
        mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        distribution_escrow_authority,
        distribution_mint.clone(),
        distribution_token_account,
        create_distribution_escrow_args,
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verify the escrow token account was created
    let distribution_escrow_token_account =
        get_token_account_state(&mut context.banks_client, distribution_token_account).await;

    assert!(
        distribution_escrow_token_account.base.owner.eq(&distribution_escrow_authority),
        "Distribution escrow token account should be owned by the distribution escrow authority PDA"
    );
}

#[tokio::test]
async fn test_should_not_create_distribution_account_twice() {
    let context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda) =
        create_minimal_security_token_mint(context, &mint_keypair, Some(&mint_creator), decimals)
            .await;

    let action_id = 42u64;
    let mint_pubkey = mint_keypair.pubkey();
    let leaves = vec![
        Leaf::new(Pubkey::new_unique(), mint_pubkey, action_id, 1000),
        Leaf::new(Pubkey::new_unique(), mint_pubkey, action_id, 2000),
    ];
    let tree = create_merkle_tree(&leaves);
    let merkle_root = tree.get_root();

    let distribution_mint = &mint_pubkey;
    let (distribution_escrow_authority, _) =
        find_distribution_escrow_authority_pda(distribution_mint, action_id, &merkle_root);

    let distribution_token_account = get_associated_token_address_with_program_id(
        &distribution_escrow_authority,
        distribution_mint,
        &spl_token_2022::ID,
    );

    let create_distribution_escrow_args = CreateDistributionEscrowArgs {
        action_id,
        merkle_root,
    };

    let result = execute_create_distribution_escrow_account(
        &context.banks_client,
        mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        distribution_escrow_authority,
        distribution_mint.clone(),
        distribution_token_account,
        create_distribution_escrow_args.clone(),
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let second_result = execute_create_distribution_escrow_account(
        &context.banks_client,
        mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        distribution_escrow_authority,
        distribution_mint.clone(),
        distribution_token_account,
        create_distribution_escrow_args.clone(),
        &mint_creator,
    )
    .await;
    assert!(
        second_result.is_err(),
        "Should not create distribution escrow account twice"
    );
}

#[rstest]
#[case(
    0u64,
    [1u8; 32],
    None,
    None,
    "Should fail with invalid action_id"
)]
#[case(
    1u64,
    [0u8; 32],
    None,
    None,
    "Should fail with invalid merkle_root"
)]
#[case(
    123u64,
    [1u8; 32],
    Some(Pubkey::new_unique()),
    None,
    "Should fail with invalid distribution_escrow_authority"
)]
#[case(
    123u64,
    [1u8; 32],
    None,
    Some(Pubkey::new_unique()),
    "Should fail with invalid distribution_token_account"
)]
#[tokio::test]
async fn test_should_not_create_distribution_account(
    #[case] action_id: u64,
    #[case] merkle_root: [u8; 32],
    #[case] invalid_distribution_escrow_authority: Option<Pubkey>,
    #[case] invalid_distribution_token_account: Option<Pubkey>,
    #[case] description: &str,
) {
    let context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_creator = context.payer.insecure_clone();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda) =
        create_minimal_security_token_mint(context, &mint_keypair, Some(&mint_creator), decimals)
            .await;

    let mint_pubkey = mint_keypair.pubkey();

    let distribution_mint = &mint_pubkey;
    let distribution_escrow_authority = invalid_distribution_escrow_authority.unwrap_or(
        find_distribution_escrow_authority_pda(distribution_mint, action_id, &merkle_root).0,
    );

    let distribution_token_account =
        invalid_distribution_token_account.unwrap_or(get_associated_token_address_with_program_id(
            &distribution_escrow_authority,
            distribution_mint,
            &spl_token_2022::ID,
        ));

    let create_distribution_escrow_args = CreateDistributionEscrowArgs {
        action_id,
        merkle_root,
    };

    let result = execute_create_distribution_escrow_account(
        &context.banks_client,
        mint_pubkey,
        mint_authority_pda,
        mint_creator.pubkey(),
        distribution_escrow_authority,
        distribution_mint.clone(),
        distribution_token_account,
        create_distribution_escrow_args,
        &mint_creator,
    )
    .await;
    assert!(result.is_err(), "{}", description);
}

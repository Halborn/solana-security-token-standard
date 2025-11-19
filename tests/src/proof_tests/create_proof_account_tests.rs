use security_token_client::{
    accounts::Proof, programs::SECURITY_TOKEN_PROGRAM_ID, types::CreateProofArgs,
};
use security_token_program::state::SecurityTokenDiscriminators;
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::{
    helpers::{
        assert_account_exists, assert_transaction_success, create_minimal_security_token_mint,
        create_spl_account, start_with_context,
    },
    proof_tests::proof_helpers::{
        create_create_proof_account_verification_config, execute_create_proof_account,
        find_proof_pda,
    },
};

#[tokio::test]
async fn test_should_create_proof_account() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let payer = context.payer.insecure_clone();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, Some(&payer), decimals)
            .await;

    let verification_config_pda = create_create_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let token_account_pubkey = create_spl_account(context, &mint_keypair, &payer).await;
    let action_id = 42u64;
    let proof_data = vec![[1u8; 32]];

    let create_proof_args = CreateProofArgs {
        action_id,
        data: proof_data,
    };
    let (proof_account, bump) = find_proof_pda(&token_account_pubkey, action_id);

    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_pda,
        proof_account,
        mint_pubkey,
        token_account_pubkey,
        create_proof_args.clone(),
        &payer,
    )
    .await;
    assert_transaction_success(result);

    // Verify the proof account was created
    let proof_account_data = assert_account_exists(context, proof_account, true)
        .await
        .unwrap();

    assert_eq!(
        proof_account_data.owner, SECURITY_TOKEN_PROGRAM_ID,
        "Proof account should be owned by security token program"
    );

    let proof = Proof::from_bytes(&proof_account_data.data).expect("Should deserialize proof data");
    assert_eq!(
        proof.discriminator,
        SecurityTokenDiscriminators::ProofDiscriminator as u8,
        "Proof account discriminator should match"
    );
    assert_eq!(proof.bump, bump, "Proof account bump should match");
    assert_eq!(
        proof.data, create_proof_args.data,
        "Proof account data should match"
    );
}

#[tokio::test]
async fn test_should_not_create_proof_account_twice() {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let payer = context.payer.insecure_clone();
    let decimals = 6u8;
    let (mint_authority_pda, _freeze_authority_pda) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, Some(&payer), decimals)
            .await;

    let verification_config_pda = create_create_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let token_account_pubkey = create_spl_account(context, &mint_keypair, &payer).await;
    let action_id = 42u64;
    let proof_data = vec![[1u8; 32]];

    let create_proof_args = CreateProofArgs {
        action_id,
        data: proof_data,
    };
    let (proof_account, _) = find_proof_pda(&token_account_pubkey, action_id);

    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_pda,
        proof_account,
        mint_pubkey,
        token_account_pubkey,
        create_proof_args.clone(),
        &payer,
    )
    .await;
    assert_transaction_success(result);

    // Verify the proof account was created
    assert_account_exists(context, proof_account, true)
        .await
        .unwrap();

    // Try creating the same proof account again
    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_pda,
        proof_account,
        mint_pubkey,
        token_account_pubkey,
        create_proof_args.clone(),
        &payer,
    )
    .await;
    assert!(
        result.is_err(),
        "Should not create the same proof account twice"
    );
}

#[rstest::rstest]
#[case(
    0u64,
    vec![[1u8; 32]],
    None,
    None,
    None,
    "Should fail with invalid action_id"
)]
#[case(
    42u64,
    vec![],
    None,
    None,
    None,
    "Should fail with zero proof_data"
)]
#[case(
    42u64,
    vec![[1u8; 32], [0u8; 32]],
    None,
    None,
    None,
    "Should fail with zero node in proof_data"
)]
#[case(
    42u64,
    vec![[1u8; 32]],
    Some(Pubkey::new_unique()),
    None,
    None,
    "Should fail with invalid_proof_account"
)]
#[case(
    42u64,
    vec![[1u8; 32]],
    None,
    Some(Pubkey::new_unique()),
    None,
    "Should fail with invalid_mint_pubkey"
)]
#[case(
    42u64,
    vec![[1u8; 32]],
    None,
    None,
    Some(Pubkey::new_unique()),
    "Should fail with invalid_token_account_pubkey"
)]
#[tokio::test]
async fn test_should_not_create_proof_account(
    #[case] action_id: u64,
    #[case] proof_data: Vec<[u8; 32]>,
    #[case] invalid_proof_account: Option<Pubkey>,
    #[case] invalid_mint_pubkey: Option<Pubkey>,
    #[case] invalid_token_account_pubkey: Option<Pubkey>,
    #[case] description: &str,
) {
    let mut context = &mut start_with_context().await;

    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let payer = context.payer.insecure_clone();
    let decimals = 6u8;
    let mint_authority_pda =
        create_minimal_security_token_mint(&mut context, &mint_keypair, Some(&payer), decimals)
            .await
            .0;

    let verification_config_pda = create_create_proof_account_verification_config(
        context,
        &mint_keypair,
        mint_authority_pda.clone(),
        vec![],
        Some(&payer),
    )
    .await;

    let valid_token_account = create_spl_account(context, &mint_keypair, &payer).await;
    let token_account_pubkey = invalid_token_account_pubkey.unwrap_or(valid_token_account);

    let create_proof_args = CreateProofArgs {
        action_id,
        data: proof_data,
    };
    let proof_account =
        invalid_proof_account.unwrap_or(find_proof_pda(&token_account_pubkey, action_id).0);
    let mint = invalid_mint_pubkey.unwrap_or(mint_pubkey);

    let result = execute_create_proof_account(
        &context.banks_client,
        mint_pubkey,
        verification_config_pda,
        proof_account,
        mint,
        token_account_pubkey,
        create_proof_args.clone(),
        &payer,
    )
    .await;
    assert!(&result.is_err(), "{}", description);

    // Verify the proof account was not created
    assert_account_exists(context, proof_account, false).await;
}

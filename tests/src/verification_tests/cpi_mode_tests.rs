use crate::{
    helpers::{
        assert_custom_error, assert_transaction_failure, assert_transaction_success,
        create_minimal_security_token_mint, create_spl_account, find_verification_config_pda,
        initialize_verification_config, send_tx,
    },
    verification_tests::verification_helpers::failing_dummy_program_processor,
};
use borsh::BorshDeserialize;
use security_token_client::{
    accounts::VerificationConfig,
    instructions::{MintBuilder, MINT_DISCRIMINATOR},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::InitializeVerificationConfigArgs,
};
use solana_program_test::*;
use solana_sdk::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey, signature::Keypair, signer::Signer, sysvar,
};

pub fn mint_dummy_program_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction_id = instruction_data.first().unwrap();
    assert_eq!(instruction_id, &MINT_DISCRIMINATOR);
    let amount = u64::from_le_bytes(
        instruction_data[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    assert_eq!(amount, 1000);
    Ok(())
}

#[tokio::test]
async fn test_mint_cpi_mode() {
    const NUM_VERIFICATION_PROGRAMS: usize = 5;

    let verification_program_ids: Vec<Pubkey> = (0..NUM_VERIFICATION_PROGRAMS)
        .map(|_| Pubkey::new_unique())
        .collect();

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);

    for (i, program_id) in verification_program_ids.iter().enumerate() {
        pt.add_program(
            Box::leak(format!("dummy_program_{}", i + 1).into_boxed_str()),
            *program_id,
            processor!(mint_dummy_program_processor),
        );
    }

    let mint_keypair = Keypair::new();
    let source_owner = Keypair::new();
    let mut context = pt.start_with_context().await;

    let (mint_authority_pda, _freeze_authority_pda, _token_program) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, 6).await;

    let (verification_config_pda, _) =
        find_verification_config_pda(mint_keypair.pubkey(), MINT_DISCRIMINATOR);

    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: MINT_DISCRIMINATOR,
        cpi_mode: true,
        program_addresses: verification_program_ids.clone(),
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &initialize_verification_config_args,
    )
    .await;

    let destination_ata = create_spl_account(&mut context, &mint_keypair, &source_owner).await;

    // Read verification config from blockchain to get program addresses (like a real client would)
    let config_account = context
        .banks_client
        .get_account(verification_config_pda)
        .await
        .unwrap()
        .expect("VerificationConfig should exist");

    let verification_config = VerificationConfig::try_from_slice(&config_account.data)
        .expect("Should be able to deserialize VerificationConfig");

    let mut mint_builder = MintBuilder::new();
    mint_builder
        .mint(mint_keypair.pubkey())
        .verification_config(verification_config_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .destination(destination_ata)
        .mint_account(mint_keypair.pubkey())
        .mint_authority(mint_authority_pda)
        .amount(1000);

    // Add verification program accounts from config (simulating client behavior)
    for program_id in &verification_config.verification_programs {
        mint_builder.add_remaining_account(solana_sdk::instruction::AccountMeta::new_readonly(
            *program_id,
            false,
        ));
    }
    let mint_ix = mint_builder.instruction();
    let result = send_tx(
        &context.banks_client,
        vec![mint_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_transaction_success(result);
}

#[tokio::test]
async fn test_mint_cpi_mode_error_cases() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);

    let dummy_program_1 = Pubkey::new_unique();
    let dummy_program_2 = Pubkey::new_unique();

    pt.add_program(
        "dummy_program_1",
        dummy_program_1,
        processor!(mint_dummy_program_processor),
    );
    pt.add_program(
        "dummy_program_2",
        dummy_program_2,
        processor!(failing_dummy_program_processor),
    );

    let mint_keypair = Keypair::new();
    let source_owner = Keypair::new();
    let mut context = pt.start_with_context().await;

    let (mint_authority_pda, _freeze_authority_pda, _token_program) =
        create_minimal_security_token_mint(&mut context, &mint_keypair, None, 6).await;

    let (verification_config_pda, _) =
        find_verification_config_pda(mint_keypair.pubkey(), MINT_DISCRIMINATOR);

    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: MINT_DISCRIMINATOR,
        cpi_mode: true,
        program_addresses: vec![dummy_program_1, dummy_program_2],
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &initialize_verification_config_args,
    )
    .await;

    let destination_ata = create_spl_account(&mut context, &mint_keypair, &source_owner).await;

    // Read verification config from blockchain to get program addresses (like a real client would)
    let config_account = context
        .banks_client
        .get_account(verification_config_pda)
        .await
        .unwrap()
        .expect("VerificationConfig should exist");

    let verification_config = VerificationConfig::try_from_slice(&config_account.data)
        .expect("Should be able to deserialize VerificationConfig");

    let mut mint_builder = MintBuilder::new();
    mint_builder
        .mint(mint_keypair.pubkey())
        .verification_config(verification_config_pda)
        .instructions_sysvar(sysvar::instructions::ID)
        .destination(destination_ata)
        .mint_account(mint_keypair.pubkey())
        .mint_authority(mint_authority_pda)
        .amount(1000);

    let mint_ix = mint_builder.instruction();
    let result = send_tx(
        &context.banks_client,
        vec![mint_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    // Transaction should fail without verification program accounts
    assert_transaction_failure(result);
    for program_id in &verification_config.verification_programs {
        mint_builder.add_remaining_account(solana_sdk::instruction::AccountMeta::new_readonly(
            *program_id,
            false,
        ));
    }
    let mint_ix = mint_builder.instruction();
    let result = send_tx(
        &context.banks_client,
        vec![mint_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    // Transaction should fail with custom error from failing dummy program
    assert_custom_error(result, 0x1111);
}

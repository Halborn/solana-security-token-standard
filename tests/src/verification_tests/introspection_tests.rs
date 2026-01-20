use crate::{
    helpers::{
        add_dummy_verification_program, assert_security_token_error, assert_transaction_success, find_mint_authority_pda, find_mint_freeze_authority_pda, find_verification_config_pda, initialize_mint, initialize_verification_config, send_tx
    },
    verification_tests::verification_helpers::dummy_program_processor,
};
use borsh::BorshSerialize;
use rstest::*;
use security_token_client::{
    errors::SecurityTokenProgramError,
    instructions::{UpdateMetadataBuilder, VerifyBuilder, UPDATE_METADATA_DISCRIMINATOR},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{
        InitializeMintArgs, InitializeVerificationConfigArgs, MetadataPointerArgs, MintArgs,
        TokenMetadataArgs, UpdateMetadataArgs, VerifyArgs,
    },
};
use solana_program_test::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
};
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;

use solana_system_interface::instruction as system_instruction;
use solana_system_interface::program as system_program;

struct VerificationTestContext {
    context: ProgramTestContext,
    dummy_program_1_id: Pubkey,
    dummy_program_2_id: Pubkey,
    mint_keypair: Keypair,
    verification_config_pda: Pubkey,
}

#[fixture]
async fn verification_test_setup() -> VerificationTestContext {
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    pt.add_program(
        "dummy_program_1",
        dummy_program_1_id,
        processor!(dummy_program_processor),
    );
    pt.add_program(
        "dummy_program_2",
        dummy_program_2_id,
        processor!(dummy_program_processor),
    );

    add_dummy_verification_program(&mut pt);

    let mut context = pt.start_with_context().await;
    let mint_keypair = Keypair::new();

    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());

    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let initialize_mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
    };

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &initialize_mint_args,
    )
    .await;

    let (verification_config_pda, _) =
        find_verification_config_pda(mint_keypair.pubkey(), UPDATE_METADATA_DISCRIMINATOR);

    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: verification_programs,
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &initialize_verification_config_args,
    )
    .await;

    VerificationTestContext {
        context,
        dummy_program_1_id,
        dummy_program_2_id,
        mint_keypair,
        verification_config_pda,
    }
}

#[rstest]
#[tokio::test]
async fn test_verify_without_prior_verification_calls(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let verify_only_ix = VerifyBuilder::new()
        .mint(setup.mint_keypair.pubkey())
        .verification_config(setup.verification_config_pda)
        .verify_args(VerifyArgs {
            ix: UPDATE_METADATA_DISCRIMINATOR,
            instruction_data: vec![],
        })
        .instruction();

    let result = send_tx(
        &setup.context.banks_client,
        vec![verify_only_ix],
        &setup.context.payer.pubkey(),
        vec![&setup.context.payer],
    )
    .await;
    assert_security_token_error(
        result,
        SecurityTokenProgramError::VerificationProgramNotFound,
    );
}

#[rstest]
#[tokio::test]
async fn test_verify_with_proper_prior_calls_succeeds(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();

    let success_instructions = vec![
        Instruction {
            program_id: setup.dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        Instruction {
            program_id: setup.dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
    ];

    let success_verify_accounts = vec![
        AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
        AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
    ];

    let verify_instruction_success = VerifyBuilder::new()
        .mint(setup.mint_keypair.pubkey())
        .verification_config(setup.verification_config_pda)
        .verify_args(VerifyArgs {
            ix: UPDATE_METADATA_DISCRIMINATOR,
            instruction_data: vec![1u8],
        })
        .add_remaining_accounts(&success_verify_accounts)
        .instruction();

    let mut success_tx_instructions: Vec<Instruction> = success_instructions.clone();
    success_tx_instructions.push(verify_instruction_success);

    let result = send_tx(
        &setup.context.banks_client,
        success_tx_instructions,
        &setup.context.payer.pubkey(),
        vec![&setup.context.payer],
    )
    .await;
    assert_transaction_success(result);
}

#[rstest]
#[tokio::test]
async fn test_verify_with_wrong_discriminator_fails(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();

    let instructions = vec![
        Instruction {
            program_id: setup.dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![128u8, 1u8],
        },
        Instruction {
            program_id: setup.dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
    ];

    let success_verify_accounts = vec![
        AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
        AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
    ];

    let verify_ix = VerifyBuilder::new()
        .mint(setup.mint_keypair.pubkey())
        .verification_config(setup.verification_config_pda)
        .verify_args(VerifyArgs {
            ix: UPDATE_METADATA_DISCRIMINATOR,
            instruction_data: vec![],
        })
        .add_remaining_accounts(&success_verify_accounts)
        .instruction();

    let mut tx_instructions = instructions.clone();
    tx_instructions.push(verify_ix);

    let result = send_tx(
        &setup.context.banks_client,
        tx_instructions,
        &setup.context.payer.pubkey(),
        vec![&setup.context.payer],
    )
    .await;
    assert_security_token_error(
        result,
        SecurityTokenProgramError::VerificationProgramNotFound,
    );
}

#[rstest]
#[tokio::test]
async fn test_verify_with_system_instructions_succeeds(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();

    let instructions = vec![
        system_instruction::transfer(
            &setup.context.payer.pubkey(),
            &setup.mint_keypair.pubkey(),
            1,
        ),
        Instruction {
            program_id: setup.dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        system_instruction::transfer(
            &setup.context.payer.pubkey(),
            &setup.mint_keypair.pubkey(),
            1,
        ),
        Instruction {
            program_id: setup.dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        Instruction {
            program_id: setup.dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![125u8, 1u8],
        },
    ];

    let success_verify_accounts = vec![
        AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
        AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
    ];

    let verify_ix = VerifyBuilder::new()
        .mint(setup.mint_keypair.pubkey())
        .verification_config(setup.verification_config_pda)
        .verify_args(VerifyArgs {
            ix: UPDATE_METADATA_DISCRIMINATOR,
            instruction_data: vec![1u8],
        })
        .add_remaining_accounts(&success_verify_accounts)
        .instruction();

    let mut tx_instructions = instructions.clone();
    tx_instructions.push(verify_ix);

    let result = send_tx(
        &setup.context.banks_client,
        tx_instructions,
        &setup.context.payer.pubkey(),
        vec![&setup.context.payer],
    )
    .await;
    assert_transaction_success(result);
}

#[rstest]
#[tokio::test]
async fn test_verify_with_correct_accounts_but_wrong_data_fails(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();

    // Programs are called with correct discriminator and data
    let instructions = vec![
        Instruction {
            program_id: setup.dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8, 2u8],
        },
        Instruction {
            program_id: setup.dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8, 2u8],
        },
    ];

    let verify_accounts = vec![
        AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
        AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
    ];

    // Verify instruction has wrong data (more arguments for the target instruction)
    let verify_ix = VerifyBuilder::new()
        .mint(setup.mint_keypair.pubkey())
        .verification_config(setup.verification_config_pda)
        .verify_args(VerifyArgs {
            ix: UPDATE_METADATA_DISCRIMINATOR,
            instruction_data: vec![1u8, 2u8, 3u8],
        })
        .add_remaining_accounts(&verify_accounts)
        .instruction();

    let mut tx_instructions = instructions;
    tx_instructions.push(verify_ix);

    let result = send_tx(
        &setup.context.banks_client,
        tx_instructions,
        &setup.context.payer.pubkey(),
        vec![&setup.context.payer],
    )
    .await;

    assert_security_token_error(
        result,
        SecurityTokenProgramError::VerificationProgramNotFound,
    );
}

#[tokio::test]
async fn test_update_metadata_under_verification() {
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);

    // Add dummy programs using builtin functions
    pt.add_program(
        "dummy_program_1",
        dummy_program_1_id,
        processor!(dummy_program_processor),
    );
    pt.add_program(
        "dummy_program_2",
        dummy_program_2_id,
        processor!(dummy_program_processor),
    );
    add_dummy_verification_program(&mut pt);

    let mint_keypair = solana_sdk::signature::Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";

    let (mint_authority_pda, _bump) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());

    let (freeze_authority_pda, _bump) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let initialize_mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: Some(MetadataPointerArgs {
            authority: context.payer.pubkey(),
            metadata_address: mint_keypair.pubkey(),
        }),
        ix_metadata: Some(TokenMetadataArgs {
            name: name.to_string().into(),
            symbol: symbol.to_string().into(),
            uri: uri.to_string().into(),
            additional_metadata: vec![],
        }),
        ix_scaled_ui_amount: None,
    };

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &initialize_mint_args,
    )
    .await;

    let (verification_config_pda, _bump) =
        find_verification_config_pda(mint_keypair.pubkey(), UPDATE_METADATA_DISCRIMINATOR);
    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: verification_programs,
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &initialize_verification_config_args,
    )
    .await;

    let updated_name = "Updated Security Token";
    let updated_symbol = "UHST";
    let updated_uri = "https://example.com/tokens";

    let update_metadata_args = UpdateMetadataArgs {
        metadata: TokenMetadataArgs {
            name: updated_name.to_string().into(),
            symbol: updated_symbol.to_string().into(),
            uri: updated_uri.to_string().into(),
            additional_metadata: vec![],
        },
    };

    let update_metadata_ix = UpdateMetadataBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(verification_config_pda)
        .instructions_sysvar_or_creator(sysvar::instructions::ID)
        .mint_account(mint_keypair.pubkey())
        .mint_authority(mint_authority_pda)
        .payer(context.payer.pubkey())
        .update_metadata_args(update_metadata_args.clone())
        .instruction();

    // Prepare metadata args
    let mut metadata_instruction_data = vec![UPDATE_METADATA_DISCRIMINATOR];
    metadata_instruction_data
        .extend_from_slice(update_metadata_args.try_to_vec().unwrap().as_slice());

    let result = send_tx(
        &context.banks_client,
        vec![update_metadata_ix.clone()],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    assert_security_token_error(
        result,
        SecurityTokenProgramError::VerificationProgramNotFound,
    );

    // Case: not enough accounts provided to verify
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();

    let verify_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: metadata_instruction_data.clone(),
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: metadata_instruction_data.clone(),
        },
    ];

    let mut tx_instructions = verify_instructions.clone();
    tx_instructions.push(update_metadata_ix.clone());

    let result = send_tx(
        &context.banks_client,
        tx_instructions,
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_security_token_error(
        result,
        SecurityTokenProgramError::AccountIntersectionMismatch,
    );

    let verify_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(mint_authority_pda, false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
                AccountMeta::new_readonly(mint_keypair.pubkey(), false),
                AccountMeta::new_readonly(TOKEN_22_PROGRAM_ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: metadata_instruction_data.clone(),
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(mint_authority_pda, false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
                AccountMeta::new_readonly(mint_keypair.pubkey(), false),
                AccountMeta::new_readonly(TOKEN_22_PROGRAM_ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: metadata_instruction_data.clone(),
        },
    ];

    let mut tx_instructions = verify_instructions.clone();
    tx_instructions.push(update_metadata_ix);

    let result = send_tx(
        &context.banks_client,
        tx_instructions,
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_transaction_success(result);
}

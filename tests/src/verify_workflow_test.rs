use crate::helpers::{
    assert_security_token_error, assert_transaction_success, initialize_mint,
    initialize_verification_config,
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
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey as SolanaPubkey,
};
use solana_program_test::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
    transaction::Transaction,
};
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;

use solana_system_interface::instruction as system_instruction;
use solana_system_interface::program as system_program;

// Simple dummy program processor that can succeed or fail based on instruction data
fn dummy_program_processor(
    _program_id: &SolanaPubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // The first byte determines instruction id
    // The second byte determines success (1) or failure (0)
    msg!("Dummy program called with {} bytes", instruction_data.len());

    // If instruction data is empty or first byte is 0, fail
    if instruction_data.is_empty() || instruction_data[1] == 0 {
        msg!("Dummy program: intentional failure");
        return Err(ProgramError::Custom(9999));
    }

    // Otherwise succeed
    msg!("Dummy program: success");
    Ok(())
}

// Another dummy program that always succeeds
fn dummy_program_2_processor(
    _program_id: &SolanaPubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // The first byte determines instruction id
    msg!(
        "Dummy program 2 called with {} bytes - always succeeds",
        instruction_data.len()
    );
    Ok(())
}

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
        processor!(dummy_program_2_processor),
    );

    let mut context = pt.start_with_context().await;
    let mint_keypair = Keypair::new();

    let (mint_authority_pda, _) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (freeze_authority_pda, _) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

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

    let (verification_config_pda, _) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
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
    let recent_blockhash = setup
        .context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap();

    let verify_only_ix = VerifyBuilder::new()
        .mint(setup.mint_keypair.pubkey())
        .verification_config(setup.verification_config_pda)
        .verify_args(VerifyArgs {
            ix: UPDATE_METADATA_DISCRIMINATOR,
            instruction_data: vec![],
        })
        .instruction();

    let transaction = Transaction::new_signed_with_payer(
        &[verify_only_ix],
        Some(&setup.context.payer.pubkey()),
        &[&setup.context.payer],
        recent_blockhash,
    );

    let result = setup
        .context
        .banks_client
        .process_transaction(transaction)
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
    let recent_blockhash = setup
        .context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap();

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

    let mut success_tx_instructions = success_instructions.clone();
    success_tx_instructions.push(verify_instruction_success);

    let transaction = Transaction::new_signed_with_payer(
        &success_tx_instructions,
        Some(&setup.context.payer.pubkey()),
        &[&setup.context.payer],
        recent_blockhash,
    );

    let result = setup
        .context
        .banks_client
        .process_transaction(transaction)
        .await;

    assert_transaction_success(result);
}

#[rstest]
#[tokio::test]
async fn test_verify_with_wrong_discriminator_fails(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let recent_blockhash = setup
        .context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap();

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

    let transaction = Transaction::new_signed_with_payer(
        &tx_instructions,
        Some(&setup.context.payer.pubkey()),
        &[&setup.context.payer],
        recent_blockhash,
    );

    let result = setup
        .context
        .banks_client
        .process_transaction(transaction)
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
    let recent_blockhash = setup
        .context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap();

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

    let transaction = Transaction::new_signed_with_payer(
        &tx_instructions,
        Some(&setup.context.payer.pubkey()),
        &[&setup.context.payer],
        recent_blockhash,
    );

    let result = setup
        .context
        .banks_client
        .process_transaction(transaction)
        .await;

    assert_transaction_success(result);
}

#[rstest]
#[tokio::test]
async fn test_verify_with_correct_accounts_but_wrong_data_fails(
    #[future] verification_test_setup: VerificationTestContext,
) {
    let setup = verification_test_setup.await;
    let recent_blockhash = setup
        .context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap();

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

    let transaction = Transaction::new_signed_with_payer(
        &tx_instructions,
        Some(&setup.context.payer.pubkey()),
        &[&setup.context.payer],
        recent_blockhash,
    );

    let result = setup
        .context
        .banks_client
        .process_transaction(transaction)
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
        processor!(dummy_program_2_processor),
    );

    let mint_keypair = solana_sdk::signature::Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";

    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

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
            update_authority: context.payer.pubkey(),
            mint: mint_keypair.pubkey(),
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

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );
    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
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
            update_authority: context.payer.pubkey(),
            mint: mint_keypair.pubkey(),
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

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[update_metadata_ix.clone()],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
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

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let mut instructions = verify_instructions.clone();
    instructions.push(update_metadata_ix.clone());

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
        .await;

    assert_security_token_error(
        result,
        SecurityTokenProgramError::AccountIntersectionMismatch,
    );

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let verify_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(mint_keypair.pubkey(), false),
                AccountMeta::new_readonly(mint_authority_pda, false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
                AccountMeta::new_readonly(TOKEN_22_PROGRAM_ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: metadata_instruction_data.clone(),
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(mint_keypair.pubkey(), false),
                AccountMeta::new_readonly(mint_authority_pda, false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
                AccountMeta::new_readonly(TOKEN_22_PROGRAM_ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: metadata_instruction_data.clone(),
        },
    ];

    let mut instructions = verify_instructions.clone();
    instructions.push(update_metadata_ix);

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
        .await;

    assert_transaction_success(result);
}

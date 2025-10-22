use crate::helpers::{assert_security_token_error, assert_transaction_success};
use security_token_client::{
    errors::SecurityTokenProgramError,
    instructions::{
        InitializeMint, InitializeMintInstructionArgs, InitializeVerificationConfig,
        InitializeVerificationConfigInstructionArgs, UpdateMetadata, UpdateMetadataInstructionArgs,
        Verify, VerifyInstructionArgs, UPDATE_METADATA_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{
        InitializeMintArgs, InitializeVerificationConfigArgs, MetadataPointerArgs, MintArgs,
        TokenMetadataArgs, UpdateMetadataArgs, VerifyArgs,
    },
};
// use security_token_client::{
//     InitializeArgs, InitializeMint, InitializeMintArgs, InitializeMintInstructionArgs,
//     InitializeVerificationConfig, InitializeVerificationConfigArgs,
//     InitializeVerificationConfigInstructionArgs, MetadataPointer, SecurityTokenError,
//     TokenMetadata, UpdateMetadata, UpdateMetadataArgs, UpdateMetadataInstructionArgs, Verify,
//     VerifyArgs, VerifyInstructionArgs, SECURITY_TOKEN_PROGRAM_ID, UPDATE_METADATA_DISCRIMINATOR,
// };
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

//TODO: Refactor to fixtures and rstest test cases
/// Test verifies that our verification workflow works with any program calls
#[tokio::test]
async fn test_verification_with_dummy_programs() -> Result<(), Box<dyn std::error::Error>> {
    // Create dummy program IDs for testing
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();

    // Setup program test with our security token program
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);

    // Disable BPF preference to use dummy programs
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

    let mut context = pt.start_with_context().await;
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    // Extract client and payer for easier use
    let banks_client = &mut context.banks_client;
    let payer = &context.payer;

    // Create mint keypair
    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    println!("Created mint: {}", mint_keypair.pubkey());
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

    let init_mint_instruction = InitializeMint {
        mint: mint_pubkey,
        payer: payer.pubkey(),
        authority: mint_authority_pda,
        token_program: spl_token_2022::ID,
        system_program: system_program::ID,
        rent_sysvar: solana_sdk::sysvar::rent::ID,
    }
    .instruction(InitializeMintInstructionArgs {
        initialize_mint_args: InitializeMintArgs {
            ix_mint: MintArgs {
                decimals: 6,
                mint_authority: payer.pubkey(),
                freeze_authority: freeze_authority_pda,
            },
            ix_metadata_pointer: None,
            ix_metadata: None,
            ix_scaled_ui_amount: None,
        },
    });

    let mint_transaction = Transaction::new_signed_with_payer(
        &[init_mint_instruction],
        Some(&payer.pubkey()),
        &[&payer, &mint_keypair], // Both payer and mint need to sign
        recent_blockhash,
    );

    banks_client
        .process_transaction(mint_transaction)
        .await
        .map_err(|e| format!("Failed to create mint: {:?}", e))?;
    println!("Mint created successfully: {}", mint_pubkey);

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_pubkey.as_ref(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_pubkey,
        verification_config_or_mint_authority: mint_authority_pda,
        instructions_sysvar_or_creator: payer.pubkey(),
        config_account: verification_config_pda,
        payer: payer.pubkey(),
        mint_account: mint_pubkey,
        system_program: system_program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        initialize_verification_config_args: InitializeVerificationConfigArgs {
            instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
            program_addresses: verification_programs,
        },
    });

    let config_transaction = Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    banks_client
        .process_transaction(config_transaction)
        .await
        .map_err(|e| format!("Failed to create VerificationConfig: {:?}", e))?;

    println!("VerificationConfig created for UpdateMetadata instruction");

    println!("Test 1: Verify without prior verification calls (should fail)");
    let verify_only_instruction = Verify {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction_with_remaining_accounts(
        VerifyInstructionArgs {
            verify_args: VerifyArgs {
                ix: UPDATE_METADATA_DISCRIMINATOR,
            },
        },
        &[],
    );

    let transaction = Transaction::new_signed_with_payer(
        &[verify_only_instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let result = banks_client.process_transaction(transaction).await;
    assert_security_token_error(
        result,
        SecurityTokenProgramError::VerificationProgramNotFound,
    );

    // Accounts verified by dummy programs
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();

    // Test 2: Verify with proper prior instruction calls (should succeed)
    let success_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
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

    println!("Test 2: Verify with proper prior instruction calls (should succeed)");
    let verify_instruction_success = Verify {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction_with_remaining_accounts(
        VerifyInstructionArgs {
            verify_args: VerifyArgs {
                ix: UPDATE_METADATA_DISCRIMINATOR,
            },
        },
        &success_verify_accounts,
    );

    let mut success_tx_instructions = success_instructions.clone();
    success_tx_instructions.push(verify_instruction_success);

    let transaction = Transaction::new_signed_with_payer(
        &success_tx_instructions,
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let result = banks_client.process_transaction(transaction).await;
    assert_transaction_success(result);

    println!("Test 3: Verify instruction discriminator (should fail)");
    let instructions = vec![
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![128u8, 1u8],
        },
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
    ];

    let verify_instruction = Verify {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction_with_remaining_accounts(
        VerifyInstructionArgs {
            verify_args: VerifyArgs {
                ix: UPDATE_METADATA_DISCRIMINATOR,
            },
        },
        &success_verify_accounts,
    );

    let mut tx_instructions = instructions.clone();
    tx_instructions.push(verify_instruction);

    let transaction = Transaction::new_signed_with_payer(
        &tx_instructions,
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let result = banks_client.process_transaction(transaction).await;
    assert_security_token_error(
        result,
        SecurityTokenProgramError::VerificationProgramNotFound,
    );

    println!("Test 4: Verify instruction with system instruction (should succeed)");
    let instructions = vec![
        system_instruction::transfer(&payer.pubkey(), &mint_pubkey, 1),
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        system_instruction::transfer(&payer.pubkey(), &mint_pubkey, 1),
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![125u8, 1u8],
        },
    ];

    let verify_instruction = Verify {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction_with_remaining_accounts(
        VerifyInstructionArgs {
            verify_args: VerifyArgs {
                ix: UPDATE_METADATA_DISCRIMINATOR,
            },
        },
        &success_verify_accounts,
    );

    let mut tx_instructions = instructions.clone();
    tx_instructions.push(verify_instruction);

    let transaction = Transaction::new_signed_with_payer(
        &tx_instructions,
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let result = banks_client.process_transaction(transaction).await;
    assert_transaction_success(result);
    Ok(())
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

    let context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();
    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
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

    let ix = InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        authority: mint_authority_pda,
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
        rent_sysvar: sysvar::rent::ID,
    }
    .instruction(InitializeMintInstructionArgs {
        initialize_mint_args: InitializeMintArgs {
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
        },
    });

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;

    assert_transaction_success(result);

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        instructions_sysvar_or_creator: context.payer.pubkey(),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: system_program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        initialize_verification_config_args: InitializeVerificationConfigArgs {
            instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
            program_addresses: verification_programs,
        },
    });

    let config_transaction = Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let updated_name = "Updated Security Token";
    let updated_symbol = "UHST";
    let updated_uri = "https://example.com/tokens";

    let update_metadata_instruction = UpdateMetadata {
        verification_config_or_mint_authority: verification_config_pda,
        instructions_sysvar_or_creator: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_account: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction(UpdateMetadataInstructionArgs {
        update_metadata_args: UpdateMetadataArgs {
            metadata: TokenMetadataArgs {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name: updated_name.to_string().into(),
                symbol: updated_symbol.to_string().into(),
                uri: updated_uri.to_string().into(),
                additional_metadata: vec![],
            },
        },
    });

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[update_metadata_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    // Process transaction
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
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
    ];

    let update_metadata_instruction = UpdateMetadata {
        verification_config_or_mint_authority: verification_config_pda,
        instructions_sysvar_or_creator: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_account: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction(UpdateMetadataInstructionArgs {
        update_metadata_args: UpdateMetadataArgs {
            metadata: TokenMetadataArgs {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name: updated_name.to_string().into(),
                symbol: updated_symbol.to_string().into(),
                uri: updated_uri.to_string().into(),
                additional_metadata: vec![],
            },
        },
    });

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let mut instructions = verify_instructions.clone();
    instructions.push(update_metadata_instruction);

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    // Process transaction
    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
        .await;

    assert_security_token_error(
        result,
        SecurityTokenProgramError::AccountIntersectionMismatch,
    );

    // Success case: enough accounts provided to verify
    let update_metadata_instruction = UpdateMetadata {
        verification_config_or_mint_authority: verification_config_pda,
        instructions_sysvar_or_creator: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_account: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction(UpdateMetadataInstructionArgs {
        update_metadata_args: UpdateMetadataArgs {
            metadata: TokenMetadataArgs {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name: updated_name.to_string().into(),
                symbol: updated_symbol.to_string().into(),
                uri: updated_uri.to_string().into(),
                additional_metadata: vec![],
            },
        },
    });

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let verify_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(mint_keypair.pubkey(), false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
                AccountMeta::new_readonly(spl_token_2022_program, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(mint_keypair.pubkey(), false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
                AccountMeta::new_readonly(spl_token_2022_program, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: vec![UPDATE_METADATA_DISCRIMINATOR, 1u8],
        },
    ];

    let mut instructions = verify_instructions.clone();
    instructions.push(update_metadata_instruction);
    println!("Total instructions count: {}", instructions.len());

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    // Process transaction
    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
        .await;

    assert_transaction_success(result);
}

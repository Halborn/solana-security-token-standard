use crate::helpers::{
    assert_security_token_error, assert_transaction_failure, assert_transaction_success,
};
use borsh::BorshDeserialize;
use kaigan::types::RemainderVec;
use security_token_client::{
    InitializeArgs, InitializeMint, InitializeMintArgs, InitializeMintInstructionArgs,
    InitializeVerificationConfig, InitializeVerificationConfigArgs,
    InitializeVerificationConfigInstructionArgs, MetadataPointer, SecurityTokenError,
    TokenMetadata, UpdateMetadata, UpdateMetadataArgs, UpdateMetadataInstructionArgs, Verify,
    VerifyArgs, VerifyInstructionArgs, SECURITY_TOKEN_ID, UPDATE_METADATA_DISCRIMINATOR,
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

use solana_system_interface::program as system_program;

// Simple dummy program processor that can succeed or fail based on instruction data
fn dummy_program_processor(
    _program_id: &SolanaPubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Dummy program called with {} bytes", instruction_data.len());

    // If instruction data is empty or first byte is 0, fail
    if instruction_data.is_empty() || instruction_data[0] == 0 {
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
    msg!(
        "Dummy program 2 called with {} bytes - always succeeds",
        instruction_data.len()
    );
    Ok(())
}

/// Test verifies that our verification workflow works with any program calls
#[tokio::test]
async fn test_verification_with_dummy_programs() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    // Create dummy program IDs for testing
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();

    // Setup program test with our security token program
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);

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

    let init_mint_instruction = security_token_client::InitializeMint {
        mint: mint_pubkey,
        payer: payer.pubkey(),
        token_program: spl_token_2022::ID,
        system_program: system_program::ID,
        rent: solana_sdk::sysvar::rent::ID,
    }
    .instruction(security_token_client::InitializeMintInstructionArgs {
        args: security_token_client::InitializeArgs {
            ix_mint: security_token_client::InitializeMintArgs {
                decimals: 6,
                mint_authority: payer.pubkey(),
                freeze_authority: Some(payer.pubkey()),
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
        &SECURITY_TOKEN_ID,
    );

    // Create InitializeVerificationConfig instruction using client
    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let init_config_instruction = InitializeVerificationConfig {
        config_account: verification_config_pda,
        payer: payer.pubkey(),
        mint_account: mint_pubkey,
        authority: payer.pubkey(), // Using payer as authority for simplicity
        system_program: system_program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
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

    // Helper function to create verification test scenarios
    async fn run_verification_test(
        banks_client: &mut BanksClient,
        payer: &Keypair,
        mint: &Keypair,
        recent_blockhash: solana_sdk::hash::Hash,
        verification_config_pda: Pubkey,
        test_name: &str,
        verification_instructions: Vec<Instruction>, // Instructions that should be called before verify
        verify_accounts: Vec<AccountMeta>,           // Accounts to pass to verify instruction
        should_succeed: bool,                        // Expected result
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", test_name);

        // Create verify instruction
        let verify_instruction = Verify {
            mint_account: mint.pubkey(),
            verification_config: Some(verification_config_pda),
            instructions_sysvar: sysvar::instructions::ID,
        }
        .instruction_with_remaining_accounts(
            VerifyInstructionArgs {
                args: VerifyArgs {
                    ix: UPDATE_METADATA_DISCRIMINATOR,
                },
            },
            &verify_accounts,
        );

        // Combine all instructions: verification calls + verify check
        let mut all_instructions = verification_instructions;
        all_instructions.push(verify_instruction);

        let transaction = Transaction::new_signed_with_payer(
            &all_instructions,
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );

        let result = banks_client.process_transaction(transaction).await;

        if should_succeed {
            assert_transaction_success(result);
        } else {
            assert_transaction_failure(result);
        }
        Ok(())
    }

    println!("Test 1: Verify without prior verification calls (should fail)");
    run_verification_test(
        banks_client,
        payer,
        &mint_keypair,
        recent_blockhash,
        verification_config_pda,
        "Test 1: Verify without prior verification calls (should fail)",
        vec![], // No prior instructions
        vec![], // No verify accounts
        false,  // Should fail
    )
    .await?;

    // Account for verification programs
    let account_for_verification_1 = Keypair::new();
    let account_for_verification_2 = Keypair::new();
    let additional_account_for_verification = Keypair::new();

    // Test 2: Verify with proper prior instruction calls (should succeed)
    let test_2_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
                AccountMeta::new_readonly(additional_account_for_verification.pubkey(), false),
            ],
            data: vec![1u8],
        },
    ];

    let test_2_verify_accounts = vec![
        AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
        AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
    ];

    run_verification_test(
        banks_client,
        payer,
        &mint_keypair,
        recent_blockhash,
        verification_config_pda,
        "Test 2: Verify with proper prior instruction calls (should succeed)",
        test_2_instructions,
        test_2_verify_accounts,
        true, // Should succeed
    )
    .await?;

    // Test 3: Verify with different accounts than intersection (should succeed)
    let test_3_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![AccountMeta::new_readonly(
                account_for_verification_1.pubkey(),
                false,
            )],
            data: vec![1u8],
        },
    ];

    let test_3_verify_accounts = vec![AccountMeta::new_readonly(
        account_for_verification_1.pubkey(),
        false,
    )];

    run_verification_test(
        banks_client,
        payer,
        &mint_keypair,
        recent_blockhash,
        verification_config_pda,
        "Test 3: Verify with different accounts than intersection (should succeed)",
        test_3_instructions,
        test_3_verify_accounts,
        true, // Should succeed
    )
    .await?;

    // Test 4: Verify with correct accounts but verification program failure (should fail)
    let test_4_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8], // Success
        },
        Instruction {
            program_id: dummy_program_1_id, // Use dummy_program_1_id which can fail
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![0u8], // This will cause dummy_program_processor to fail
        },
    ];

    let test_4_verify_accounts = vec![
        AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
        AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
    ];

    run_verification_test(
        banks_client,
        payer,
        &mint_keypair,
        recent_blockhash,
        verification_config_pda,
        "Test 4: Verify with correct accounts but verification program failure (should fail)",
        test_4_instructions,
        test_4_verify_accounts,
        false, // Should fail because program fails
    )
    .await?;

    // Test 5: Verify with lacking accounts (should fail)
    let test_5_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
    ];

    let test_5_verify_accounts = vec![AccountMeta::new_readonly(
        account_for_verification_1.pubkey(),
        false,
    )];

    run_verification_test(
        banks_client,
        payer,
        &mint_keypair,
        recent_blockhash,
        verification_config_pda,
        "Test 5: Verify with lacking accounts (should fail)",
        test_5_instructions,
        test_5_verify_accounts,
        false, // Should fail - not all intersection accounts provided
    )
    .await?;

    // Test 6: Wrong mint
    let test_6_instructions = vec![
        Instruction {
            program_id: dummy_program_1_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
    ];

    let test_6_verify_accounts = vec![AccountMeta::new_readonly(
        account_for_verification_1.pubkey(),
        false,
    )];

    run_verification_test(
        banks_client,
        payer,
        &mint_keypair,
        recent_blockhash,
        verification_config_pda,
        "Test 6: Wrong mint (should fail)",
        test_6_instructions,
        test_6_verify_accounts,
        false, // Should fail - not all intersection accounts provided
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_update_metadata_under_verification() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
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

    let ix = InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
        rent: sysvar::rent::ID,
    }
    .instruction(InitializeMintInstructionArgs {
        args: InitializeArgs {
            ix_mint: InitializeMintArgs {
                decimals: 6,
                mint_authority: context.payer.pubkey(),
                freeze_authority: None, // No freeze authority for this test
            },
            ix_metadata_pointer: Some(MetadataPointer {
                authority: context.payer.pubkey(),
                metadata_address: mint_keypair.pubkey(),
            }),
            ix_metadata: Some(TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: name.len() as u32,
                name: name.to_string().into(),
                symbol_len: symbol.len() as u32,
                symbol: symbol.to_string().into(),
                uri_len: uri.len() as u32,
                uri: uri.to_string().into(),
                additional_metadata_len: 0,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&[]).unwrap(),
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

    if let Err(error) = &result {
        panic!("Transaction failed: {}", error);
    }

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let verification_programs = vec![dummy_program_1_id, dummy_program_2_id];
    let init_config_instruction = InitializeVerificationConfig {
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        authority: context.payer.pubkey(), // Using payer as authority for simplicity
        system_program: system_program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
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

    if let Err(error) = &result {
        panic!("Transaction failed: {}", error);
    }

    let updated_name = "Updated Security Token";
    let updated_symbol = "UHST";
    let updated_uri = "https://example.com/tokens";

    let update_metadata_instruction = UpdateMetadata {
        verification_config: Some(verification_config_pda),
        instructions_sysvar: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_for_update: mint_keypair.pubkey(),
        mint_authority: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction(UpdateMetadataInstructionArgs {
        args: UpdateMetadataArgs {
            metadata: TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: updated_name.len() as u32,
                name: updated_name.to_string().into(),
                symbol_len: updated_symbol.len() as u32,
                symbol: updated_symbol.to_string().into(),
                uri_len: updated_uri.len() as u32,
                uri: updated_uri.to_string().into(),
                additional_metadata_len: 0,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&[]).unwrap(),
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

    assert_security_token_error(result, SecurityTokenError::VerificationProgramNotFound);

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
            data: vec![1u8],
        },
        Instruction {
            program_id: dummy_program_2_id,
            accounts: vec![
                AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
                AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
            ],
            data: vec![1u8],
        },
    ];

    let update_metadata_instruction = UpdateMetadata {
        verification_config: Some(verification_config_pda),
        instructions_sysvar: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_for_update: mint_keypair.pubkey(),
        mint_authority: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction(UpdateMetadataInstructionArgs {
        args: UpdateMetadataArgs {
            metadata: TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: updated_name.len() as u32,
                name: updated_name.to_string().into(),
                symbol_len: updated_symbol.len() as u32,
                symbol: updated_symbol.to_string().into(),
                uri_len: updated_uri.len() as u32,
                uri: updated_uri.to_string().into(),
                additional_metadata_len: 0,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&[]).unwrap(),
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

    assert_security_token_error(result, SecurityTokenError::AccountIntersectionMismatch);

    // Success case: enough accounts provided to verify
    let update_metadata_instruction = UpdateMetadata {
        verification_config: Some(verification_config_pda),
        instructions_sysvar: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_for_update: mint_keypair.pubkey(),
        mint_authority: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction_with_remaining_accounts(
        UpdateMetadataInstructionArgs {
            args: UpdateMetadataArgs {
                metadata: TokenMetadata {
                    update_authority: context.payer.pubkey(),
                    mint: mint_keypair.pubkey(),
                    name_len: updated_name.len() as u32,
                    name: updated_name.to_string().into(),
                    symbol_len: updated_symbol.len() as u32,
                    symbol: updated_symbol.to_string().into(),
                    uri_len: updated_uri.len() as u32,
                    uri: updated_uri.to_string().into(),
                    additional_metadata_len: 0,
                    additional_metadata: RemainderVec::<u8>::try_from_slice(&[]).unwrap(),
                },
            },
        },
        &vec![
            AccountMeta::new_readonly(account_for_verification_1.pubkey(), false),
            AccountMeta::new_readonly(account_for_verification_2.pubkey(), false),
        ],
    );

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
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

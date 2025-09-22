use security_token_client::{
    InitializeArgs, InitializeMint, InitializeMintArgs, InitializeMintInstructionArgs,
    InitializeVerificationConfig, InitializeVerificationConfigArgs,
    InitializeVerificationConfigInstructionArgs, Verify, VerifyArgs, VerifyInstructionArgs,
    SECURITY_TOKEN_ID,
};
use security_token_program::instruction::{self, SecurityTokenInstruction};
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
async fn test_verification_with_dummy_programs() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    // Create dummy program IDs for testing
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();

    // Setup program test with our security token program
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);

    // Disable BPF preference to use builtin functions instead of .so files
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
        system_program: solana_sdk::system_program::ID,
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

    let mint_result = banks_client.process_transaction(mint_transaction).await;
    match mint_result {
        Ok(_) => println!("Mint created successfully: {}", mint_pubkey),
        Err(e) => {
            println!("Failed to create mint: {:?}", e);
            panic!("Cannot proceed without mint: {:?}", e);
        }
    }

    // Find verification config PDA using the same logic as program
    let mut instruction_discriminator = [0u8; 8];
    instruction_discriminator[0] = SecurityTokenInstruction::UpdateMetadata.discriminant();

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_pubkey.as_ref(),
            &instruction_discriminator,
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
        system_program: solana_sdk::system_program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator,
            program_addresses: verification_programs,
        },
    });

    let config_transaction = Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let config_result = banks_client.process_transaction(config_transaction).await;
    match config_result {
        Ok(_) => println!("VerificationConfig created for UpdateMetadata instruction"),
        Err(e) => {
            panic!("Cannot proceed without VerificationConfig: {:?}", e);
        }
    }

    println!("Test 1: Verify without prior verification calls (should fail)");
    let verify_only_instruction = Verify {
        mint_account: mint_pubkey,
        verification_config: Some(verification_config_pda),
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction(VerifyInstructionArgs {
        args: VerifyArgs {
            ix: SecurityTokenInstruction::UpdateMetadata.discriminant(),
        },
    });

    let verify_only_transaction = Transaction::new_signed_with_payer(
        &[verify_only_instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let verify_only_result = banks_client
        .process_transaction(verify_only_transaction)
        .await;

    match verify_only_result {
        Ok(_) => {
            panic!("Verification unexpectedly succeeded without prior calls");
        }
        Err(e) => {
            println!("Verification failed as expected: {:?}", e);
        }
    }

    // Test 2: Verify instruction WITH prior instruction (should succeed)
    println!("\nTest 2: Verify with prior instruction calls (should succeed)");

    // Create a prior instruction using a memo program (simple and should work)
    // We'll just create a simple instruction with one of our dummy programs
    let instruction_1 = Instruction {
        program_id: dummy_program_1_id,
        accounts: vec![],
        data: vec![1u8], // Dummy data - this will fail but we only need instruction count > 1
    };

    let instruction_2 = Instruction {
        program_id: dummy_program_2_id,
        accounts: vec![],
        data: vec![1u8], // Dummy data - this will succeed
    };

    // Create Verify instruction to check that verification programs were called
    let verify_instruction = Verify {
        mint_account: mint_pubkey,
        verification_config: Some(verification_config_pda),
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction(VerifyInstructionArgs {
        args: VerifyArgs {
            ix: SecurityTokenInstruction::UpdateMetadata.discriminant(),
        },
    });

    // Single transaction with: prior instruction + verify check
    let full_verification_transaction = Transaction::new_signed_with_payer(
        &[instruction_1, instruction_2, verify_instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let full_verify_result = banks_client
        .process_transaction(full_verification_transaction)
        .await;

    match full_verify_result {
        Ok(_) => {
            println!("Full verification workflow succeeded!");
        }
        Err(e) => {
            panic!("Verification with prior calls failed: {:?}", e);
        }
    }
}

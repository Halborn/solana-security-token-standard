//! Security Token Standard Integration Tests

use security_token_program::{
    instruction::SecurityTokenInstruction,
    processor::Processor,
    state::{Rate, Receipt, SecurityTokenMint, VerificationConfig, VerificationStatus},
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::signature::Signer;
use spl_pod::optional_keys::OptionalNonZeroPubkey;

#[tokio::test]
async fn test_program_loads() {
    let program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "security_token_program",
        program_id,
        processor!(Processor::process),
    );

    let (_banks_client, _payer, _recent_blockhash) = program_test.start().await;

    // Basic test that program loads successfully
    println!("Security Token program loaded successfully");
}

#[tokio::test]
async fn test_initialize_mint_instruction() {
    let program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "security_token_program",
        program_id,
        processor!(Processor::process),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Create initialize mint instruction
    let mint_account = Pubkey::new_unique();
    let instruction = Instruction::new_with_bytes(
        program_id,
        &[SecurityTokenInstruction::InitializeMint as u8],
        vec![
            AccountMeta::new(mint_account, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
    );

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    // Process transaction - should succeed with Phase 1 stub
    let result = banks_client.process_transaction(transaction).await;
    assert!(result.is_ok(), "Initialize mint instruction should succeed");
}

#[test]
fn test_state_structure_sizes() {
    // Verify all state structure sizes are reasonable for on-chain storage
    let mint_size = std::mem::size_of::<SecurityTokenMint>();
    let verification_config_size = std::mem::size_of::<VerificationConfig>();
    let verification_status_size = std::mem::size_of::<VerificationStatus>();
    let rate_size = std::mem::size_of::<Rate>();
    let receipt_size = std::mem::size_of::<Receipt>();

    println!("SecurityTokenMint size: {} bytes", mint_size);
    println!(
        "VerificationConfig size: {} bytes",
        verification_config_size
    );
    println!(
        "VerificationStatus size: {} bytes",
        verification_status_size
    );
    println!("Rate size: {} bytes", rate_size);
    println!("Receipt size: {} bytes", receipt_size);

    // All structures should be reasonable for on-chain storage
    assert!(mint_size <= 512, "SecurityTokenMint should be <= 512 bytes");
    assert!(
        verification_config_size <= 256,
        "VerificationConfig should be <= 256 bytes"
    );
    assert!(
        verification_status_size <= 256,
        "VerificationStatus should be <= 256 bytes"
    );
    assert!(rate_size <= 64, "Rate should be <= 64 bytes");
    assert!(receipt_size <= 128, "Receipt should be <= 128 bytes");
}

#[test]
fn test_verification_structures_defaults() {
    let config = VerificationConfig::default();
    // Test that all verification programs are None by default
    for program in config.verification_programs.iter() {
        assert_eq!(*program, OptionalNonZeroPubkey::default());
    }
    // Copy values to avoid packed field references
    let discriminator = config.instruction_discriminator;
    let flags = config.flags;
    assert_eq!(discriminator, [0; 8]);
    assert_eq!(flags, 0);

    let status = VerificationStatus::default();
    // Copy values to avoid packed field references
    let kyc_timestamp = status.kyc_timestamp;
    let aml_timestamp = status.aml_timestamp;
    let is_whitelisted = status.is_whitelisted;

    assert_eq!(kyc_timestamp, 0);
    assert_eq!(aml_timestamp, 0);
    assert_eq!(is_whitelisted, 0);
}

#[test]
fn test_corporate_actions_structures() {
    // Test Rate structure
    let rate = Rate {
        numerator: 3,
        denominator: 2,
        rounding: 0,
        _reserved: [0; 7],
    };
    // Copy values to avoid packed field references
    let numerator = rate.numerator;
    let denominator = rate.denominator;
    assert_eq!(numerator, 3);
    assert_eq!(denominator, 2);

    // Test Receipt structure
    let receipt = Receipt {
        action_id: 12345,
        account: solana_program::pubkey::Pubkey::new_unique(),
        amount: 1000,
        timestamp: 1640995200, // Jan 1, 2022
        _reserved: [0; 8],
    };
    // Copy values to avoid packed field references
    let action_id = receipt.action_id;
    let amount = receipt.amount;
    assert_eq!(action_id, 12345);
    assert_eq!(amount, 1000);
}

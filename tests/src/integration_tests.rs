//! Security Token Standard Integration Tests

use security_token_program::{
    instruction::SecurityTokenInstruction,
    processor::Processor,
    state::{SecurityTokenMint, VerificationConfig},
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::signature::Signer;

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
fn test_security_token_mint_size() {
    // Verify state structure sizes are reasonable
    let mint_size = std::mem::size_of::<SecurityTokenMint>();
    println!("SecurityTokenMint size: {} bytes", mint_size);

    // Should be a reasonable size for on-chain storage
    assert!(mint_size <= 512, "SecurityTokenMint should be <= 512 bytes");
}

#[test]
fn test_verification_config_defaults() {
    let config = VerificationConfig::default();
    assert_eq!(config.kyc_level, 0);
    assert_eq!(config.aml_required, 0);
    assert_eq!(config.accreditation_level, 0);
}

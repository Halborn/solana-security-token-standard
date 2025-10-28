use security_token_client::{
    errors::SecurityTokenProgramError, instructions::{InitializeMintBuilder, InitializeVerificationConfigBuilder}, programs::SECURITY_TOKEN_PROGRAM_ID, types::{InitializeMintArgs, InitializeVerificationConfigArgs}
};
use solana_program_test::{BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    instruction::InstructionError,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::TransactionError,
};

/// Helper function to assert that a transaction failed with a specific SecurityTokenError
pub fn assert_security_token_error(
    result: Result<(), BanksClientError>,
    expected_error: SecurityTokenProgramError,
) {
    match result {
        Err(e) => match e {
            BanksClientError::TransactionError(transaction_error) => match transaction_error {
                TransactionError::InstructionError(_, instruction_error) => match instruction_error
                {
                    InstructionError::Custom(error_code) => {
                        let expected_code = expected_error as u32;
                        assert_eq!(
                            error_code, expected_code,
                            "Expected error code {}, but got error code {}",
                            expected_code, error_code
                        );
                        println!("Test passed: Got expected error code {}", expected_code);
                    }
                    _ => panic!(
                        "Expected custom instruction error, got: {:?}",
                        instruction_error
                    ),
                },
                _ => panic!("Expected instruction error, got: {:?}", transaction_error),
            },
            _ => panic!("Expected transaction error, got: {:?}", e),
        },
        Ok(_) => panic!("Expected transaction to fail, but it succeeded"),
    }
}

pub fn assert_transaction_success(result: Result<(), BanksClientError>) {
    match result {
        Ok(_) => {
            println!("Test passed: Transaction succeeded as expected");
        }
        Err(e) => panic!(
            "Expected transaction to succeed, but it failed with: {:?}",
            e
        ),
    }
}

pub fn assert_transaction_failure(result: Result<(), BanksClientError>) {
    match result {
        Err(_) => {
            println!("Test passed: Transaction failed as expected");
        }
        Ok(_) => panic!("Expected transaction to fail, but it succeeded"),
    }
}

pub async fn initialize_mint(
    mint_keypair: &Keypair,
    context: &mut ProgramTestContext,
    mint_authority_pda: Pubkey,
    args: &InitializeMintArgs,
) {
    let ix = InitializeMintBuilder::new()
        .mint(mint_keypair.pubkey())
        .payer(context.payer.pubkey())
        .authority(mint_authority_pda)
        .initialize_mint_args(args.clone())
        .instruction();
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;

    assert_transaction_success(result);
}

pub async fn initialize_verification_config(
    mint_keypair: &Keypair,
    context: &mut ProgramTestContext,
    mint_authority_pda: Pubkey,
    verification_config_pda: Pubkey,
    args: &InitializeVerificationConfigArgs,
) {
    let ix = InitializeVerificationConfigBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(context.payer.pubkey())
        .mint_account(mint_keypair.pubkey())
        .payer(context.payer.pubkey())
        .config_account(verification_config_pda)
        .initialize_verification_config_args(args.clone())
        .instruction();
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;

    assert_transaction_success(result);
}

pub async fn start_with_context() -> ProgramTestContext {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);
    pt.start_with_context().await
}
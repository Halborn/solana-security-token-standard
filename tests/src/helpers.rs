use security_token_client::{
    errors::SecurityTokenProgramError,
    instructions::{InitializeMintBuilder, InitializeVerificationConfigBuilder},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{InitializeMintArgs, InitializeVerificationConfigArgs},
};
use solana_program_test::{BanksClient, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    instruction::InstructionError,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::TransactionError,
};

pub const TX_FEE: u64 = 5000;

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

pub async fn assert_account_exists(
    context: &mut ProgramTestContext,
    account_pubkey: Pubkey,
    should_check_existence: bool,
) -> Option<Account> {
    let account_info = context
        .banks_client
        .get_account(account_pubkey)
        .await
        .unwrap();

    if should_check_existence {
        assert!(
            account_info.is_some(),
            "Expected account {} to exist",
            account_pubkey
        );
    } else {
        assert!(
            account_info.is_none(),
            "Expected account {} to not exist",
            account_pubkey
        );
    }

    println!("Test passed: Account {} exists", account_pubkey);
    account_info
}

pub async fn initialize_mint(
    mint_keypair: &Keypair,
    context: &mut ProgramTestContext,
    mint_authority_pda: Pubkey,
    args: &InitializeMintArgs,
) {
    let mint_creator = &context.payer.insecure_clone();
    initialize_mint_for_creator(
        context,
        mint_keypair,
        mint_authority_pda,
        mint_creator,
        args,
    )
    .await;
}

pub async fn initialize_mint_for_creator(
    context: &mut ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    mint_creator: &Keypair,
    args: &InitializeMintArgs,
) {
    let payer = &mint_creator.pubkey();
    let ix = InitializeMintBuilder::new()
        .mint(mint_keypair.pubkey())
        .payer(payer.clone())
        .authority(mint_authority_pda)
        .initialize_mint_args(args.clone())
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(payer),
        &[&mint_creator, &mint_keypair],
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

pub fn initialize_program() -> ProgramTest {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);
    pt
}

pub async fn start_with_context() -> ProgramTestContext {
    let pt = initialize_program();
    pt.start_with_context().await
}

type Balance = u64;
pub async fn start_with_context_and_accounts(
    initial_accounts: Vec<(&Keypair, Balance)>,
) -> ProgramTestContext {
    let mut pt = initialize_program();

    // Preload all requested accounts
    for (kp, lamports) in initial_accounts {
        pt.add_account(
            kp.pubkey(),
            Account {
                lamports,
                data: vec![],
                owner: solana_system_interface::program::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    pt.start_with_context().await
}

pub async fn send_tx(
    banks_client: &BanksClient,
    ixs: Vec<solana_sdk::instruction::Instruction>,
    payer: &Pubkey,
    signers: Vec<&Keypair>,
) -> Result<(), BanksClientError> {
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &ixs,
        Some(payer),
        &signers,
        recent_blockhash,
    );

    banks_client.process_transaction(transaction).await
}

pub fn find_mint_authority_pda(mint: &Pubkey, creator: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"mint.authority", &mint.to_bytes(), &creator.to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

pub fn find_mint_freeze_authority_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint.to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

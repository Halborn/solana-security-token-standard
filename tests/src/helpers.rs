use security_token_client::{
    errors::SecurityTokenProgramError,
    instructions::{InitializeMintBuilder, InitializeVerificationConfigBuilder, MintBuilder},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{InitializeMintArgs, InitializeVerificationConfigArgs, MintArgs},
};
use solana_program::example_mocks::solana_sdk::sysvar;
use solana_program_test::{BanksClient, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    instruction::InstructionError,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::TransactionError,
};
use spl_token_2022::extension::StateWithExtensionsOwned;
use spl_token_2022::state::{Account as TokenAccount, Mint as TokenMint};

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
    let result = initialize_verification_config_for_payer(
        &context.banks_client,
        &context.payer,
        mint_keypair,
        mint_authority_pda,
        verification_config_pda,
        args,
    )
    .await;
    assert_transaction_success(result);
}

pub async fn initialize_verification_config_for_payer(
    banks_client: &BanksClient,
    payer: &Keypair,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    verification_config_pda: Pubkey,
    args: &InitializeVerificationConfigArgs,
) -> Result<(), BanksClientError> {
    let ix = InitializeVerificationConfigBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(payer.pubkey())
        .mint_account(mint_keypair.pubkey())
        .payer(payer.pubkey())
        .config_account(verification_config_pda)
        .initialize_verification_config_args(args.clone())
        .instruction();

    send_tx(banks_client, vec![ix], &payer.pubkey(), vec![payer]).await
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

pub fn find_permanent_delegate_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"mint.permanent_delegate", mint.as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

pub fn find_receipt_pda(mint: &Pubkey, action_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"receipt", &mint.as_ref(), &action_id.to_le_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

pub fn find_verification_config_pda(mint: Pubkey, instruction_discriminator: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"verification_config",
            &mint.as_ref(),
            &[instruction_discriminator],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

/// Create a minimal security token mint without metadata and scaled amount
pub async fn create_minimal_security_token_mint(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &solana_sdk::signature::Keypair,
    mint_creator: Option<&Keypair>,
    decimals: u8,
) -> (Pubkey, Pubkey, Pubkey) {
    let spl_token_2022_program =
        Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

    let payer = mint_creator.unwrap_or(&context.payer).insecure_clone();
    let mint_authority = payer.pubkey();

    let (mint_authority_pda, _bump) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &mint_authority);

    let (freeze_authority_pda, _bump) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals,
            mint_authority: mint_authority.clone(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
    };

    initialize_mint_for_creator(
        context,
        &mint_keypair,
        mint_authority_pda,
        &payer,
        &mint_args,
    )
    .await;

    (
        mint_authority_pda,
        freeze_authority_pda,
        spl_token_2022_program,
    )
}

/// Create associated token account for owner and mint
pub async fn create_token_account(
    banks_client: &BanksClient,
    owner: &Pubkey,
    mint: &Pubkey,
    payer: &Keypair,
) -> (Result<(), BanksClientError>, Pubkey) {
    let token_account_pubkey =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            &owner,
            &mint,
            &spl_token_2022::ID,
        );

    let create_destination_account_ix =
        spl_associated_token_account::instruction::create_associated_token_account_idempotent(
            &payer.pubkey(),
            &owner,
            &mint,
            &spl_token_2022::ID,
        );
    let signer = payer.insecure_clone();
    let signers = vec![&signer];
    let result = send_tx(
        banks_client,
        vec![create_destination_account_ix],
        &payer.pubkey(),
        signers,
    )
    .await;

    (result, token_account_pubkey)
}

/// Mint tokens to destination token account
pub async fn mint_tokens_to(
    banks_client: &BanksClient,
    amount: u64,
    mint: Pubkey,
    destination_account: Pubkey,
    mint_authority_pda: Pubkey,
    verification_config: Pubkey,
    payer: &Keypair,
) -> Result<(), BanksClientError> {
    let mint_ix = MintBuilder::new()
        .mint(mint)
        .verification_config(verification_config)
        .instructions_sysvar(sysvar::instructions::ID)
        .mint_account(mint)
        .mint_authority(mint_authority_pda)
        .destination(destination_account)
        .amount(amount)
        .instruction();

    let signer = payer.insecure_clone();
    let signers = vec![&signer];
    send_tx(banks_client, vec![mint_ix], &payer.pubkey(), signers).await
}

/// Convert UI amount to raw amount based on decimals
/// E.g. 1000 UI amount (3 deciamls) = 1_000_000 raw amount
pub fn from_ui_amount(amount: u64, decimals: u8) -> u64 {
    let factor = 10u64.pow(decimals as u32);
    amount * factor
}

/// Fetch and deserialize mint account state with extensions
pub async fn get_mint_state(
    banks_client: &mut BanksClient,
    mint: Pubkey,
) -> StateWithExtensionsOwned<TokenMint> {
    let account = banks_client
        .get_account(mint)
        .await
        .expect("mint account fetch")
        .expect("mint account must exist");

    StateWithExtensionsOwned::<TokenMint>::unpack(account.data)
        .expect("mint state should deserialize")
}

/// Fetch and deserialize token account state
pub async fn get_token_account_state(
    banks_client: &mut BanksClient,
    token_account: Pubkey,
) -> StateWithExtensionsOwned<TokenAccount> {
    let account = banks_client
        .get_account(token_account)
        .await
        .expect("token account fetch")
        .expect("token account must exist");

    StateWithExtensionsOwned::<TokenAccount>::unpack(account.data)
        .expect("token account state should deserialize")
}

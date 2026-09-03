//! End-to-end integration test for the Split Guard verification program in introspection mode.
//!
//! In introspection mode the security token Transfer instruction checks that each
//! configured verification program was called earlier in the same transaction (via the
//! instructions sysvar). The split_guard program acts as one such program: the caller
//! includes an explicit split_guard instruction (disc=TRANSFER_DISCRIMINATOR, with
//! split_guard_pda in accounts) *before* the security token Transfer.
//!
//! Transaction layout when split_guard is configured as a verification program:
//!   [split_guard_verify_ix(..., split_guard_pda),
//!    security_token_Transfer_ix]
//!
//! When the halt is active, split_guard_verify_ix returns Custom(0) and the whole
//! transaction fails before the transfer executes.
//!
//! Requires SBF builds of all three programs:
//! ```bash
//! ./scripts/build.sh sbf
//! cargo build-sbf --manifest-path examples/split-guard/Cargo.toml
//! SBF_OUT_DIR=$(pwd)/target/deploy cargo test --manifest-path examples/split-guard/Cargo.toml
//! ```

use security_token_client::{
    instructions::{
        InitializeMintBuilder, InitializeVerificationConfigBuilder, MintBuilder, TransferBuilder,
        MINT_DISCRIMINATOR, TRANSFER_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{
        InitializeMintArgs, InitializeVerificationConfigArgs, MintArgs, VerificationAccountMeta,
        VerificationProgramConfig,
    },
};
use security_token_program::{constants::seeds, error::SecurityTokenError};
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program_test::{
    processor, BanksClient, BanksClientError, ProgramTest, ProgramTestContext,
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::TransactionError,
};
use spl_token_2022::extension::StateWithExtensionsOwned;
use spl_token_2022::state::Account as TokenAccount;
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;
use spl_transfer_hook_interface::get_extra_account_metas_address;

const SPLIT_GUARD_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("SGuard1111111111111111111111111111111111111");

const DUMMY_VERIFICATION_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("DummyVer1f1cat1onProgram11111111111111111111");

const SPLIT_GUARD_SEED: &[u8] = b"split_guard";
const ACTIVATE_HALT_DISCRIMINATOR: u8 = 0;
const DEACTIVATE_HALT_DISCRIMINATOR: u8 = 1;
const ERR_SPLIT_HALT_ACTIVE: u32 = 0;

fn dummy_verification_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}

fn find_split_guard_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SPLIT_GUARD_SEED, mint.as_ref()], &SPLIT_GUARD_PROGRAM_ID)
}

fn find_mint_authority_pda(mint: &Pubkey, creator: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::MINT_AUTHORITY, &mint.to_bytes(), &creator.to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

fn find_mint_freeze_authority_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::FREEZE_AUTHORITY, &mint.to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

fn find_permanent_delegate_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::PERMANENT_DELEGATE, mint.as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

fn find_transfer_hook_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::TRANSFER_HOOK, mint.as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

fn find_verification_config_pda(mint: Pubkey, discriminator: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::VERIFICATION_CONFIG, mint.as_ref(), &[discriminator]],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

async fn send_tx(
    banks_client: &BanksClient,
    ixs: Vec<Instruction>,
    payer: &Pubkey,
    signers: Vec<&Keypair>,
) -> Result<(), BanksClientError> {
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let message = solana_sdk::message::v0::Message::try_compile(payer, &ixs, &[], recent_blockhash)
        .expect("compile V0 message");
    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(message),
        &signers,
    )
    .expect("sign V0 transaction");
    banks_client.process_transaction(tx).await
}

fn assert_ok(result: Result<(), BanksClientError>) {
    if let Err(e) = result {
        panic!(
            "Expected transaction to succeed, but it failed with: {:?}",
            e
        );
    }
}

fn assert_custom_error(result: Result<(), BanksClientError>, expected: u32) {
    match result {
        Err(BanksClientError::TransactionError(TransactionError::InstructionError(
            _,
            InstructionError::Custom(actual),
        ))) => assert_eq!(actual, expected, "wrong custom error code"),
        Err(e) => panic!("Expected Custom({}), but got: {:?}", expected, e),
        Ok(_) => panic!("Expected Custom({}), but transaction succeeded", expected),
    }
}

async fn advance_slot(context: &mut ProgramTestContext) {
    let slot = context.banks_client.get_root_slot().await.unwrap();
    context.warp_to_slot(slot + 1).unwrap();
}

async fn get_token_balance(banks_client: &mut BanksClient, token_account: Pubkey) -> u64 {
    let account = banks_client
        .get_account(token_account)
        .await
        .unwrap()
        .unwrap();
    StateWithExtensionsOwned::<TokenAccount>::unpack(account.data)
        .unwrap()
        .base
        .amount
}

async fn initialize_mint(
    mint: &Keypair,
    context: &mut ProgramTestContext,
    mint_authority_pda: Pubkey,
    freeze_authority_pda: Pubkey,
) {
    let payer_pubkey = context.payer.pubkey();
    let ix = InitializeMintBuilder::new()
        .mint(mint.pubkey())
        .payer(payer_pubkey)
        .authority(mint_authority_pda)
        .initialize_mint_args(InitializeMintArgs {
            ix_mint: MintArgs {
                decimals: 6,
                mint_authority: payer_pubkey,
                freeze_authority: freeze_authority_pda,
            },
            ix_metadata_pointer: None,
            ix_metadata: None,
            ix_scaled_ui_amount: None,
            ix_default_account_state: None,
        })
        .instruction();
    let payer = context.payer.insecure_clone();
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, mint],
        recent_blockhash,
    );
    assert_ok(context.banks_client.process_transaction(tx).await);
}

async fn initialize_verification_config(
    mint: &Keypair,
    context: &mut ProgramTestContext,
    mint_authority_pda: Pubkey,
    args: InitializeVerificationConfigArgs,
) {
    let transfer_hook_program_id = Pubkey::from(security_token_transfer_hook::id());
    let (verification_config_pda, _) =
        find_verification_config_pda(mint.pubkey(), args.instruction_discriminator);
    let account_metas_pda =
        get_extra_account_metas_address(&mint.pubkey(), &transfer_hook_program_id);
    let (transfer_hook_pda, _) = find_transfer_hook_pda(&mint.pubkey());

    let payer = context.payer.insecure_clone();
    let ix = InitializeVerificationConfigBuilder::new()
        .mint(mint.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(payer.pubkey())
        .mint_account(mint.pubkey())
        .payer(payer.pubkey())
        .config_account(verification_config_pda)
        .initialize_verification_config_args(args)
        .account_metas_pda(Some(account_metas_pda))
        .transfer_hook_pda(Some(transfer_hook_pda))
        .transfer_hook_program(Some(transfer_hook_program_id))
        .instruction();

    assert_ok(
        send_tx(
            &context.banks_client,
            vec![ix],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
    );
}

async fn create_spl_account(
    context: &mut ProgramTestContext,
    mint: &Keypair,
    owner: &Keypair,
) -> Pubkey {
    let account = spl_associated_token_account::get_associated_token_address_with_program_id(
        &owner.pubkey(),
        &mint.pubkey(),
        &TOKEN_22_PROGRAM_ID,
    );
    let ix = spl_associated_token_account::instruction::create_associated_token_account_idempotent(
        &context.payer.pubkey(),
        &owner.pubkey(),
        &mint.pubkey(),
        &TOKEN_22_PROGRAM_ID,
    );
    let payer = context.payer.insecure_clone();
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    assert_ok(context.banks_client.process_transaction(tx).await);
    account
}

async fn mint_tokens(
    mint: &Keypair,
    context: &mut ProgramTestContext,
    mint_authority_pda: Pubkey,
    destination: Pubkey,
    amount: u64,
) {
    let (mint_vc_pda, _) = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR);

    initialize_verification_config(
        mint,
        context,
        mint_authority_pda,
        InitializeVerificationConfigArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            cpi_mode: false,
            programs: vec![VerificationProgramConfig {
                program_id: DUMMY_VERIFICATION_PROGRAM_ID,
                extra_accounts: vec![],
            }],
        },
    )
    .await;

    let mint_ix = MintBuilder::new()
        .mint(mint.pubkey())
        .verification_config(mint_vc_pda)
        .mint_account(mint.pubkey())
        .mint_authority(mint_authority_pda)
        .destination(destination)
        .amount(amount)
        .add_remaining_account(AccountMeta::new_readonly(
            DUMMY_VERIFICATION_PROGRAM_ID,
            false,
        ))
        .instruction();

    let dummy_ix = Instruction {
        program_id: DUMMY_VERIFICATION_PROGRAM_ID,
        accounts: mint_ix.accounts[3..7].to_vec(),
        data: mint_ix.data.clone(),
    };

    let payer = context.payer.insecure_clone();
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[dummy_ix, mint_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    assert_ok(context.banks_client.process_transaction(tx).await);
}

fn activate_halt_ix(
    authority: &Pubkey,
    mint: &Pubkey,
    pda: &Pubkey,
    mint_authority_pda: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: SPLIT_GUARD_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*pda, false),
            AccountMeta::new_readonly(*mint_authority_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: vec![ACTIVATE_HALT_DISCRIMINATOR],
    }
}

fn deactivate_halt_ix(
    authority: &Pubkey,
    mint: &Pubkey,
    pda: &Pubkey,
    destination: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: SPLIT_GUARD_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*pda, false),
            AccountMeta::new(*destination, false),
        ],
        data: vec![DEACTIVATE_HALT_DISCRIMINATOR],
    }
}

/// Verification instruction preceding security token Transfer in the same transaction.
///
/// Exact verifier account layout:
///   0. from_token_account
///   1. mint
///   2. to_token_account
///   3. permanent_delegate_authority
///   4. split_guard_pda
fn split_guard_verify_ix(
    permanent_delegate: &Pubkey,
    mint: &Pubkey,
    from: &Pubkey,
    to: &Pubkey,
    split_guard_pda: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![TRANSFER_DISCRIMINATOR];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: SPLIT_GUARD_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(*from, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*to, false),
            AccountMeta::new_readonly(*permanent_delegate, false),
            AccountMeta::new_readonly(*split_guard_pda, false),
        ],
        data,
    }
}

struct Ctx {
    context: ProgramTestContext,
    mint: Keypair,
    mint_authority_pda: Pubkey,
    permanent_delegate_pda: Pubkey,
    transfer_vc_pda: Pubkey,
    source_account: Pubkey,
    destination_account: Pubkey,
    split_guard_pda: Pubkey,
    transfer_hook_program_id: Pubkey,
    amount: u64,
}

async fn setup() -> Ctx {
    let transfer_hook_program_id = Pubkey::from(security_token_transfer_hook::id());

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.add_program(
        "security_token_transfer_hook",
        transfer_hook_program_id,
        None,
    );
    pt.add_program("split_guard", SPLIT_GUARD_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    pt.add_program(
        "dummy_verification_program",
        DUMMY_VERIFICATION_PROGRAM_ID,
        processor!(dummy_verification_processor),
    );

    let mint = Keypair::new();
    let source_owner = Keypair::new();
    let destination_owner = Keypair::new();

    let mut context = pt.start_with_context().await;

    let (mint_authority_pda, _) = find_mint_authority_pda(&mint.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint.pubkey());
    let (permanent_delegate_pda, _) = find_permanent_delegate_pda(&mint.pubkey());
    let (transfer_vc_pda, _) = find_verification_config_pda(mint.pubkey(), TRANSFER_DISCRIMINATOR);
    let (split_guard_pda, _) = find_split_guard_pda(&mint.pubkey());

    initialize_mint(
        &mint,
        &mut context,
        mint_authority_pda,
        freeze_authority_pda,
    )
    .await;

    // Register split_guard as the transfer verification program (introspection mode)
    initialize_verification_config(
        &mint,
        &mut context,
        mint_authority_pda,
        InitializeVerificationConfigArgs {
            instruction_discriminator: TRANSFER_DISCRIMINATOR,
            cpi_mode: false,
            programs: vec![VerificationProgramConfig {
                program_id: SPLIT_GUARD_PROGRAM_ID,
                extra_accounts: vec![VerificationAccountMeta {
                    discriminator: 0,
                    address_config: split_guard_pda.to_bytes(),
                    is_signer: false,
                    is_writable: false,
                }],
            }],
        },
    )
    .await;

    let source_account = create_spl_account(&mut context, &mint, &source_owner).await;
    let destination_account = create_spl_account(&mut context, &mint, &destination_owner).await;

    let amount = 100_000u64;
    mint_tokens(
        &mint,
        &mut context,
        mint_authority_pda,
        source_account,
        amount * 2,
    )
    .await;

    Ctx {
        context,
        mint,
        mint_authority_pda,
        permanent_delegate_pda,
        transfer_vc_pda,
        source_account,
        destination_account,
        split_guard_pda,
        transfer_hook_program_id,
        amount,
    }
}

impl Ctx {
    fn verify_ix(&self) -> Instruction {
        split_guard_verify_ix(
            &self.permanent_delegate_pda,
            &self.mint.pubkey(),
            &self.source_account,
            &self.destination_account,
            &self.split_guard_pda,
            self.amount,
        )
    }

    fn transfer_ix(&self) -> Instruction {
        TransferBuilder::new()
            .mint(self.mint.pubkey())
            .verification_config(self.transfer_vc_pda)
            .permanent_delegate_authority(self.permanent_delegate_pda)
            .mint_account(self.mint.pubkey())
            .from_token_account(self.source_account)
            .to_token_account(self.destination_account)
            .transfer_hook_program(self.transfer_hook_program_id)
            .amount(self.amount)
            .add_remaining_account(AccountMeta::new_readonly(SPLIT_GUARD_PROGRAM_ID, false))
            .add_remaining_account(AccountMeta::new_readonly(self.split_guard_pda, false))
            .instruction()
    }
}

/// Full lifecycle: transfer allowed -> halt activated -> transfer blocked ->
/// halt deactivated -> transfer allowed. Verifies token balances at each step.
#[tokio::test]
async fn test_split_guard_blocks_transfers_in_introspection_mode() {
    let mut ctx = setup().await;
    let payer = ctx.context.payer.insecure_clone();

    // Step 1: transfer succeeds when halt is inactive
    assert_ok(
        send_tx(
            &ctx.context.banks_client,
            vec![ctx.verify_ix(), ctx.transfer_ix()],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
    );
    assert_eq!(
        get_token_balance(&mut ctx.context.banks_client, ctx.destination_account).await,
        ctx.amount
    );

    // Step 2: activate halt
    assert_ok(
        send_tx(
            &ctx.context.banks_client,
            vec![activate_halt_ix(
                &payer.pubkey(),
                &ctx.mint.pubkey(),
                &ctx.split_guard_pda,
                &ctx.mint_authority_pda,
            )],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
    );

    // Step 3: transfer fails while halt is active — split_guard returns Custom(0)
    assert_custom_error(
        send_tx(
            &ctx.context.banks_client,
            vec![ctx.verify_ix(), ctx.transfer_ix()],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
        ERR_SPLIT_HALT_ACTIVE,
    );
    // Balance unchanged from step 1
    assert_eq!(
        get_token_balance(&mut ctx.context.banks_client, ctx.destination_account).await,
        ctx.amount
    );

    // Step 4: deactivate halt
    assert_ok(
        send_tx(
            &ctx.context.banks_client,
            vec![deactivate_halt_ix(
                &payer.pubkey(),
                &ctx.mint.pubkey(),
                &ctx.split_guard_pda,
                &payer.pubkey(),
            )],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
    );

    // Step 5: transfer succeeds again — advance slot to avoid tx deduplication cache
    advance_slot(&mut ctx.context).await;
    assert_ok(
        send_tx(
            &ctx.context.banks_client,
            vec![ctx.verify_ix(), ctx.transfer_ix()],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
    );
    assert_eq!(
        get_token_balance(&mut ctx.context.banks_client, ctx.destination_account).await,
        ctx.amount * 2
    );
}

/// Transfer without the preceding split_guard instruction fails:
/// security token program cannot find the verification program in the instructions sysvar.
#[tokio::test]
async fn test_transfer_without_split_guard_ix_fails() {
    let ctx = setup().await;
    let payer = ctx.context.payer.insecure_clone();

    assert_custom_error(
        send_tx(
            &ctx.context.banks_client,
            vec![ctx.transfer_ix()],
            &payer.pubkey(),
            vec![&payer],
        )
        .await,
        SecurityTokenError::VerificationProgramNotFound as u32,
    );
}

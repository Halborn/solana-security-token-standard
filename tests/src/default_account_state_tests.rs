use security_token_client::{
    instructions::{UpdateDefaultAccountStateBuilder, UPDATE_DEFAULT_ACCOUNT_STATE_DISCRIMINATOR},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{InitializeMintArgs, MintArgs, UpdateDefaultAccountStateArgs},
};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use spl_token_2022::extension::default_account_state::DefaultAccountState as DefaultAccountStateExt;
use spl_token_2022::extension::BaseStateWithExtensions;
use spl_token_2022::state::AccountState;

use crate::helpers::{
    add_dummy_verification_program, assert_transaction_success,
    create_dummy_verification_from_instruction, create_spl_account, create_verification_config,
    find_mint_authority_pda, find_mint_freeze_authority_pda, get_mint_state,
    get_token_account_state, initialize_mint, send_tx, DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID,
};

const STATE_INITIALIZED: u8 = AccountState::Initialized as u8;
const STATE_FROZEN: u8 = AccountState::Frozen as u8;

async fn setup() -> (ProgramTestContext, Keypair, Pubkey, Pubkey, Pubkey) {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let context = pt.start_with_context().await;
    let payer = context.payer.pubkey();
    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) = find_mint_authority_pda(&mint_keypair.pubkey(), &payer);
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());
    (
        context,
        mint_keypair,
        mint_authority_pda,
        freeze_authority_pda,
        payer,
    )
}

fn mint_args(
    payer: Pubkey,
    freeze_authority: Pubkey,
    default_state: Option<u8>,
) -> InitializeMintArgs {
    InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: payer,
            freeze_authority,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: default_state,
    }
}

fn make_update_ix(
    mint_pubkey: Pubkey,
    mint_authority_pda: Pubkey,
    freeze_authority_pda: Pubkey,
    payer_pubkey: Pubkey,
    state: u8,
) -> solana_sdk::instruction::Instruction {
    UpdateDefaultAccountStateBuilder::new()
        .mint(mint_pubkey)
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(payer_pubkey)
        .freeze_authority(freeze_authority_pda)
        .mint_account(mint_pubkey)
        .update_default_account_state_args(UpdateDefaultAccountStateArgs { state })
        .instruction()
}

// ─── Initialize tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_initialize_mint_with_default_account_state_frozen() {
    let (mut context, mint_keypair, mint_authority_pda, freeze_authority_pda, payer) =
        setup().await;

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &mint_args(payer, freeze_authority_pda, Some(STATE_FROZEN)),
    )
    .await;

    let mint_state = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    let ext = mint_state
        .get_extension::<DefaultAccountStateExt>()
        .expect("DefaultAccountState extension must exist");
    assert_eq!(
        ext.state, STATE_FROZEN,
        "default account state should be Frozen"
    );

    // Newly created token account should be frozen
    let token_account = create_spl_account(&mut context, &mint_keypair, &Keypair::new()).await;
    let token_state = get_token_account_state(&mut context.banks_client, token_account).await;
    assert_eq!(
        token_state.base.state,
        AccountState::Frozen,
        "new token account should start frozen"
    );
}

#[tokio::test]
async fn test_initialize_mint_without_default_account_state() {
    let (mut context, mint_keypair, mint_authority_pda, freeze_authority_pda, payer) =
        setup().await;

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &mint_args(payer, freeze_authority_pda, None),
    )
    .await;

    let mint_state = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    assert!(
        mint_state
            .get_extension::<DefaultAccountStateExt>()
            .is_err(),
        "DefaultAccountState extension should not exist when not requested"
    );
}

#[tokio::test]
async fn test_update_default_account_state_via_mint_authority() {
    let (mut context, mint_keypair, mint_authority_pda, freeze_authority_pda, payer) =
        setup().await;

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &mint_args(payer, freeze_authority_pda, Some(STATE_FROZEN)),
    )
    .await;

    // Switch Frozen → Initialized via mint authority path
    let result = send_tx(
        &context.banks_client,
        vec![make_update_ix(
            mint_keypair.pubkey(),
            mint_authority_pda,
            freeze_authority_pda,
            payer,
            STATE_INITIALIZED,
        )],
        &payer,
        vec![&context.payer],
    )
    .await;
    assert_transaction_success(result);

    let mint_state = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    let ext = mint_state
        .get_extension::<DefaultAccountStateExt>()
        .expect("DefaultAccountState extension must exist");
    assert_eq!(
        ext.state, STATE_INITIALIZED,
        "default account state should be Initialized after update"
    );
}

#[tokio::test]
async fn test_update_default_account_state_via_verification_programs() {
    let (mut context, mint_keypair, mint_authority_pda, freeze_authority_pda, payer) =
        setup().await;

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &mint_args(payer, freeze_authority_pda, Some(STATE_INITIALIZED)),
    )
    .await;

    let verification_config_pda = create_verification_config(
        &mut context,
        &mint_keypair,
        mint_authority_pda,
        UPDATE_DEFAULT_ACCOUNT_STATE_DISCRIMINATOR,
        vec![DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID],
        None,
    )
    .await;

    // Switch Initialized → Frozen via verification programs path
    let update_ix = UpdateDefaultAccountStateBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(verification_config_pda)
        .instructions_sysvar_or_creator(solana_program::sysvar::instructions::ID)
        .freeze_authority(freeze_authority_pda)
        .mint_account(mint_keypair.pubkey())
        .update_default_account_state_args(UpdateDefaultAccountStateArgs {
            state: STATE_FROZEN,
        })
        .instruction();

    let result = send_tx(
        &context.banks_client,
        vec![
            create_dummy_verification_from_instruction(&update_ix),
            update_ix,
        ],
        &payer,
        vec![&context.payer],
    )
    .await;
    assert_transaction_success(result);

    let mint_state = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    let ext = mint_state
        .get_extension::<DefaultAccountStateExt>()
        .expect("DefaultAccountState extension must exist");
    assert_eq!(
        ext.state, STATE_FROZEN,
        "default account state should be Frozen after update"
    );
}

#[tokio::test]
async fn test_update_default_account_state_invalid_state_rejected() {
    let (mut context, mint_keypair, mint_authority_pda, freeze_authority_pda, payer) =
        setup().await;

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &mint_args(payer, freeze_authority_pda, Some(STATE_FROZEN)),
    )
    .await;

    let result = send_tx(
        &context.banks_client,
        vec![make_update_ix(
            mint_keypair.pubkey(),
            mint_authority_pda,
            freeze_authority_pda,
            payer,
            AccountState::Uninitialized as u8,
        )],
        &payer,
        vec![&context.payer],
    )
    .await;
    assert!(result.is_err(), "invalid state value should be rejected");
}

#[tokio::test]
async fn test_update_default_account_state_without_extension_fails() {
    let (mut context, mint_keypair, mint_authority_pda, freeze_authority_pda, payer) =
        setup().await;

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &mint_args(payer, freeze_authority_pda, None),
    )
    .await;

    let result = send_tx(
        &context.banks_client,
        vec![make_update_ix(
            mint_keypair.pubkey(),
            mint_authority_pda,
            freeze_authority_pda,
            payer,
            STATE_INITIALIZED,
        )],
        &payer,
        vec![&context.payer],
    )
    .await;
    assert!(
        result.is_err(),
        "update on mint without extension should fail"
    );
}

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

use crate::helpers::{
    add_dummy_verification_program, assert_transaction_success,
    create_dummy_verification_from_instruction, create_spl_account, create_verification_config,
    find_mint_authority_pda, find_mint_freeze_authority_pda, get_mint_state,
    get_token_account_state, initialize_mint, send_tx,
};

// 1 = Initialized, 2 = Frozen
const STATE_INITIALIZED: u8 = 1;
const STATE_FROZEN: u8 = 2;

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
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let mut context = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: Some(STATE_FROZEN),
    };

    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

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
        spl_token_2022::state::AccountState::Frozen,
        "new token account should start frozen"
    );
}

#[tokio::test]
async fn test_initialize_mint_without_default_account_state() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let mut context = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: None,
    };

    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    let mint_state = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    let ext = mint_state.get_extension::<DefaultAccountStateExt>();
    assert!(
        ext.is_err(),
        "DefaultAccountState extension should not exist when not requested"
    );
}

#[tokio::test]
async fn test_update_default_account_state_via_mint_authority() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let mut context = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    // Initialize with Frozen default state
    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: Some(STATE_FROZEN),
    };
    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    // Switch Frozen to Initialized via mint authority path
    let update_ix = make_update_ix(
        mint_keypair.pubkey(),
        mint_authority_pda,
        freeze_authority_pda,
        context.payer.pubkey(),
        STATE_INITIALIZED,
    );
    let result = send_tx(
        &context.banks_client,
        vec![update_ix],
        &context.payer.pubkey(),
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
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let mut context = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    // Initialize with Initialized default state
    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: Some(STATE_INITIALIZED),
    };
    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    // Set up verification config for UpdateDefaultAccountState (discriminant 24)
    let verification_config_pda = create_verification_config(
        &mut context,
        &mint_keypair,
        mint_authority_pda,
        UPDATE_DEFAULT_ACCOUNT_STATE_DISCRIMINATOR,
        vec![crate::helpers::DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID],
        None,
    )
    .await;

    // Switch Initialized to Frozen via verification programs path
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

    let dummy_ix = create_dummy_verification_from_instruction(&update_ix);

    let result = send_tx(
        &context.banks_client,
        vec![dummy_ix, update_ix],
        &context.payer.pubkey(),
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
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let mut context = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: Some(STATE_FROZEN),
    };
    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    // state=0 (Uninitialized) is invalid — program should reject it
    let update_ix = make_update_ix(
        mint_keypair.pubkey(),
        mint_authority_pda,
        freeze_authority_pda,
        context.payer.pubkey(),
        0, // invalid
    );
    let result = send_tx(
        &context.banks_client,
        vec![update_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    // ProgramError::InvalidArgument maps to InstructionError::InvalidArgument, not a custom error
    assert!(result.is_err(), "invalid state value should be rejected");
}

#[tokio::test]
async fn test_update_default_account_state_without_extension_fails() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    let mut context = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let (mint_authority_pda, _) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());
    let (freeze_authority_pda, _) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

    // Initialize WITHOUT DefaultAccountState
    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: None,
    };
    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    // UpdateDefaultAccountState on a mint without the extension should fail
    let update_ix = make_update_ix(
        mint_keypair.pubkey(),
        mint_authority_pda,
        freeze_authority_pda,
        context.payer.pubkey(),
        STATE_INITIALIZED,
    );
    let result = send_tx(
        &context.banks_client,
        vec![update_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert!(
        result.is_err(),
        "update on mint without extension should fail"
    );
}

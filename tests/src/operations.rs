use security_token_client::instructions::{
    BurnBuilder, FreezeBuilder, MintBuilder, PauseBuilder, ResumeBuilder, ThawBuilder,
    BURN_DISCRIMINATOR, FREEZE_DISCRIMINATOR, MINT_DISCRIMINATOR, PAUSE_DISCRIMINATOR,
    RESUME_DISCRIMINATOR, THAW_DISCRIMINATOR,
};
use security_token_client::programs::SECURITY_TOKEN_PROGRAM_ID;
use security_token_client::types::{
    InitializeMintArgs, InitializeVerificationConfigArgs, MintArgs,
};

use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::{signature::Keypair, sysvar};
use spl_pod::primitives::PodBool;
use spl_token_2022::extension::pausable::PausableConfig;
use spl_token_2022::extension::BaseStateWithExtensions;
use spl_token_2022::extension::StateWithExtensionsOwned;
use spl_token_2022::state::{AccountState, Mint as TokenMint};

use crate::helpers::{
    assert_transaction_success, get_mint_state, get_token_account_state, initialize_mint,
    initialize_verification_config,
};
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;

#[tokio::test]
async fn test_basic_t22_operations() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);

    let mint_keypair = Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let destination_account =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            &context.payer.pubkey(),
            &mint_keypair.pubkey(),
            &TOKEN_22_PROGRAM_ID,
        );

    let initialize_mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
    };

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &initialize_mint_args,
    )
    .await;

    // Prepare all verification configs
    let instructions = vec![
        MINT_DISCRIMINATOR,
        BURN_DISCRIMINATOR,
        FREEZE_DISCRIMINATOR,
        THAW_DISCRIMINATOR,
    ];

    let mut verification_configs = vec![];
    // NOTE: Move to fixture?
    for discriminator in instructions {
        let (verification_config_pda, _bump) = Pubkey::find_program_address(
            &[
                b"verification_config",
                mint_keypair.pubkey().as_ref(),
                &[discriminator],
            ],
            &SECURITY_TOKEN_PROGRAM_ID,
        );

        let initialize_verification_config_args = InitializeVerificationConfigArgs {
            instruction_discriminator: discriminator,
            cpi_mode: false,
            program_addresses: vec![],
        };

        initialize_verification_config(
            &mint_keypair,
            &mut context,
            mint_authority_pda,
            verification_config_pda,
            &initialize_verification_config_args,
        )
        .await;
        verification_configs.push(verification_config_pda);
    }

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let create_destination_account_ix =
        spl_associated_token_account::instruction::create_associated_token_account_idempotent(
            &context.payer.pubkey(),
            &context.payer.pubkey(),
            &mint_keypair.pubkey(),
            &TOKEN_22_PROGRAM_ID,
        );

    let create_destination_account_tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[create_destination_account_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(create_destination_account_tx)
        .await;

    assert_transaction_success(result);

    let mint_state_before = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    assert_eq!(mint_state_before.base.supply, 0);

    let mint_ix = MintBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config(verification_configs[0])
        .instructions_sysvar(sysvar::instructions::ID)
        .mint_account(mint_keypair.pubkey())
        .mint_authority(mint_authority_pda)
        .destination(destination_account)
        .amount(1_000_000)
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let mint_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[mint_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(mint_transaction)
        .await;
    assert_transaction_success(result);

    let mint_state_after = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    assert_eq!(mint_state_after.base.supply, 1_000_000);

    let token_account_after =
        get_token_account_state(&mut context.banks_client, destination_account).await;
    assert_eq!(token_account_after.base.amount, 1_000_000);

    let (permanent_delegate_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.permanent_delegate", mint_keypair.pubkey().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let burn_ix = BurnBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config(verification_configs[1])
        .instructions_sysvar(sysvar::instructions::ID)
        .permanent_delegate(permanent_delegate_pda)
        .mint_account(mint_keypair.pubkey())
        .token_account(destination_account)
        .amount(500_000)
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let burn_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[burn_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );
    let result = context
        .banks_client
        .process_transaction(burn_transaction)
        .await;
    assert_transaction_success(result);

    let mint_state_after_burn =
        get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    assert_eq!(mint_state_after_burn.base.supply, 500_000);

    let token_account_after_burn =
        get_token_account_state(&mut context.banks_client, destination_account).await;
    assert_eq!(token_account_after_burn.base.amount, 500_000);

    let freeze_ix = FreezeBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config(verification_configs[2])
        .mint_account(mint_keypair.pubkey())
        .freeze_authority(freeze_authority_pda)
        .token_account(destination_account)
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let freeze_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[freeze_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );
    let result = context
        .banks_client
        .process_transaction(freeze_transaction)
        .await;
    assert_transaction_success(result);

    let frozen_account =
        get_token_account_state(&mut context.banks_client, destination_account).await;
    assert_eq!(frozen_account.base.state, AccountState::Frozen);

    let thaw_ix = ThawBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config(verification_configs[3])
        .mint_account(mint_keypair.pubkey())
        .freeze_authority(freeze_authority_pda)
        .token_account(destination_account)
        .instruction();

    let thaw_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[thaw_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );
    let result = context
        .banks_client
        .process_transaction(thaw_transaction)
        .await;
    assert_transaction_success(result);
    let thawed_account =
        get_token_account_state(&mut context.banks_client, destination_account).await;
    assert_eq!(thawed_account.base.state, AccountState::Initialized);
}

#[tokio::test]
async fn test_t22_extension_operations() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);

    let mint_keypair = Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let initialize_mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
    };

    initialize_mint(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        &initialize_mint_args,
    )
    .await;

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let (pause_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.pause_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[PAUSE_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let pause_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: PAUSE_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: vec![],
    };
    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &pause_verification_config_args,
    )
    .await;

    let pause_ix = PauseBuilder::new()
        .mint(mint_keypair.pubkey())
        .mint_account(mint_keypair.pubkey())
        .verification_config(verification_config_pda)
        .pause_authority(pause_authority_pda)
        .instruction();

    let pause_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[pause_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(pause_transaction)
        .await;
    assert_transaction_success(result);

    let mint_state: StateWithExtensionsOwned<TokenMint> =
        get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    let pausable = mint_state
        .get_extension::<PausableConfig>()
        .expect("Pausable extension should exist");
    assert_eq!(pausable.paused, PodBool(1));

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[RESUME_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let resume_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: RESUME_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: vec![],
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &resume_verification_config_args,
    )
    .await;

    let resume_ix = ResumeBuilder::new()
        .mint(mint_keypair.pubkey())
        .mint_account(mint_keypair.pubkey())
        .verification_config(verification_config_pda)
        .pause_authority(pause_authority_pda)
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let resume_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[resume_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(resume_transaction)
        .await;
    assert_transaction_success(result);

    let mint_state: StateWithExtensionsOwned<TokenMint> =
        get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    let pausable = mint_state
        .get_extension::<PausableConfig>()
        .expect("Pausable extension should exist");
    assert_eq!(pausable.paused, PodBool(0));
}

use security_token_client::{
    InitializeVerificationConfig, InitializeVerificationConfigArgs,
    InitializeVerificationConfigInstructionArgs, BURN_DISCRIMINATOR, FREEZE_DISCRIMINATOR,
    MINT_DISCRIMINATOR, PAUSE_DISCRIMINATOR, RESUME_DISCRIMINATOR, SECURITY_TOKEN_ID,
    THAW_DISCRIMINATOR,
};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::{signature::Keypair, sysvar};
use spl_pod::primitives::PodBool;
use spl_token_2022::extension::pausable::PausableConfig;
use spl_token_2022::extension::BaseStateWithExtensions;
use spl_token_2022::extension::StateWithExtensionsOwned;
use spl_token_2022::state::{Account as TokenAccount, AccountState, Mint as TokenMint};

use crate::helpers::assert_transaction_success;

async fn get_mint_state(
    banks_client: &mut solana_program_test::BanksClient,
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

async fn get_token_account_state(
    banks_client: &mut solana_program_test::BanksClient,
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

//TODO: Don't forget about fixtures initialization mint at least
#[tokio::test]
async fn test_basic_t22_operations() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    let mint_keypair = Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_ID,
    );

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    let destination_account =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            &context.payer.pubkey(),
            &mint_keypair.pubkey(),
            &spl_token_2022_program,
        );

    let initialize_mint_ix = security_token_client::InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        mint_authority_account: mint_authority_pda,
        token_program: spl_token_2022_program,
        system_program: solana_system_interface::program::ID,
        rent: sysvar::rent::ID,
    }
    .instruction(security_token_client::InitializeMintInstructionArgs {
        args: security_token_client::InitializeArgs {
            ix_mint: security_token_client::InitializeMintArgs {
                decimals: 6,
                mint_authority: context.payer.pubkey(),
                freeze_authority: freeze_authority_pda,
            },
            ix_metadata_pointer: None,
            ix_metadata: None,
            ix_scaled_ui_amount: None,
        },
    });

    let initialize_mint_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[initialize_mint_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(initialize_mint_transaction)
        .await;
    assert_transaction_success(result);

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let create_destination_account_ix =
        spl_associated_token_account::instruction::create_associated_token_account_idempotent(
            &context.payer.pubkey(),
            &context.payer.pubkey(),
            &mint_keypair.pubkey(),
            &spl_token_2022_program,
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

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[MINT_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let mint_state_before = get_mint_state(&mut context.banks_client, mint_keypair.pubkey()).await;
    assert_eq!(mint_state_before.base.supply, 0);

    let mint_ix = security_token_client::Mint {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
        creator: context.payer.pubkey(),
        mint_info: mint_keypair.pubkey(),
        mint_authority: mint_authority_pda,
        destination_account,
        token_program: spl_token_2022_program,
    }
    .instruction(security_token_client::MintInstructionArgs { amount: 1_000_000 });

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

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[BURN_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let (permanent_delegate_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.permanent_delegate", mint_keypair.pubkey().as_ref()],
        &SECURITY_TOKEN_ID,
    );

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: BURN_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let burn_ix = security_token_client::Burn {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
        permanent_delegate: permanent_delegate_pda,
        mint_info: mint_keypair.pubkey(),
        token_account: destination_account,
        token_program: spl_token_2022_program,
    }
    .instruction(security_token_client::BurnInstructionArgs { amount: 500_000 });

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

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[FREEZE_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: FREEZE_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let freeze_ix = security_token_client::Freeze {
        mint: mint_keypair.pubkey(),
        mint_info: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        freeze_authority: freeze_authority_pda,
        token_account: destination_account,
        token_program: spl_token_2022_program,
        instructions_sysvar: sysvar::instructions::ID,
    }
    .instruction();

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

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[THAW_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: THAW_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let thaw_ix = security_token_client::Thaw {
        mint: mint_keypair.pubkey(),
        mint_info: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        freeze_authority: freeze_authority_pda,
        token_account: destination_account,
        token_program: spl_token_2022_program,
        instructions_sysvar: sysvar::instructions::ID,
    }
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
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    let mint_keypair = Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_ID,
    );

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();
    let initialize_mint_ix = security_token_client::InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        mint_authority_account: mint_authority_pda,
        token_program: spl_token_2022_program,
        system_program: solana_system_interface::program::ID,
        rent: sysvar::rent::ID,
    }
    .instruction(security_token_client::InitializeMintInstructionArgs {
        args: security_token_client::InitializeArgs {
            ix_mint: security_token_client::InitializeMintArgs {
                decimals: 6,
                mint_authority: context.payer.pubkey(),
                freeze_authority: freeze_authority_pda,
            },
            ix_metadata_pointer: None,
            ix_metadata: None,
            ix_scaled_ui_amount: None,
        },
    });

    let initialize_mint_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[initialize_mint_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(initialize_mint_transaction)
        .await;
    assert_transaction_success(result);

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let (pause_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.pause_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_ID,
    );

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[PAUSE_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: PAUSE_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: PAUSE_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let pause_ix = security_token_client::Pause {
        mint: mint_keypair.pubkey(),
        mint_info: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        pause_authority: pause_authority_pda,
        token_program: spl_token_2022_program,
        instructions_sysvar: sysvar::instructions::ID,
    }
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
        &SECURITY_TOKEN_ID,
    );

    let init_config_instruction = InitializeVerificationConfig {
        mint: mint_keypair.pubkey(),
        verification_config_or_mint_authority: mint_authority_pda,
        sysvar_or_creator: (context.payer.pubkey(), true),
        config_account: verification_config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator: RESUME_DISCRIMINATOR,
            program_addresses: vec![],
        },
    });

    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_config_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;

    assert_transaction_success(result);

    let resume_ix = security_token_client::Resume {
        mint: mint_keypair.pubkey(),
        mint_info: mint_keypair.pubkey(),
        pause_authority: pause_authority_pda,
        token_program: spl_token_2022_program,
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
    }
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

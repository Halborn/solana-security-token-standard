use security_token_client::instructions::{
    BurnBuilder, FreezeBuilder, MintBuilder, PauseBuilder, ResumeBuilder, ThawBuilder,
    TransferBuilder, BURN_DISCRIMINATOR, FREEZE_DISCRIMINATOR, MINT_DISCRIMINATOR,
    PAUSE_DISCRIMINATOR, RESUME_DISCRIMINATOR, THAW_DISCRIMINATOR, TRANSFER_DISCRIMINATOR,
};
use security_token_client::programs::SECURITY_TOKEN_PROGRAM_ID;
use security_token_client::types::{
    InitializeMintArgs, InitializeVerificationConfigArgs, MintArgs,
};
use solana_program::entrypoint::ProgramResult;
use solana_sdk::account_info::AccountInfo;
use solana_sdk::system_program;
use spl_tlv_account_resolution::account::ExtraAccountMeta;
use spl_tlv_account_resolution::state::ExtraAccountMetaList;
use spl_transfer_hook_interface::instruction::{
    initialize_extra_account_meta_list, ExecuteInstruction,
};
use spl_transfer_hook_interface::offchain::add_extra_account_metas_for_execute;
use spl_type_length_value::state::TlvStateBorrowed;

use crate::helpers::{
    assert_transaction_success, create_spl_account, find_mint_authority_pda,
    find_mint_freeze_authority_pda, find_verification_config_pda, get_mint_state,
    get_token_account_state, initialize_mint, initialize_mint_verification_and_mint_to_account,
    initialize_program, initialize_verification_config, send_tx,
};
use security_token_transfer_hook;
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::{signature::Keypair, sysvar};
use spl_discriminator::SplDiscriminate;
use spl_pod::primitives::PodBool;
use spl_token_2022::extension::pausable::PausableConfig;
use spl_token_2022::extension::BaseStateWithExtensions;
use spl_token_2022::extension::StateWithExtensionsOwned;
use spl_token_2022::state::{AccountState, Mint as TokenMint};
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;
use spl_transfer_hook_interface::get_extra_account_metas_address;

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

#[tokio::test]
async fn test_t22_transfer_operations() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);
    pt.add_program(
        "security_token_transfer_hook",
        Pubkey::from(security_token_transfer_hook::id()),
        None,
    );

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let source_keypair = Keypair::new();
    let destination_keypair = Keypair::new();

    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (permanent_delegate_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.permanent_delegate", mint_keypair.pubkey().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (freeze_authority_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.freeze_authority", &mint_keypair.pubkey().to_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[TRANSFER_DISCRIMINATOR],
        ],
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

    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: TRANSFER_DISCRIMINATOR,
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

    let source_account = create_spl_account(&mut context, &mint_keypair, &source_keypair).await;
    let destination_account =
        create_spl_account(&mut context, &mint_keypair, &destination_keypair).await;

    initialize_mint_verification_and_mint_to_account(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        source_account,
        200_000,
    )
    .await;

    let transfer_ix = TransferBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config(verification_config_pda)
        .permanent_delegate_authority(permanent_delegate_pda)
        .mint_account(mint_keypair.pubkey())
        .from_token_account(source_account)
        .to_token_account(destination_account)
        .transfer_hook_program(Pubkey::from(security_token_transfer_hook::id()))
        .amount(100_000)
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let transfer_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );
    let result = context
        .banks_client
        .process_transaction(transfer_transaction)
        .await;
    assert_transaction_success(result);
    let destination_account_state =
        get_token_account_state(&mut context.banks_client, destination_account).await;
    assert_eq!(destination_account_state.base.amount, 100_000);
}

fn dummy_program_1_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Example of transfer verification program
    // (1 byte discriminator + 8 bytes amount)
    if instruction_data.len() != 9 {
        return Err(solana_program::program_error::ProgramError::InvalidInstructionData);
    }

    let instruction_byte = instruction_data[0];
    let amount_bytes: [u8; 8] = instruction_data[1..9]
        .try_into()
        .map_err(|_| solana_program::program_error::ProgramError::InvalidInstructionData)?;
    let amount = u64::from_le_bytes(amount_bytes);

    assert_eq!(instruction_byte, TRANSFER_DISCRIMINATOR);
    assert_eq!(amount, 125_000);
    Ok(())
}

#[tokio::test]
async fn test_p2p_transfer_direct_spl() {
    let dummy_program_1_id = Pubkey::new_unique();
    let dummy_program_2_id = Pubkey::new_unique();
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);

    pt.add_program(
        "security_token_transfer_hook",
        Pubkey::from(security_token_transfer_hook::id()),
        None,
    );
    pt.prefer_bpf(false);
    pt.add_program(
        "dummy_program_1",
        dummy_program_1_id,
        processor!(dummy_program_1_processor),
    );
    pt.add_program(
        "dummy_program_2",
        dummy_program_2_id,
        processor!(dummy_program_1_processor),
    );

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let mint_keypair = Keypair::new();
    let source_owner = Keypair::new();
    let destination_owner = Keypair::new();

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

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[TRANSFER_DISCRIMINATOR],
        ],
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

    let initialize_verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: TRANSFER_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: vec![dummy_program_1_id, dummy_program_2_id],
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &initialize_verification_config_args,
    )
    .await;

    let account_metas_pda = get_extra_account_metas_address(
        &mint_keypair.pubkey(),
        &Pubkey::from(security_token_transfer_hook::id()),
    );

    let extra_account_metas = [
        ExtraAccountMeta {
            discriminator: 0,
            is_writable: PodBool(0),
            is_signer: PodBool(0),
            address_config: verification_config_pda.to_bytes(),
        },
        ExtraAccountMeta {
            discriminator: 0,
            is_writable: PodBool(0),
            is_signer: PodBool(0),
            address_config: dummy_program_1_id.to_bytes(),
        },
        ExtraAccountMeta {
            discriminator: 0,
            is_writable: PodBool(0),
            is_signer: PodBool(0),
            address_config: dummy_program_2_id.to_bytes(),
        },
    ];
    let source_account = create_spl_account(&mut context, &mint_keypair, &source_owner).await;
    let destination_account =
        create_spl_account(&mut context, &mint_keypair, &destination_owner).await;

    initialize_mint_verification_and_mint_to_account(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        source_account,
        250_000,
    )
    .await;

    let init_extra_metas_ix = initialize_extra_account_meta_list(
        &Pubkey::from(security_token_transfer_hook::id()),
        &account_metas_pda,
        &mint_keypair.pubkey(),
        &context.payer.pubkey(),
        &extra_account_metas,
    );

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let init_tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[init_extra_metas_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );
    let result = context.banks_client.process_transaction(init_tx).await;
    assert_transaction_success(result);

    let account_metas_account = context
        .banks_client
        .get_account(account_metas_pda)
        .await
        .expect("extra meta account fetch")
        .expect("extra meta account must exist");

    let account_meta_data = account_metas_account.data;
    assert_eq!(
        &account_meta_data[..ExecuteInstruction::SPL_DISCRIMINATOR_SLICE.len()],
        ExecuteInstruction::SPL_DISCRIMINATOR_SLICE,
        "execute discriminator must be stored",
    );
    let tlv_state =
        TlvStateBorrowed::unpack(&account_meta_data).expect("tlv header should deserialize");
    let mut expected_tlv =
        vec![0u8; ExtraAccountMetaList::size_of(extra_account_metas.len()).unwrap()];
    ExtraAccountMetaList::init::<ExecuteInstruction>(&mut expected_tlv, &extra_account_metas)
        .expect("expected tlv init");
    let meta_list = ExtraAccountMetaList::unpack_with_tlv_state::<ExecuteInstruction>(&tlv_state)
        .expect("extra meta list should deserialize");
    let meta_slice = meta_list.data();
    let stored_meta = meta_slice
        .get(0)
        .expect("meta list should contain the verification config entry");
    assert_eq!(
        stored_meta.discriminator, 0,
        "stored meta should be a raw pubkey"
    );
    assert_eq!(
        stored_meta.address_config,
        verification_config_pda.to_bytes()
    );

    let transfer_hook_program_id = Pubkey::from(security_token_transfer_hook::id());

    let mut spl_transfer_ix = spl_token_2022::instruction::transfer_checked(
        &TOKEN_22_PROGRAM_ID,
        &source_account,
        &mint_keypair.pubkey(),
        &destination_account,
        &source_owner.pubkey(),
        &[],
        125_000,
        6,
    )
    .expect("SPL transfer ix");

    let banks_client = context.banks_client.clone();

    add_extra_account_metas_for_execute(
        &mut spl_transfer_ix,
        &transfer_hook_program_id,
        &source_account,
        &mint_keypair.pubkey(),
        &destination_account,
        &source_owner.pubkey(),
        125_000,
        |address| {
            let banks_client = banks_client.clone();
            async move {
                banks_client
                    .get_account(address)
                    .await
                    .map(|opt| {
                        if let Some(acc) = opt {
                            Some(acc.data)
                        } else {
                            Some(vec![])
                        }
                    })
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
        },
    )
    .await
    .expect("add extra metas");

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[spl_transfer_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &source_owner],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;
    assert_transaction_success(result);

    let source_state = get_token_account_state(&mut context.banks_client, source_account).await;
    assert_eq!(source_state.base.amount, 125_000);

    let destination_state =
        get_token_account_state(&mut context.banks_client, destination_account).await;
    assert_eq!(destination_state.base.amount, 125_000);
}

#[tokio::test]
async fn test_transfer_hook_extra_account_metas_init_and_update() {
    let transfer_hook_program_id = Pubkey::from(security_token_transfer_hook::id());

    let mut pt = initialize_program();

    pt.add_program(
        "security_token_transfer_hook",
        transfer_hook_program_id,
        None,
    );

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let mint_keypair = Keypair::new();

    let (mint_authority_pda, _bump) =
        find_mint_authority_pda(&mint_keypair.pubkey(), &context.payer.pubkey());

    let (freeze_authority_pda, _bump) = find_mint_freeze_authority_pda(&mint_keypair.pubkey());

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

    // Get extra account metas PDA
    let extra_account_metas_pda =
        get_extra_account_metas_address(&mint_keypair.pubkey(), &transfer_hook_program_id);

    // Initialize with one extra account meta
    let (verification_config_pda, _bump) =
        find_verification_config_pda(mint_keypair.pubkey(), TRANSFER_DISCRIMINATOR);

    let initial_metas =
        vec![ExtraAccountMeta::new_with_pubkey(&verification_config_pda, false, false).unwrap()];

    let mut init_buffer = vec![0u8; ExtraAccountMetaList::size_of(initial_metas.len()).unwrap()];
    ExtraAccountMetaList::init::<ExecuteInstruction>(&mut init_buffer, &initial_metas).unwrap();

    let init_ix = initialize_extra_account_meta_list(
        &transfer_hook_program_id,
        &extra_account_metas_pda,
        &mint_keypair.pubkey(),
        &context.payer.pubkey(),
        &initial_metas,
    );

    let result = send_tx(
        &context.banks_client,
        vec![init_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    assert_transaction_success(result);

    // Verify initialization
    let extra_account_metas_account = context
        .banks_client
        .get_account(extra_account_metas_pda)
        .await
        .unwrap()
        .expect("extra account metas account should exist");

    let tlv_state = TlvStateBorrowed::unpack(&extra_account_metas_account.data)
        .expect("tlv header should deserialize");
    let extra_metas_data =
        ExtraAccountMetaList::unpack_with_tlv_state::<ExecuteInstruction>(&tlv_state)
            .expect("extra meta list should deserialize");
    assert_eq!(extra_metas_data.data().len(), 1);

    // Update with two extra account metas
    let dummy_account = Pubkey::new_unique();
    let updated_metas = vec![
        ExtraAccountMeta::new_with_pubkey(&verification_config_pda, false, false).unwrap(),
        ExtraAccountMeta::new_with_pubkey(&dummy_account, false, false).unwrap(),
    ];

    let mut update_ix = spl_transfer_hook_interface::instruction::update_extra_account_meta_list(
        &transfer_hook_program_id,
        &extra_account_metas_pda,
        &mint_keypair.pubkey(),
        &context.payer.pubkey(),
        &updated_metas,
    );

    // Add System Program as additional account for realloc
    update_ix
        .accounts
        .push(solana_sdk::instruction::AccountMeta::new_readonly(
            solana_sdk::system_program::ID,
            false,
        ));

    let result = send_tx(
        &context.banks_client,
        vec![update_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    assert_transaction_success(result);

    // Verify update
    let extra_account_metas_account = context
        .banks_client
        .get_account(extra_account_metas_pda)
        .await
        .unwrap()
        .expect("extra account metas account should exist");

    let tlv_state = TlvStateBorrowed::unpack(&extra_account_metas_account.data)
        .expect("tlv header should deserialize");
    let extra_metas_data =
        ExtraAccountMetaList::unpack_with_tlv_state::<ExecuteInstruction>(&tlv_state)
            .expect("extra meta list should deserialize");
    assert_eq!(extra_metas_data.data().len(), 2);

    // Verify the metas are correct
    let metas = extra_metas_data
        .data()
        .into_iter()
        .map(|meta| meta.clone())
        .collect::<Vec<_>>();
    assert_eq!(Pubkey::from(metas[0].address_config), verification_config_pda);
    assert_eq!(Pubkey::from(metas[1].address_config), dummy_account);
}

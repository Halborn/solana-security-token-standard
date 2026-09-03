use crate::helpers::{
    assert_transaction_failure, assert_transaction_success, create_minimal_security_token_mint,
    create_spl_account, find_mint_authority_pda, find_verification_config_pda,
    send_v0_tx as send_tx,
};
use crate::verification_tests::verification_helpers::{
    dynamic_initialize_config_instruction_with_mode, dynamic_update_config_instruction,
};
use security_token_client::{
    instructions::{
        InitializeVerificationConfigBuilder, MintBuilder, TrimVerificationConfigBuilder,
        UpdateVerificationConfigBuilder, MINT_DISCRIMINATOR, TRANSFER_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{
        InitializeVerificationConfigArgs as ClientInitializeArgs, TrimVerificationConfigArgs,
        UpdateVerificationConfigArgs as ClientUpdateArgs,
        VerificationAccountMeta as ClientVerificationAccountMeta,
        VerificationProgramConfig as ClientVerificationProgramConfig,
    },
};

use security_token_program::constants::{
    MAX_TOTAL_VERIFICATION_EXTRAS, MAX_VERIFICATION_EXTRAS_PER_PROGRAM, MAX_VERIFICATION_PROGRAMS,
};
use security_token_program::instructions::{VerificationAccountMeta, VerificationProgramConfig};
use security_token_program::state::{AccountDeserialize, VerificationConfig};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction, sysvar,
};

fn cpi_verifier(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 5);
    assert_eq!(instruction_data[0], MINT_DISCRIMINATOR);
    assert!(!accounts[4].is_signer);
    assert!(!accounts[4].is_writable);
    Ok(())
}

fn introspection_verifier(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 5);
    assert_eq!(instruction_data[0], MINT_DISCRIMINATOR);
    Ok(())
}

fn nested_initialize_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    verifier: Pubkey,
    cpi_mode: bool,
) -> Instruction {
    nested_initialize_instruction_with_extra(
        payer,
        mint,
        mint_authority,
        config,
        verifier,
        cpi_mode,
        VerificationAccountMeta {
            discriminator: 0,
            address_config: payer.to_bytes(),
            is_signer: false,
            is_writable: false,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn nested_initialize_instruction_with_extra(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    verifier: Pubkey,
    cpi_mode: bool,
    extra: VerificationAccountMeta,
) -> Instruction {
    dynamic_initialize_config_instruction_with_mode(
        payer,
        mint,
        mint_authority,
        config,
        MINT_DISCRIMINATOR,
        cpi_mode,
        vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts: vec![extra],
        }],
    )
}

fn nested_update_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    verifier: Pubkey,
    offset: u8,
    extra_accounts: Vec<VerificationAccountMeta>,
) -> Instruction {
    dynamic_update_config_instruction(
        payer,
        mint,
        mint_authority,
        config,
        MINT_DISCRIMINATOR,
        true,
        offset,
        vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts,
        }],
    )
}

async fn run_dynamic_mint(cpi_mode: bool, break_block: bool, trailing_route: bool) {
    let verifier = Pubkey::new_unique();
    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    if cpi_mode {
        program_test.add_program("dynamic_verifier", verifier, processor!(cpi_verifier));
    } else {
        program_test.add_program(
            "dynamic_verifier",
            verifier,
            processor!(introspection_verifier),
        );
    }

    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let owner = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    assert_eq!(
        mint_authority,
        find_mint_authority_pda(&mint.pubkey(), &context.payer.pubkey()).0
    );
    let config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;

    let initialize = nested_initialize_instruction(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        verifier,
        cpi_mode,
    );
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![initialize],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );

    let destination = create_spl_account(&mut context, &mint, &owner).await;
    let amount = 1_000u64;
    let mut remaining_accounts = vec![
        AccountMeta::new_readonly(verifier, false),
        AccountMeta::new_readonly(context.payer.pubkey(), false),
    ];
    if trailing_route {
        remaining_accounts.push(AccountMeta::new_readonly(context.payer.pubkey(), false));
    }
    let mint_instruction = MintBuilder::new()
        .mint(mint.pubkey())
        .verification_config(config)
        .instructions_sysvar(sysvar::instructions::ID)
        .mint_authority(mint_authority)
        .mint_account(mint.pubkey())
        .destination(destination)
        .amount(amount)
        .add_remaining_accounts(&remaining_accounts)
        .instruction();

    let mut instructions = Vec::new();
    if !cpi_mode {
        let mut verifier_data = vec![MINT_DISCRIMINATOR];
        verifier_data.extend_from_slice(&amount.to_le_bytes());
        instructions.push(Instruction {
            program_id: verifier,
            accounts: vec![
                AccountMeta::new_readonly(mint_authority, false),
                AccountMeta::new(mint.pubkey(), false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(spl_token_2022::ID, false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
            ],
            data: verifier_data,
        });
        if break_block {
            instructions.push(system_instruction::transfer(
                &context.payer.pubkey(),
                &owner.pubkey(),
                1,
            ));
        }
    }
    instructions.push(mint_instruction);

    let result = send_tx(
        &context.banks_client,
        instructions,
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    if break_block || trailing_route {
        assert_transaction_failure(result);
    } else {
        assert_transaction_success(result);
    }
}

#[tokio::test]
async fn dynamic_accounts_are_isolated_in_cpi_mode() {
    run_dynamic_mint(true, false, false).await;
}

#[tokio::test]
async fn dynamic_accounts_require_exact_introspection_block() {
    run_dynamic_mint(false, false, false).await;
}

#[tokio::test]
async fn dynamic_accounts_reject_trailing_routing_accounts() {
    run_dynamic_mint(true, false, true).await;
}

#[tokio::test]
async fn introspection_rejects_noncontiguous_verifier_block() {
    run_dynamic_mint(false, true, false).await;
}

#[tokio::test]
async fn nested_config_grows_and_trims_to_exact_rent_size() {
    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;

    let first_verifier = Pubkey::new_unique();
    let initialize = nested_initialize_instruction(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        first_verifier,
        true,
    );
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![initialize],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );

    let initial_account = context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .unwrap();
    let initial_size = initial_account.data.len();
    let decoded = VerificationConfig::try_from_bytes(&initial_account.data).unwrap();
    assert_eq!(decoded.programs.len(), 1);

    let second_verifier = Pubkey::new_unique();
    let update = nested_update_instruction(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        second_verifier,
        1,
        vec![],
    );
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![update],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );
    let grown_account = context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grown_account.data.len(), initial_size + 36);
    assert_eq!(
        VerificationConfig::try_from_bytes(&grown_account.data)
            .unwrap()
            .programs
            .len(),
        2
    );

    let shrink = nested_update_instruction(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        first_verifier,
        0,
        vec![],
    );
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![shrink],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );
    let shrunk_account = context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .unwrap();
    let rent = context.banks_client.get_rent().await.unwrap();
    assert_eq!(shrunk_account.data.len(), grown_account.data.len() - 35);
    assert_eq!(
        shrunk_account.lamports,
        rent.minimum_balance(shrunk_account.data.len())
    );

    let trim = TrimVerificationConfigBuilder::new()
        .mint(mint.pubkey())
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(context.payer.pubkey())
        .mint_account(mint.pubkey())
        .config_account(config)
        .recipient(context.payer.pubkey())
        .trim_verification_config_args(TrimVerificationConfigArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            size: 1,
            close: false,
        })
        .instruction();
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![trim],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );
    let trimmed_account = context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trimmed_account.data.len(), initial_size - 35);
    assert_eq!(
        trimmed_account.lamports,
        rent.minimum_balance(trimmed_account.data.len())
    );
}

#[test]
fn routing_fits_v0_with_and_without_lookup_table() {
    assert_eq!(MAX_VERIFICATION_PROGRAMS, 10);
    assert_eq!(MAX_VERIFICATION_EXTRAS_PER_PROGRAM, 8);
    assert_eq!(MAX_TOTAL_VERIFICATION_EXTRAS, 32);

    let payer = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let mint_authority = Pubkey::new_unique();
    let config = Pubkey::new_unique();
    let account_metas_pda = Pubkey::new_unique();
    let transfer_hook_pda = Pubkey::new_unique();
    let transfer_hook_program = Pubkey::from(security_token_transfer_hook::id());
    let mut extras_left = MAX_TOTAL_VERIFICATION_EXTRAS;
    let programs: Vec<ClientVerificationProgramConfig> = (0..MAX_VERIFICATION_PROGRAMS)
        .map(|program_index| {
            let extra_count = extras_left.min(MAX_VERIFICATION_EXTRAS_PER_PROGRAM);
            extras_left -= extra_count;
            ClientVerificationProgramConfig {
                program_id: Pubkey::new_unique(),
                extra_accounts: (0..extra_count)
                    .map(|extra_index| ClientVerificationAccountMeta {
                        discriminator: 0,
                        address_config: [(program_index * MAX_VERIFICATION_EXTRAS_PER_PROGRAM
                            + extra_index) as u8; 32],
                        is_signer: false,
                        is_writable: false,
                    })
                    .collect(),
            }
        })
        .collect();

    let v0_transaction_size = |instruction: Instruction, lookup_addresses: &[Pubkey]| {
        let lookups = if lookup_addresses.is_empty() {
            vec![]
        } else {
            vec![
                solana_sdk::address_lookup_table::AddressLookupTableAccount {
                    key: Pubkey::new_unique(),
                    addresses: lookup_addresses.to_vec(),
                },
            ]
        };
        let message = solana_sdk::message::v0::Message::try_compile(
            &payer,
            &[instruction],
            &lookups,
            solana_sdk::hash::Hash::new_unique(),
        )
        .unwrap();
        1 + 64
            + solana_sdk::message::VersionedMessage::V0(message)
                .serialize()
                .len()
    };
    let initialize = |programs| {
        InitializeVerificationConfigBuilder::new()
            .mint(mint)
            .verification_config_or_mint_authority(mint_authority)
            .instructions_sysvar_or_creator(payer)
            .payer(payer)
            .mint_account(mint)
            .config_account(config)
            .initialize_verification_config_args(ClientInitializeArgs {
                instruction_discriminator: TRANSFER_DISCRIMINATOR,
                cpi_mode: false,
                programs,
            })
            .account_metas_pda(Some(account_metas_pda))
            .transfer_hook_pda(Some(transfer_hook_pda))
            .transfer_hook_program(Some(transfer_hook_program))
            .instruction()
    };

    let monolithic = initialize(programs.clone());
    let monolithic_addresses: Vec<Pubkey> = monolithic
        .accounts
        .iter()
        .map(|account| account.pubkey)
        .collect();
    let monolithic_size = v0_transaction_size(monolithic, &monolithic_addresses);
    assert!(
        monolithic_size > security_token_client::verification::MAX_V0_TRANSACTION_SIZE,
        "monolithic maximum config unexpectedly fits in {monolithic_size} bytes"
    );

    for (index, program) in programs.iter().cloned().enumerate() {
        let instruction = if index == 0 {
            initialize(vec![program])
        } else {
            UpdateVerificationConfigBuilder::new()
                .mint(mint)
                .verification_config_or_mint_authority(mint_authority)
                .instructions_sysvar_or_creator(payer)
                .payer(payer)
                .mint_account(mint)
                .config_account(config)
                .update_verification_config_args(ClientUpdateArgs {
                    instruction_discriminator: TRANSFER_DISCRIMINATOR,
                    cpi_mode: false,
                    offset: index as u8,
                    programs: vec![program],
                })
                .account_metas_pda(Some(account_metas_pda))
                .transfer_hook_pda(Some(transfer_hook_pda))
                .transfer_hook_program(Some(transfer_hook_program))
                .instruction()
        };
        let chunk_size = v0_transaction_size(instruction, &[]);
        assert!(
            chunk_size <= security_token_client::verification::MAX_V0_TRANSACTION_SIZE,
            "config chunk {index} is {chunk_size} bytes"
        );
    }

    let account_count = 9 + MAX_VERIFICATION_PROGRAMS + MAX_TOTAL_VERIFICATION_EXTRAS;
    let addresses: Vec<Pubkey> = (0..account_count).map(|_| Pubkey::new_unique()).collect();
    let representative_instruction = Instruction {
        program_id: Pubkey::new_unique(),
        accounts: addresses[..15]
            .iter()
            .map(|address| AccountMeta::new_readonly(*address, false))
            .collect(),
        data: vec![0; 9],
    };
    let representative_size = v0_transaction_size(representative_instruction, &[]);
    assert!(
        representative_size <= security_token_client::verification::MAX_V0_TRANSACTION_SIZE,
        "representative routing without a lookup table is {representative_size} bytes"
    );

    let instruction = Instruction {
        program_id: Pubkey::new_unique(),
        accounts: addresses
            .iter()
            .map(|address| AccountMeta::new_readonly(*address, false))
            .collect(),
        data: vec![0; 9],
    };
    let lookup_table = solana_sdk::address_lookup_table::AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses,
    };
    let message = solana_sdk::message::v0::Message::try_compile(
        &payer,
        &[instruction],
        &[lookup_table],
        solana_sdk::hash::Hash::new_unique(),
    )
    .unwrap();
    assert_eq!(message.address_table_lookups.len(), 1);
    let serialized_size = 1
        + 64
        + solana_sdk::message::VersionedMessage::V0(message)
            .serialize()
            .len();
    assert!(
        serialized_size <= security_token_client::verification::MAX_V0_TRANSACTION_SIZE,
        "maximum routing V0 transaction is {serialized_size} bytes"
    );
}

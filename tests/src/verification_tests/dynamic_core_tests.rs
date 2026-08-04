use crate::helpers::{
    add_dummy_verification_program, assert_transaction_failure, assert_transaction_success,
    create_minimal_security_token_mint, create_spl_account, find_mint_authority_pda,
    find_permanent_delegate_pda, find_transfer_hook_pda, find_verification_config_pda,
    get_token_account_state, send_v0_tx as send_tx, DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID,
};
use security_token_client::{
    instructions::{
        InitializeVerificationConfigBuilder, MintBuilder, TransferBuilder,
        TrimVerificationConfigBuilder, UpdateVerificationConfigBuilder,
        INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR, MINT_DISCRIMINATOR, TRANSFER_DISCRIMINATOR,
        UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{
        InitializeVerificationConfigArgs as ClientInitializeArgs, TrimVerificationConfigArgs,
        UpdateVerificationConfigArgs as ClientUpdateArgs,
        VerificationAccountMeta as ClientVerificationAccountMeta,
        VerificationProgramConfig as ClientVerificationProgramConfig,
    },
};

fn client_programs(programs: &[VerificationProgramConfig]) -> Vec<ClientVerificationProgramConfig> {
    programs
        .iter()
        .map(|program| ClientVerificationProgramConfig {
            program_id: Pubkey::from(program.program_id),
            extra_accounts: program
                .extra_accounts
                .iter()
                .map(|meta| ClientVerificationAccountMeta {
                    discriminator: meta.discriminator,
                    address_config: meta.address_config,
                    is_signer: meta.is_signer,
                    is_writable: meta.is_writable,
                })
                .collect(),
        })
        .collect()
}
use security_token_program::constants::{
    MAX_TOTAL_VERIFICATION_EXTRAS, MAX_VERIFICATION_EXTRAS_PER_PROGRAM, MAX_VERIFICATION_PROGRAMS,
};
use security_token_program::instructions::{
    InitializeVerificationConfigArgs, UpdateVerificationConfigArgs, VerificationAccountMeta,
    VerificationProgramConfig,
};
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
use spl_discriminator::SplDiscriminate;
use spl_tlv_account_resolution::{account::ExtraAccountMeta, seeds::Seed};
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;
use spl_transfer_hook_interface::{
    get_extra_account_metas_address, instruction::ExecuteInstruction,
    offchain::add_extra_account_metas_for_execute,
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

fn seed_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 5);
    assert_eq!(instruction_data[0], MINT_DISCRIMINATOR);
    let (expected_extra, _) = Pubkey::find_program_address(&[accounts[1].key.as_ref()], program_id);
    assert_eq!(accounts[4].key, &expected_extra);
    Ok(())
}

fn transfer_verifier_one(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 5);
    assert_eq!(instruction_data.len(), 9);
    assert_eq!(instruction_data[0], TRANSFER_DISCRIMINATOR);
    assert!(!accounts[0].is_writable);
    assert!(!accounts[1].is_writable);
    assert!(!accounts[2].is_writable);
    assert!(!accounts[3].is_writable);
    let (expected_extra, _) = Pubkey::find_program_address(&[accounts[1].key.as_ref()], program_id);
    assert_eq!(accounts[4].key, &expected_extra);
    Ok(())
}

fn transfer_verifier_two(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 8);
    assert_eq!(instruction_data.len(), 9);
    assert_eq!(instruction_data[0], TRANSFER_DISCRIMINATOR);
    let (expected_first, _) = Pubkey::find_program_address(
        &[accounts[0].key.as_ref(), accounts[1].key.as_ref()],
        program_id,
    );
    assert_eq!(accounts[4].key, &expected_first);
    let (expected_second, _) =
        Pubkey::find_program_address(&[accounts[4].key.as_ref()], program_id);
    assert_eq!(accounts[5].key, &expected_second);
    assert_eq!(accounts[6].key, accounts[0].key);
    assert!(accounts[7].is_signer);
    assert!(!accounts[7].is_writable);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn nested_initialize_config_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    instruction_discriminator: u8,
    programs: Vec<VerificationProgramConfig>,
) -> Instruction {
    let mut builder = InitializeVerificationConfigBuilder::new();
    builder
        .mint(mint)
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(payer)
        .payer(payer)
        .mint_account(mint)
        .config_account(config)
        .initialize_verification_config_args(ClientInitializeArgs {
            instruction_discriminator,
            cpi_mode: true,
            programs: client_programs(&programs),
        });
    if instruction_discriminator == TRANSFER_DISCRIMINATOR {
        builder
            .account_metas_pda(Some(get_extra_account_metas_address(
                &mint,
                &Pubkey::from(security_token_transfer_hook::id()),
            )))
            .transfer_hook_pda(Some(find_transfer_hook_pda(&mint).0))
            .transfer_hook_program(Some(Pubkey::from(security_token_transfer_hook::id())));
    }
    let mut instruction = builder.instruction();
    let args = InitializeVerificationConfigArgs {
        instruction_discriminator,
        cpi_mode: true,
        programs,
    };
    instruction.data = vec![INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR];
    instruction.data.extend_from_slice(&args.to_bytes_inner());
    instruction
}

#[allow(clippy::too_many_arguments)]
fn nested_update_transfer_config_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    offset: u8,
    programs: Vec<VerificationProgramConfig>,
) -> Instruction {
    let mut instruction = UpdateVerificationConfigBuilder::new()
        .mint(mint)
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(payer)
        .payer(payer)
        .mint_account(mint)
        .config_account(config)
        .update_verification_config_args(ClientUpdateArgs {
            instruction_discriminator: TRANSFER_DISCRIMINATOR,
            cpi_mode: true,
            offset,
            programs: client_programs(&programs),
        })
        .account_metas_pda(Some(get_extra_account_metas_address(
            &mint,
            &Pubkey::from(security_token_transfer_hook::id()),
        )))
        .transfer_hook_pda(Some(find_transfer_hook_pda(&mint).0))
        .transfer_hook_program(Some(Pubkey::from(security_token_transfer_hook::id())))
        .instruction();
    let args = UpdateVerificationConfigArgs {
        instruction_discriminator: TRANSFER_DISCRIMINATOR,
        cpi_mode: true,
        offset,
        programs,
    };
    instruction.data = vec![UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR];
    instruction.data.extend_from_slice(&args.to_bytes_inner());
    instruction
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
    let mut instruction = InitializeVerificationConfigBuilder::new()
        .mint(mint)
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(payer)
        .payer(payer)
        .mint_account(mint)
        .config_account(config)
        .initialize_verification_config_args(ClientInitializeArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            cpi_mode,
            programs: vec![ClientVerificationProgramConfig {
                program_id: verifier,
                extra_accounts: vec![ClientVerificationAccountMeta {
                    discriminator: extra.discriminator,
                    address_config: extra.address_config,
                    is_signer: extra.is_signer,
                    is_writable: extra.is_writable,
                }],
            }],
        })
        .instruction();

    let args = InitializeVerificationConfigArgs {
        instruction_discriminator: MINT_DISCRIMINATOR,
        cpi_mode,
        programs: vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts: vec![extra],
        }],
    };
    instruction.data = vec![INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR];
    instruction.data.extend_from_slice(&args.to_bytes_inner());
    instruction
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
    let mut instruction = UpdateVerificationConfigBuilder::new()
        .mint(mint)
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(payer)
        .payer(payer)
        .mint_account(mint)
        .config_account(config)
        .update_verification_config_args(ClientUpdateArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            cpi_mode: true,
            offset,
            programs: vec![ClientVerificationProgramConfig {
                program_id: verifier,
                extra_accounts: extra_accounts
                    .iter()
                    .map(|meta| ClientVerificationAccountMeta {
                        discriminator: meta.discriminator,
                        address_config: meta.address_config,
                        is_signer: meta.is_signer,
                        is_writable: meta.is_writable,
                    })
                    .collect(),
            }],
        })
        .instruction();
    let args = UpdateVerificationConfigArgs {
        instruction_discriminator: MINT_DISCRIMINATOR,
        cpi_mode: true,
        offset,
        programs: vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts,
        }],
    };
    instruction.data = vec![UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR];
    instruction.data.extend_from_slice(&args.to_bytes_inner());
    instruction
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
async fn seed_extra_is_resolved_at_runtime() {
    let verifier = Pubkey::new_unique();
    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    program_test.add_program("seed_verifier", verifier, processor!(seed_verifier));

    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let owner = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;

    let spl_meta =
        ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 1 }], false, false).unwrap();
    let initialize = nested_initialize_instruction_with_extra(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        verifier,
        true,
        VerificationAccountMeta {
            discriminator: spl_meta.discriminator,
            address_config: spl_meta.address_config,
            is_signer: false,
            is_writable: false,
        },
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
    let (resolved_extra, _) = Pubkey::find_program_address(&[mint.pubkey().as_ref()], &verifier);
    let extra_rent = context
        .banks_client
        .get_rent()
        .await
        .unwrap()
        .minimum_balance(0);
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![system_instruction::transfer(
                &context.payer.pubkey(),
                &resolved_extra,
                extra_rent,
            )],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );
    let mint_instruction = MintBuilder::new()
        .mint(mint.pubkey())
        .verification_config(config)
        .instructions_sysvar(sysvar::instructions::ID)
        .mint_authority(mint_authority)
        .mint_account(mint.pubkey())
        .destination(destination)
        .amount(1_000)
        .add_remaining_accounts(&[
            AccountMeta::new_readonly(verifier, false),
            AccountMeta::new_readonly(resolved_extra, false),
        ])
        .instruction();
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![mint_instruction],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TransferTamper {
    None,
    WrongExtra,
    MissingExtra,
    DirectHookInvocation,
    InsufficientPrivilege,
    NonExecutableVerifier,
    ConflictingDuplicatePrivileges,
}

async fn run_dynamic_transfer_hook(tamper: TransferTamper) {
    let verifier_one = Pubkey::new_unique();
    let verifier_two = Pubkey::new_unique();
    let configured_verifier_one = if tamper == TransferTamper::NonExecutableVerifier {
        Pubkey::new_unique()
    } else {
        verifier_one
    };
    let mut program_test = ProgramTest::default();
    program_test.prefer_bpf(true);
    program_test.add_program("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.add_program(
        "security_token_transfer_hook",
        Pubkey::from(security_token_transfer_hook::id()),
        None,
    );
    program_test.prefer_bpf(false);
    program_test.add_program(
        "transfer_verifier_one",
        verifier_one,
        processor!(transfer_verifier_one),
    );
    program_test.add_program(
        "transfer_verifier_two",
        verifier_two,
        processor!(transfer_verifier_two),
    );
    add_dummy_verification_program(&mut program_test);

    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let source_owner = Keypair::new();
    let destination_owner = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;

    let mint_config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;
    let initialize_mint_config = nested_initialize_config_instruction(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        mint_config,
        MINT_DISCRIMINATOR,
        vec![VerificationProgramConfig {
            program_id: DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID.to_bytes(),
            extra_accounts: vec![],
        }],
    );
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![initialize_mint_config],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );

    let source = create_spl_account(&mut context, &mint, &source_owner).await;
    let destination = create_spl_account(&mut context, &mint, &destination_owner).await;
    let mint_instruction = MintBuilder::new()
        .mint(mint.pubkey())
        .verification_config(mint_config)
        .instructions_sysvar(sysvar::instructions::ID)
        .mint_authority(mint_authority)
        .mint_account(mint.pubkey())
        .destination(source)
        .amount(250_000)
        .add_remaining_account(AccountMeta::new_readonly(
            DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID,
            false,
        ))
        .instruction();
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![mint_instruction],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );

    let first_pda =
        ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 1 }], false, false).unwrap();
    let second_first_pda = ExtraAccountMeta::new_with_seeds(
        &[Seed::AccountKey { index: 0 }, Seed::AccountKey { index: 1 }],
        false,
        false,
    )
    .unwrap();
    let second_pda =
        ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 4 }], false, false).unwrap();
    let local_meta = |meta: ExtraAccountMeta| VerificationAccountMeta {
        discriminator: meta.discriminator,
        address_config: meta.address_config,
        is_signer: false,
        is_writable: false,
    };
    let mut first_meta = local_meta(first_pda);
    first_meta.is_writable = true;
    let repeated_meta = VerificationAccountMeta {
        is_writable: tamper != TransferTamper::ConflictingDuplicatePrivileges,
        ..first_meta.clone()
    };
    let transfer_config = find_verification_config_pda(mint.pubkey(), TRANSFER_DISCRIMINATOR).0;
    let initialize_transfer_config = nested_initialize_config_instruction(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        transfer_config,
        TRANSFER_DISCRIMINATOR,
        vec![
            VerificationProgramConfig {
                program_id: configured_verifier_one.to_bytes(),
                extra_accounts: vec![first_meta],
            },
            VerificationProgramConfig {
                program_id: verifier_two.to_bytes(),
                extra_accounts: vec![
                    local_meta(second_first_pda),
                    local_meta(second_pda),
                    VerificationAccountMeta {
                        discriminator: 0,
                        address_config: source.to_bytes(),
                        is_signer: false,
                        is_writable: false,
                    },
                    VerificationAccountMeta {
                        discriminator: 0,
                        address_config: context.payer.pubkey().to_bytes(),
                        is_signer: true,
                        is_writable: false,
                    },
                ],
            },
            VerificationProgramConfig {
                program_id: configured_verifier_one.to_bytes(),
                extra_accounts: vec![repeated_meta],
            },
        ],
    );
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            vec![initialize_transfer_config],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );

    let verifier_one_extra =
        Pubkey::find_program_address(&[mint.pubkey().as_ref()], &configured_verifier_one).0;
    let verifier_two_first =
        Pubkey::find_program_address(&[source.as_ref(), mint.pubkey().as_ref()], &verifier_two).0;
    let verifier_two_second =
        Pubkey::find_program_address(&[verifier_two_first.as_ref()], &verifier_two).0;
    let rent = context
        .banks_client
        .get_rent()
        .await
        .unwrap()
        .minimum_balance(0);
    let create_extras = vec![
        system_instruction::transfer(&context.payer.pubkey(), &verifier_one_extra, rent),
        system_instruction::transfer(&context.payer.pubkey(), &verifier_two_first, rent),
        system_instruction::transfer(&context.payer.pubkey(), &verifier_two_second, rent),
    ];
    assert_transaction_success(
        send_tx(
            &context.banks_client,
            create_extras,
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await,
    );

    let transfer_hook_program_id = Pubkey::from(security_token_transfer_hook::id());
    let mut transfer = spl_token_2022::instruction::transfer_checked(
        &TOKEN_22_PROGRAM_ID,
        &source,
        &mint.pubkey(),
        &destination,
        &source_owner.pubkey(),
        &[],
        125_000,
        6,
    )
    .unwrap();
    let banks_client = context.banks_client.clone();
    add_extra_account_metas_for_execute(
        &mut transfer,
        &transfer_hook_program_id,
        &source,
        &mint.pubkey(),
        &destination,
        &source_owner.pubkey(),
        125_000,
        |address| {
            let banks_client = banks_client.clone();
            async move {
                banks_client
                    .get_account(address)
                    .await
                    .map(|account| account.map(|account| account.data))
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            }
        },
    )
    .await
    .unwrap();
    match tamper {
        TransferTamper::None => {}
        TransferTamper::WrongExtra => {
            transfer.accounts.last_mut().unwrap().pubkey = context.payer.pubkey();
        }
        TransferTamper::MissingExtra => {
            transfer.accounts.pop();
        }
        TransferTamper::DirectHookInvocation => {}
        TransferTamper::InsufficientPrivilege => {
            for meta in transfer
                .accounts
                .iter_mut()
                .filter(|meta| meta.pubkey == verifier_one_extra)
            {
                meta.is_writable = false;
            }
        }
        TransferTamper::NonExecutableVerifier | TransferTamper::ConflictingDuplicatePrivileges => {}
    }

    if tamper == TransferTamper::DirectHookInvocation {
        let account_metas_pda =
            get_extra_account_metas_address(&mint.pubkey(), &transfer_hook_program_id);
        let mut data = ExecuteInstruction::SPL_DISCRIMINATOR_SLICE.to_vec();
        data.extend_from_slice(&125_000u64.to_le_bytes());
        let direct_hook = Instruction {
            program_id: transfer_hook_program_id,
            accounts: vec![
                AccountMeta::new_readonly(source, false),
                AccountMeta::new_readonly(mint.pubkey(), false),
                AccountMeta::new_readonly(destination, false),
                AccountMeta::new_readonly(source_owner.pubkey(), false),
                AccountMeta::new_readonly(account_metas_pda, false),
                AccountMeta::new_readonly(transfer_config, false),
                AccountMeta::new_readonly(configured_verifier_one, false),
                AccountMeta::new(verifier_one_extra, false),
                AccountMeta::new_readonly(verifier_two, false),
                AccountMeta::new_readonly(verifier_two_first, false),
                AccountMeta::new_readonly(verifier_two_second, false),
                AccountMeta::new_readonly(source, false),
                AccountMeta::new_readonly(context.payer.pubkey(), true),
                AccountMeta::new_readonly(configured_verifier_one, false),
                AccountMeta::new(verifier_one_extra, false),
                AccountMeta::new_readonly(context.payer.pubkey(), false),
            ],
            data,
        };
        assert_transaction_failure(
            send_tx(
                &context.banks_client,
                vec![direct_hook],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );
        return;
    }

    let result = send_tx(
        &context.banks_client,
        vec![transfer],
        &context.payer.pubkey(),
        vec![&context.payer, &source_owner],
    )
    .await;
    if tamper != TransferTamper::None {
        assert_transaction_failure(result);
    } else {
        assert_transaction_success(result);
        assert_eq!(
            get_token_account_state(&mut context.banks_client, source)
                .await
                .base
                .amount,
            125_000
        );
        assert_eq!(
            get_token_account_state(&mut context.banks_client, destination)
                .await
                .base
                .amount,
            125_000
        );

        let core_transfer = TransferBuilder::new()
            .mint(mint.pubkey())
            .verification_config(transfer_config)
            .permanent_delegate_authority(find_permanent_delegate_pda(&mint.pubkey()).0)
            .mint_account(mint.pubkey())
            .from_token_account(source)
            .to_token_account(destination)
            .transfer_hook_program(transfer_hook_program_id)
            .amount(10_000)
            .add_remaining_account(AccountMeta::new_readonly(verifier_one, false))
            .add_remaining_account(AccountMeta::new(verifier_one_extra, false))
            .add_remaining_account(AccountMeta::new_readonly(verifier_two, false))
            .add_remaining_account(AccountMeta::new_readonly(verifier_two_first, false))
            .add_remaining_account(AccountMeta::new_readonly(verifier_two_second, false))
            .add_remaining_account(AccountMeta::new_readonly(source, false))
            .add_remaining_account(AccountMeta::new_readonly(context.payer.pubkey(), true))
            .add_remaining_account(AccountMeta::new_readonly(verifier_one, false))
            .add_remaining_account(AccountMeta::new(verifier_one_extra, false))
            .instruction();
        assert_transaction_success(
            send_tx(
                &context.banks_client,
                vec![core_transfer],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );
        assert_eq!(
            get_token_account_state(&mut context.banks_client, source)
                .await
                .base
                .amount,
            115_000
        );
        assert_eq!(
            get_token_account_state(&mut context.banks_client, destination)
                .await
                .base
                .amount,
            135_000
        );

        let account_metas_pda =
            get_extra_account_metas_address(&mint.pubkey(), &transfer_hook_program_id);
        let config_before = context
            .banks_client
            .get_account(transfer_config)
            .await
            .unwrap()
            .unwrap();
        let meta_list_before = context
            .banks_client
            .get_account(account_metas_pda)
            .await
            .unwrap()
            .unwrap();
        let unrepresentable = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::InstructionData {
                    index: 0,
                    length: 2,
                },
                Seed::Literal { bytes: vec![5; 27] },
            ],
            false,
            false,
        )
        .unwrap();
        let rejected_update = nested_update_transfer_config_instruction(
            context.payer.pubkey(),
            mint.pubkey(),
            mint_authority,
            transfer_config,
            1,
            vec![VerificationProgramConfig {
                program_id: verifier_two.to_bytes(),
                extra_accounts: vec![local_meta(unrepresentable)],
            }],
        );
        assert_transaction_failure(
            send_tx(
                &context.banks_client,
                vec![rejected_update],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );
        let config_after_rejection = context
            .banks_client
            .get_account(transfer_config)
            .await
            .unwrap()
            .unwrap();
        let meta_list_after_rejection = context
            .banks_client
            .get_account(account_metas_pda)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(config_after_rejection.data, config_before.data);
        assert_eq!(config_after_rejection.lamports, config_before.lamports);
        assert_eq!(meta_list_after_rejection.data, meta_list_before.data);
        assert_eq!(
            meta_list_after_rejection.lamports,
            meta_list_before.lamports
        );

        let surplus = 12_345;
        assert_transaction_success(
            send_tx(
                &context.banks_client,
                vec![system_instruction::transfer(
                    &context.payer.pubkey(),
                    &account_metas_pda,
                    surplus,
                )],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );
        let before_shrink = context
            .banks_client
            .get_account(account_metas_pda)
            .await
            .unwrap()
            .unwrap();
        let shrink_update = nested_update_transfer_config_instruction(
            context.payer.pubkey(),
            mint.pubkey(),
            mint_authority,
            transfer_config,
            1,
            vec![VerificationProgramConfig {
                program_id: verifier_two.to_bytes(),
                extra_accounts: vec![],
            }],
        );
        assert_transaction_success(
            send_tx(
                &context.banks_client,
                vec![shrink_update],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );
        let after_shrink = context
            .banks_client
            .get_account(account_metas_pda)
            .await
            .unwrap()
            .unwrap();
        assert!(after_shrink.data.len() < before_shrink.data.len());
        let rent = context.banks_client.get_rent().await.unwrap();
        assert_eq!(
            after_shrink.lamports,
            rent.minimum_balance(after_shrink.data.len()) + surplus
        );

        let close = TrimVerificationConfigBuilder::new()
            .mint(mint.pubkey())
            .verification_config_or_mint_authority(mint_authority)
            .instructions_sysvar_or_creator(context.payer.pubkey())
            .mint_account(mint.pubkey())
            .config_account(transfer_config)
            .recipient(context.payer.pubkey())
            .account_metas_pda(Some(account_metas_pda))
            .transfer_hook_pda(Some(find_transfer_hook_pda(&mint.pubkey()).0))
            .transfer_hook_program(Some(transfer_hook_program_id))
            .trim_verification_config_args(TrimVerificationConfigArgs {
                instruction_discriminator: TRANSFER_DISCRIMINATOR,
                size: 0,
                close: true,
            })
            .instruction();
        assert_transaction_success(
            send_tx(
                &context.banks_client,
                vec![close],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );

        let mut transfer_after_close = spl_token_2022::instruction::transfer_checked(
            &TOKEN_22_PROGRAM_ID,
            &source,
            &mint.pubkey(),
            &destination,
            &source_owner.pubkey(),
            &[],
            1,
            6,
        )
        .unwrap();
        let banks_client = context.banks_client.clone();
        add_extra_account_metas_for_execute(
            &mut transfer_after_close,
            &transfer_hook_program_id,
            &source,
            &mint.pubkey(),
            &destination,
            &source_owner.pubkey(),
            1,
            |address| {
                let banks_client = banks_client.clone();
                async move {
                    banks_client
                        .get_account(address)
                        .await
                        .map(|account| account.map(|account| account.data))
                        .map_err(|error| {
                            Box::new(error) as Box<dyn std::error::Error + Send + Sync>
                        })
                }
            },
        )
        .await
        .unwrap();
        assert_transaction_failure(
            send_tx(
                &context.banks_client,
                vec![transfer_after_close],
                &context.payer.pubkey(),
                vec![&context.payer, &source_owner],
            )
            .await,
        );

        let reinitialize = nested_initialize_config_instruction(
            context.payer.pubkey(),
            mint.pubkey(),
            mint_authority,
            transfer_config,
            TRANSFER_DISCRIMINATOR,
            vec![VerificationProgramConfig {
                program_id: verifier_one.to_bytes(),
                extra_accounts: vec![],
            }],
        );
        assert_transaction_failure(
            send_tx(
                &context.banks_client,
                vec![reinitialize],
                &context.payer.pubkey(),
                vec![&context.payer],
            )
            .await,
        );
    }
}

#[tokio::test]
async fn dynamic_transfer_hook_routes_isolated_extras() {
    run_dynamic_transfer_hook(TransferTamper::None).await;
}

#[tokio::test]
async fn dynamic_transfer_hook_rejects_wrong_extra() {
    run_dynamic_transfer_hook(TransferTamper::WrongExtra).await;
}

#[tokio::test]
async fn dynamic_transfer_hook_rejects_missing_extra() {
    run_dynamic_transfer_hook(TransferTamper::MissingExtra).await;
}

#[tokio::test]
async fn dynamic_transfer_hook_rejects_direct_invocation() {
    run_dynamic_transfer_hook(TransferTamper::DirectHookInvocation).await;
}

#[tokio::test]
async fn dynamic_transfer_hook_rejects_insufficient_privilege() {
    run_dynamic_transfer_hook(TransferTamper::InsufficientPrivilege).await;
}

#[tokio::test]
async fn dynamic_transfer_hook_rejects_non_executable_verifier() {
    run_dynamic_transfer_hook(TransferTamper::NonExecutableVerifier).await;
}

#[tokio::test]
async fn dynamic_transfer_hook_rejects_conflicting_duplicate_privileges() {
    run_dynamic_transfer_hook(TransferTamper::ConflictingDuplicatePrivileges).await;
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

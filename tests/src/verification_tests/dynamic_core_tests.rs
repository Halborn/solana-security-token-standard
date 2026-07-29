use crate::helpers::{
    assert_transaction_failure, assert_transaction_success, create_minimal_security_token_mint,
    create_spl_account, find_mint_authority_pda, find_verification_config_pda, send_tx,
};
use security_token_client::{
    instructions::{
        InitializeVerificationConfigBuilder, MintBuilder, TrimVerificationConfigBuilder,
        UpdateVerificationConfigBuilder, INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR,
        MINT_DISCRIMINATOR, UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{
        InitializeVerificationConfigArgs as LegacyInitializeArgs, TrimVerificationConfigArgs,
        UpdateVerificationConfigArgs as LegacyUpdateArgs,
    },
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
use spl_tlv_account_resolution::{account::ExtraAccountMeta, seeds::Seed};

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
        .initialize_verification_config_args(LegacyInitializeArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            cpi_mode,
            program_addresses: vec![verifier],
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
        .update_verification_config_args(LegacyUpdateArgs {
            instruction_discriminator: MINT_DISCRIMINATOR,
            cpi_mode: true,
            offset,
            program_addresses: vec![verifier],
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

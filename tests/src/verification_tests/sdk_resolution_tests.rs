use crate::{
    helpers::{
        assert_transaction_success, create_minimal_security_token_mint, create_spl_account,
        find_verification_config_pda, get_mint_state, get_token_account_state,
        send_v0_tx as send_tx,
    },
    verification_tests::verification_helpers::{
        dynamic_initialize_config_instruction_with_mode, dynamic_meta, mint_seed_verifier,
    },
};
use security_token_client::{
    accounts::VerificationConfig as ClientVerificationConfig,
    instructions::{MintBuilder, MINT_DISCRIMINATOR},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    verification::{
        append_verification_accounts, build_introspection_instructions, decode_verification_config,
        resolve_verification_accounts,
    },
};
use security_token_program::instructions::VerificationProgramConfig;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar,
};
use spl_tlv_account_resolution::{account::ExtraAccountMeta, pubkey_data::PubkeyData, seeds::Seed};

const ACCOUNT_DATA_PUBKEY_OFFSET: usize = 3;

struct SdkMintContext {
    context: ProgramTestContext,
    mint: Keypair,
    mint_authority: Pubkey,
    destination: Pubkey,
    config: Pubkey,
}

impl SdkMintContext {
    fn base_instruction(&self, amount: u64) -> Instruction {
        MintBuilder::new()
            .mint(self.mint.pubkey())
            .verification_config(self.config)
            .instructions_sysvar(sysvar::instructions::ID)
            .mint_authority(self.mint_authority)
            .mint_account(self.mint.pubkey())
            .destination(self.destination)
            .amount(amount)
            .instruction()
    }

    async fn decode_config(&mut self) -> ClientVerificationConfig {
        let account = self
            .context
            .banks_client
            .get_account(self.config)
            .await
            .unwrap()
            .unwrap();
        decode_verification_config(&account.data).unwrap()
    }
}

async fn start_sdk_mint_context(
    program_test: ProgramTest,
    mint: Keypair,
    cpi_mode: bool,
    programs: Vec<VerificationProgramConfig>,
) -> SdkMintContext {
    let mut context = program_test.start_with_context().await;
    let owner = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let destination = create_spl_account(&mut context, &mint, &owner).await;
    let config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;
    let initialize = dynamic_initialize_config_instruction_with_mode(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        MINT_DISCRIMINATOR,
        cpi_mode,
        programs,
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
    SdkMintContext {
        context,
        mint,
        mint_authority,
        destination,
        config,
    }
}

fn mint_canonical_accounts(instruction: &Instruction) -> Vec<(AccountMeta, Option<Vec<u8>>)> {
    instruction.accounts[3..]
        .iter()
        .cloned()
        .map(|meta| (meta, None))
        .collect()
}

fn sdk_resolver_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 6);
    assert_eq!(instruction_data[0], MINT_DISCRIMINATOR);
    let expected_source = Pubkey::find_program_address(&[accounts[1].key.as_ref()], program_id).0;
    assert_eq!(accounts[4].key, &expected_source);
    let source_data = accounts[4].try_borrow_data()?;
    assert_eq!(
        &source_data[ACCOUNT_DATA_PUBKEY_OFFSET..ACCOUNT_DATA_PUBKEY_OFFSET + 32],
        accounts[5].key.as_ref()
    );
    Ok(())
}

#[tokio::test]
async fn rust_sdk_resolver_assembles_mint_with_chained_pda_and_account_data() {
    let verifier = Pubkey::new_unique();
    let mint = Keypair::new();
    let resolved = Pubkey::new_unique();
    let source = Pubkey::find_program_address(&[mint.pubkey().as_ref()], &verifier).0;
    let mut source_data = vec![0xA5; ACCOUNT_DATA_PUBKEY_OFFSET + 32];
    source_data[ACCOUNT_DATA_PUBKEY_OFFSET..].copy_from_slice(resolved.as_ref());

    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    program_test.add_program(
        "sdk_resolver_verifier",
        verifier,
        processor!(sdk_resolver_verifier),
    );
    for (address, data) in [(source, source_data), (resolved, Vec::new())] {
        program_test.add_account(
            address,
            Account {
                lamports: 1_000_000,
                data,
                owner: verifier,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    let source_meta = ExtraAccountMeta::new_with_seeds(
        // Mint's canonical verifier ABI is [authority, mint, destination, token program].
        &[Seed::AccountKey { index: 1 }],
        false,
        false,
    )
    .unwrap();
    let resolved_meta = ExtraAccountMeta::new_with_pubkey_data(
        &PubkeyData::AccountData {
            account_index: 4,
            data_index: ACCOUNT_DATA_PUBKEY_OFFSET as u8,
        },
        false,
        false,
    )
    .unwrap();
    let mut setup = start_sdk_mint_context(
        program_test,
        mint,
        true,
        vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts: vec![dynamic_meta(source_meta), dynamic_meta(resolved_meta)],
        }],
    )
    .await;

    let amount = 1_000;
    let base_instruction = setup.base_instruction(amount);
    assert_eq!(base_instruction.accounts.len(), 7);
    let sdk_config = setup.decode_config().await;
    let canonical_accounts = mint_canonical_accounts(&base_instruction);
    let fetched_accounts = [
        (
            source,
            setup
                .context
                .banks_client
                .get_account(source)
                .await
                .unwrap()
                .unwrap()
                .data,
        ),
        (
            resolved,
            setup
                .context
                .banks_client
                .get_account(resolved)
                .await
                .unwrap()
                .unwrap()
                .data,
        ),
    ];
    let groups = resolve_verification_accounts(
        &sdk_config,
        &canonical_accounts,
        &base_instruction.data,
        |address| {
            Ok(fetched_accounts
                .iter()
                .find(|(key, _)| key == &address)
                .map(|(_, data)| data.clone()))
        },
    )
    .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].program_id, verifier);
    assert_eq!(groups[0].extra_accounts[0].pubkey, source);
    assert_eq!(groups[0].extra_accounts[1].pubkey, resolved);

    let assembled = append_verification_accounts(&base_instruction, &groups);
    assert_eq!(base_instruction.accounts.len(), 7);
    assert_eq!(assembled.accounts.len(), 10);
    assert_eq!(assembled.accounts[7].pubkey, verifier);
    assert_eq!(assembled.accounts[8].pubkey, source);
    assert_eq!(assembled.accounts[9].pubkey, resolved);
    assert_transaction_success(
        send_tx(
            &setup.context.banks_client,
            vec![assembled],
            &setup.context.payer.pubkey(),
            vec![&setup.context.payer],
        )
        .await,
    );
    assert_mint_result(&mut setup, amount).await;
}

async fn run_sdk_introspection(verifier_count: usize) {
    assert!((1..=2).contains(&verifier_count));
    let mint = Keypair::new();
    let verifiers = (0..verifier_count)
        .map(|_| Pubkey::new_unique())
        .collect::<Vec<_>>();
    let resolved = verifiers
        .iter()
        .map(|verifier| Pubkey::find_program_address(&[mint.pubkey().as_ref()], verifier).0)
        .collect::<Vec<_>>();

    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    let verifier_names = [
        "sdk_introspection_verifier_one",
        "sdk_introspection_verifier_two",
    ];
    for (index, (verifier, extra)) in verifiers.iter().zip(&resolved).enumerate() {
        program_test.add_program(
            verifier_names[index],
            *verifier,
            processor!(mint_seed_verifier),
        );
        program_test.add_account(
            *extra,
            Account {
                lamports: 1_000_000,
                data: Vec::new(),
                owner: *verifier,
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    let programs = verifiers
        .iter()
        .map(|verifier| {
            let extra =
                ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 1 }], false, false)
                    .unwrap();
            VerificationProgramConfig {
                program_id: verifier.to_bytes(),
                extra_accounts: vec![dynamic_meta(extra)],
            }
        })
        .collect();
    let mut setup = start_sdk_mint_context(program_test, mint, false, programs).await;

    let amount = 2_000;
    let base_instruction = setup.base_instruction(amount);
    let sdk_config = setup.decode_config().await;
    assert!(!sdk_config.cpi_mode);
    let canonical_accounts = mint_canonical_accounts(&base_instruction);
    let mut fetched_accounts = Vec::with_capacity(resolved.len());
    for extra in &resolved {
        let data = setup
            .context
            .banks_client
            .get_account(*extra)
            .await
            .unwrap()
            .unwrap()
            .data;
        fetched_accounts.push((*extra, data));
    }
    let groups = resolve_verification_accounts(
        &sdk_config,
        &canonical_accounts,
        &base_instruction.data,
        |address| {
            Ok(fetched_accounts
                .iter()
                .find(|(key, _)| key == &address)
                .map(|(_, data)| data.clone()))
        },
    )
    .unwrap();
    assert_eq!(groups.len(), verifier_count);
    for (index, group) in groups.iter().enumerate() {
        assert_eq!(group.program_id, verifiers[index]);
        assert_eq!(group.extra_accounts.len(), 1);
        assert_eq!(group.extra_accounts[0].pubkey, resolved[index]);
    }

    let canonical_metas = canonical_accounts
        .iter()
        .map(|(meta, _)| meta.clone())
        .collect::<Vec<_>>();
    let verifier_instructions =
        build_introspection_instructions(&canonical_metas, &base_instruction.data, &groups);
    let assembled = append_verification_accounts(&base_instruction, &groups);

    assert_eq!(verifier_instructions.len(), verifier_count);
    for (index, instruction) in verifier_instructions.iter().enumerate() {
        assert_eq!(instruction.program_id, verifiers[index]);
        assert_eq!(instruction.data, base_instruction.data);
        assert_eq!(instruction.accounts.len(), 5);
        assert_eq!(instruction.accounts[4].pubkey, resolved[index]);
        let tail_index = 7 + index * 2;
        assert_eq!(assembled.accounts[tail_index].pubkey, verifiers[index]);
        assert_eq!(assembled.accounts[tail_index + 1].pubkey, resolved[index]);
    }
    assert_eq!(assembled.accounts.len(), 7 + verifier_count * 2);

    let mut transaction_instructions = verifier_instructions;
    transaction_instructions.push(assembled);
    assert_transaction_success(
        send_tx(
            &setup.context.banks_client,
            transaction_instructions,
            &setup.context.payer.pubkey(),
            vec![&setup.context.payer],
        )
        .await,
    );
    assert_mint_result(&mut setup, amount).await;
}

#[tokio::test]
async fn rust_sdk_builds_introspection_mint_transaction_for_core() {
    run_sdk_introspection(1).await;
}

#[tokio::test]
async fn rust_sdk_builds_multi_verifier_introspection_mint_for_core() {
    run_sdk_introspection(2).await;
}

async fn assert_mint_result(setup: &mut SdkMintContext, amount: u64) {
    assert_eq!(
        get_mint_state(&mut setup.context.banks_client, setup.mint.pubkey())
            .await
            .base
            .supply,
        amount
    );
    assert_eq!(
        get_token_account_state(&mut setup.context.banks_client, setup.destination)
            .await
            .base
            .amount,
        amount
    );
}

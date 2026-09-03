use crate::{
    helpers::{
        assert_instruction_error, assert_security_token_error, assert_transaction_success,
        create_minimal_security_token_mint, create_spl_account, find_verification_config_pda,
        get_mint_state, get_token_account_state, send_v0_tx as send_tx,
    },
    receipt_tests::receipt_helpers::find_common_action_receipt_pda,
    verification_tests::verification_helpers::{
        dynamic_initialize_config_instruction_with_mode, dynamic_meta, mint_seed_verifier,
    },
};
use security_token_client::{
    errors::SecurityTokenProgramError,
    instructions::{
        CloseActionReceiptAccount, CloseActionReceiptAccountInstructionArgs, MintBuilder,
        CLOSE_ACTION_RECEIPT_ACCOUNT_DISCRIMINATOR, MINT_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::CloseActionReceiptArgs,
};
use security_token_program::{
    instructions::{VerificationAccountMeta, VerificationProgramConfig},
    state::{AccountSerialize, Receipt},
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account, account_info::AccountInfo, entrypoint::ProgramResult,
    instruction::AccountMeta, pubkey::Pubkey, signature::Keypair, signer::Signer,
    system_instruction, sysvar,
};
use spl_tlv_account_resolution::{account::ExtraAccountMeta, pubkey_data::PubkeyData, seeds::Seed};

const ACCOUNT_DATA_PUBKEY_OFFSET: usize = 3;
const INSTRUCTION_DATA_PUBKEY_OFFSET: usize = 9;

fn account_data_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 6);
    assert_eq!(instruction_data[0], MINT_DISCRIMINATOR);
    assert_eq!(accounts[4].owner, program_id);
    let source_data = accounts[4].try_borrow_data()?;
    assert_eq!(
        &source_data[ACCOUNT_DATA_PUBKEY_OFFSET..ACCOUNT_DATA_PUBKEY_OFFSET + 32],
        accounts[5].key.as_ref()
    );
    Ok(())
}

fn instruction_data_verifier(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 4);
    assert_eq!(instruction_data.len(), 41);
    assert_eq!(
        instruction_data[0],
        CLOSE_ACTION_RECEIPT_ACCOUNT_DISCRIMINATOR
    );
    assert_eq!(
        &instruction_data[INSTRUCTION_DATA_PUBKEY_OFFSET..],
        accounts[3].key.as_ref()
    );
    Ok(())
}

#[tokio::test]
async fn seed_extra_is_resolved_at_runtime() {
    let verifier = Pubkey::new_unique();
    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    program_test.add_program("seed_verifier", verifier, processor!(mint_seed_verifier));

    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let owner = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;
    let resolved_meta =
        ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 1 }], false, false).unwrap();
    let initialize = dynamic_initialize_config_instruction_with_mode(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        MINT_DISCRIMINATOR,
        true,
        vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts: vec![dynamic_meta(resolved_meta)],
        }],
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
    let resolved = Pubkey::find_program_address(&[mint.pubkey().as_ref()], &verifier).0;
    let rent = context
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
                &resolved,
                rent,
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
            AccountMeta::new_readonly(resolved, false),
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

#[derive(Clone, Copy)]
enum AccountDataTamper {
    None,
    WrongResolvedAccount,
    ShortSourceData,
}

async fn run_account_data_resolution(tamper: AccountDataTamper) {
    let verifier = Pubkey::new_unique();
    let source = Pubkey::new_unique();
    let resolved = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let resolved_bytes = resolved.to_bytes();
    let stored_len = if matches!(tamper, AccountDataTamper::ShortSourceData) {
        31
    } else {
        32
    };
    let mut source_data = vec![0xA5; ACCOUNT_DATA_PUBKEY_OFFSET + stored_len];
    source_data[ACCOUNT_DATA_PUBKEY_OFFSET..].copy_from_slice(&resolved_bytes[..stored_len]);

    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    program_test.add_program(
        "account_data_verifier",
        verifier,
        processor!(account_data_verifier),
    );
    for (address, data) in [
        (source, source_data),
        (resolved, Vec::new()),
        (wrong, Vec::new()),
    ] {
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

    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let owner = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let config = find_verification_config_pda(mint.pubkey(), MINT_DISCRIMINATOR).0;
    let resolved_meta = ExtraAccountMeta::new_with_pubkey_data(
        &PubkeyData::AccountData {
            // Mint exposes four canonical accounts, so the first extra has local index 4.
            account_index: 4,
            data_index: ACCOUNT_DATA_PUBKEY_OFFSET as u8,
        },
        false,
        false,
    )
    .unwrap();
    let initialize = dynamic_initialize_config_instruction_with_mode(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        MINT_DISCRIMINATOR,
        true,
        vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts: vec![
                VerificationAccountMeta {
                    discriminator: 0,
                    address_config: source.to_bytes(),
                    is_signer: false,
                    is_writable: false,
                },
                dynamic_meta(resolved_meta),
            ],
        }],
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
    let supplied = if matches!(tamper, AccountDataTamper::WrongResolvedAccount) {
        wrong
    } else {
        resolved
    };
    let amount = 1_000;
    let mint_instruction = MintBuilder::new()
        .mint(mint.pubkey())
        .verification_config(config)
        .instructions_sysvar(sysvar::instructions::ID)
        .mint_authority(mint_authority)
        .mint_account(mint.pubkey())
        .destination(destination)
        .amount(amount)
        .add_remaining_accounts(&[
            AccountMeta::new_readonly(verifier, false),
            AccountMeta::new_readonly(source, false),
            AccountMeta::new_readonly(supplied, false),
        ])
        .instruction();
    let result = send_tx(
        &context.banks_client,
        vec![mint_instruction],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    match tamper {
        AccountDataTamper::None => assert_transaction_success(result),
        AccountDataTamper::WrongResolvedAccount => assert_security_token_error(
            result,
            SecurityTokenProgramError::AccountIntersectionMismatch,
        ),
        AccountDataTamper::ShortSourceData => {
            assert_instruction_error(result, "InvalidAccountData")
        }
    }
    let expected_amount = if matches!(tamper, AccountDataTamper::None) {
        amount
    } else {
        0
    };
    assert_eq!(
        get_mint_state(&mut context.banks_client, mint.pubkey())
            .await
            .base
            .supply,
        expected_amount
    );
    assert_eq!(
        get_token_account_state(&mut context.banks_client, destination)
            .await
            .base
            .amount,
        expected_amount
    );
}

#[tokio::test]
async fn pubkey_from_previous_extra_account_data_resolves_in_core_cpi() {
    run_account_data_resolution(AccountDataTamper::None).await;
}

#[tokio::test]
async fn pubkey_from_account_data_rejects_wrong_runtime_account() {
    run_account_data_resolution(AccountDataTamper::WrongResolvedAccount).await;
}

#[tokio::test]
async fn pubkey_from_account_data_rejects_short_source_data() {
    run_account_data_resolution(AccountDataTamper::ShortSourceData).await;
}

#[derive(Clone, Copy)]
enum InstructionDataTamper {
    None,
    WrongResolvedAccount,
}

async fn run_instruction_data_resolution(tamper: InstructionDataTamper) {
    let verifier = Pubkey::new_unique();
    let resolved = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let mint = Keypair::new();
    let action_id = 42;
    let receipt = find_common_action_receipt_pda(&mint.pubkey(), &resolved, action_id).0;

    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    program_test.add_program(
        "instruction_data_verifier",
        verifier,
        processor!(instruction_data_verifier),
    );
    program_test.add_account(
        receipt,
        Account {
            lamports: 1_000_000,
            data: Receipt::new().unwrap().to_bytes(),
            owner: SECURITY_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    for address in [resolved, wrong] {
        program_test.add_account(
            address,
            Account {
                lamports: 1_000_000,
                data: Vec::new(),
                owner: verifier,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    let mut context = program_test.start_with_context().await;
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let config =
        find_verification_config_pda(mint.pubkey(), CLOSE_ACTION_RECEIPT_ACCOUNT_DISCRIMINATOR).0;
    let resolved_meta = ExtraAccountMeta::new_with_pubkey_data(
        &PubkeyData::InstructionData {
            index: INSTRUCTION_DATA_PUBKEY_OFFSET as u8,
        },
        false,
        false,
    )
    .unwrap();
    let initialize = dynamic_initialize_config_instruction_with_mode(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        CLOSE_ACTION_RECEIPT_ACCOUNT_DISCRIMINATOR,
        true,
        vec![VerificationProgramConfig {
            program_id: verifier.to_bytes(),
            extra_accounts: vec![dynamic_meta(resolved_meta)],
        }],
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

    let supplied = if matches!(tamper, InstructionDataTamper::WrongResolvedAccount) {
        wrong
    } else {
        resolved
    };
    let close = CloseActionReceiptAccount {
        mint: mint.pubkey(),
        verification_config_or_mint_authority: config,
        instructions_sysvar_or_creator: sysvar::instructions::ID,
        receipt_account: receipt,
        destination: context.payer.pubkey(),
        mint_account: mint.pubkey(),
    }
    .instruction_with_remaining_accounts(
        CloseActionReceiptAccountInstructionArgs {
            close_action_receipt_args: CloseActionReceiptArgs {
                action_id,
                token_account: resolved,
            },
        },
        &[
            AccountMeta::new_readonly(verifier, false),
            AccountMeta::new_readonly(supplied, false),
        ],
    );
    let result = send_tx(
        &context.banks_client,
        vec![close],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    match tamper {
        InstructionDataTamper::None => assert_transaction_success(result),
        InstructionDataTamper::WrongResolvedAccount => assert_security_token_error(
            result,
            SecurityTokenProgramError::AccountIntersectionMismatch,
        ),
    }
    let receipt_after = context.banks_client.get_account(receipt).await.unwrap();
    assert_eq!(
        receipt_after.is_none(),
        matches!(tamper, InstructionDataTamper::None)
    );
}

#[tokio::test]
async fn pubkey_from_instruction_data_resolves_in_core_cpi() {
    run_instruction_data_resolution(InstructionDataTamper::None).await;
}

#[tokio::test]
async fn pubkey_from_instruction_data_rejects_wrong_runtime_account() {
    run_instruction_data_resolution(InstructionDataTamper::WrongResolvedAccount).await;
}

#[tokio::test]
async fn pubkey_from_instruction_data_rejects_out_of_bounds_config() {
    let mut program_test =
        ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    program_test.prefer_bpf(false);
    let mut context = program_test.start_with_context().await;
    let mint = Keypair::new();
    let (mint_authority, _) =
        create_minimal_security_token_mint(&mut context, &mint, None, 6).await;
    let config =
        find_verification_config_pda(mint.pubkey(), CLOSE_ACTION_RECEIPT_ACCOUNT_DISCRIMINATOR).0;
    let resolved_meta = ExtraAccountMeta::new_with_pubkey_data(
        &PubkeyData::InstructionData {
            // The instruction is 41 bytes, so byte 10 cannot start a 32-byte key.
            index: (INSTRUCTION_DATA_PUBKEY_OFFSET + 1) as u8,
        },
        false,
        false,
    )
    .unwrap();
    let initialize = dynamic_initialize_config_instruction_with_mode(
        context.payer.pubkey(),
        mint.pubkey(),
        mint_authority,
        config,
        CLOSE_ACTION_RECEIPT_ACCOUNT_DISCRIMINATOR,
        true,
        vec![VerificationProgramConfig {
            program_id: Pubkey::new_unique().to_bytes(),
            extra_accounts: vec![dynamic_meta(resolved_meta)],
        }],
    );
    let result = send_tx(
        &context.banks_client,
        vec![initialize],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    assert_instruction_error(result, "InvalidArgument");
    assert!(context
        .banks_client
        .get_account(config)
        .await
        .unwrap()
        .is_none());
}

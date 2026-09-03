use crate::helpers::{
    add_dummy_verification_program, assert_transaction_failure, assert_transaction_success,
    create_minimal_security_token_mint, create_spl_account, find_permanent_delegate_pda,
    find_verification_config_pda, get_token_account_state, send_v0_tx as send_tx,
    DEFAULT_DUMMY_VERIFICATION_PROGRAM_ID,
};
use crate::verification_tests::verification_helpers::{
    dynamic_initialize_config_instruction, dynamic_update_config_instruction,
};
use security_token_client::{
    instructions::{MintBuilder, TransferBuilder, MINT_DISCRIMINATOR, TRANSFER_DISCRIMINATOR},
    programs::SECURITY_TOKEN_PROGRAM_ID,
};

use security_token_program::instructions::{VerificationAccountMeta, VerificationProgramConfig};
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
fn nested_update_transfer_config_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    offset: u8,
    programs: Vec<VerificationProgramConfig>,
) -> Instruction {
    dynamic_update_config_instruction(
        payer,
        mint,
        mint_authority,
        config,
        TRANSFER_DISCRIMINATOR,
        true,
        offset,
        programs,
    )
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
    let initialize_mint_config = dynamic_initialize_config_instruction(
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
    let initialize_transfer_config = dynamic_initialize_config_instruction(
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

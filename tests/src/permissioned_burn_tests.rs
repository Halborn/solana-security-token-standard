use security_token_client::{
    errors::SecurityTokenProgramError,
    instructions::{BurnBuilder, InitializeMintBuilder, BURN_DISCRIMINATOR},
    types::{
        InitializeMintArgs, MetadataPointerArgs, MintArgs, ScaledUiAmountConfigArgs,
        TokenMetadataArgs,
    },
};
use solana_program_test::ProgramTestContext;
use solana_sdk::{
    account::AccountSharedData,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use crate::helpers::{
    assert_security_token_error, assert_transaction_failure, assert_transaction_success,
    create_dummy_verification_from_instruction, create_permissioned_burn_mint, create_spl_account,
    create_verification_config, find_mint_authority_pda, find_mint_freeze_authority_pda,
    find_permanent_delegate_pda, get_account, get_default_verification_programs, get_mint_state,
    get_token_account_state, initialize_mint, initialize_mint_verification_and_mint_to_account,
    send_tx, start_with_context, start_with_token_2022_v11_context,
};

const AMOUNT: u64 = 1_000_000;

async fn setup_protected_mint() -> (ProgramTestContext, Keypair, Pubkey, Pubkey, Pubkey) {
    let mut context = start_with_token_2022_v11_context().await;
    let mint = Keypair::new();
    let (mint_authority, _) = create_permissioned_burn_mint(&mut context, &mint, None, 6).await;
    let payer = context.payer.insecure_clone();
    let token_account = create_spl_account(&mut context, &mint, &payer).await;
    initialize_mint_verification_and_mint_to_account(
        &mint,
        &mut context,
        mint_authority,
        token_account,
        AMOUNT,
    )
    .await;
    let burn_config = create_verification_config(
        &mut context,
        &mint,
        mint_authority,
        BURN_DISCRIMINATOR,
        get_default_verification_programs(),
        None,
    )
    .await;
    let (permanent_delegate, _) = find_permanent_delegate_pda(&mint.pubkey());
    (
        context,
        mint,
        token_account,
        burn_config,
        permanent_delegate,
    )
}

async fn assert_supply_and_balance(
    context: &mut ProgramTestContext,
    mint: Pubkey,
    token_account: Pubkey,
    expected: u64,
) {
    assert_eq!(
        get_mint_state(&mut context.banks_client, mint)
            .await
            .base
            .supply,
        expected
    );
    assert_eq!(
        get_token_account_state(&mut context.banks_client, token_account)
            .await
            .base
            .amount,
        expected
    );
}

fn ssts_burn_instructions(
    mint: Pubkey,
    token_account: Pubkey,
    burn_config: Pubkey,
    permanent_delegate: Pubkey,
    amount: u64,
) -> Vec<solana_sdk::instruction::Instruction> {
    let burn = BurnBuilder::new()
        .mint(mint)
        .verification_config(burn_config)
        .permanent_delegate(permanent_delegate)
        .mint_account(mint)
        .token_account(token_account)
        .amount(amount)
        .instruction();
    vec![create_dummy_verification_from_instruction(&burn), burn]
}

fn permissioned_burn_checked_instruction(
    account: Pubkey,
    mint: Pubkey,
    permissioned_burn_authority: Pubkey,
    authority: Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = [0; 11];
    data[..2].copy_from_slice(&[46, 2]);
    data[2..10].copy_from_slice(&amount.to_le_bytes());
    data[10] = decimals;

    Instruction {
        program_id: spl_token_2022::ID,
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new(mint, false),
            AccountMeta::new_readonly(permissioned_burn_authority, true),
            AccountMeta::new_readonly(authority, true),
        ],
        data: data.to_vec(),
    }
}

fn permissioned_burn_entry(data: &[u8]) -> Option<(usize, &[u8])> {
    let mut offset = 166;
    while offset + 4 <= data.len() {
        let extension_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let extension_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let entry = data.get(offset + 4..offset + 4 + extension_len)?;
        if extension_type == 28 {
            return Some((offset, entry));
        }
        if extension_type == 0 {
            return None;
        }
        offset += 4 + extension_len;
    }
    None
}

fn permissioned_burn_authority(data: &[u8]) -> Option<Pubkey> {
    let (_, entry) = permissioned_burn_entry(data)?;
    let authority = Pubkey::new_from_array(entry.try_into().unwrap());
    (authority != Pubkey::default()).then_some(authority)
}

fn permissioned_burn_header_offset(data: &[u8]) -> usize {
    permissioned_burn_entry(data).unwrap().0
}

#[tokio::test]
async fn protected_mint_blocks_native_burns_and_allows_ssts_burn() {
    let (mut context, mint, token_account, burn_config, permanent_delegate) =
        setup_protected_mint().await;
    let mint_account = get_account(&mut context, mint.pubkey()).await.unwrap();
    assert_eq!(
        permissioned_burn_authority(&mint_account.data),
        Some(permanent_delegate)
    );

    for instruction in [
        spl_token_2022::instruction::burn(
            &spl_token_2022::ID,
            &token_account,
            &mint.pubkey(),
            &context.payer.pubkey(),
            &[],
            1,
        )
        .unwrap(),
        spl_token_2022::instruction::burn_checked(
            &spl_token_2022::ID,
            &token_account,
            &mint.pubkey(),
            &context.payer.pubkey(),
            &[],
            1,
            6,
        )
        .unwrap(),
    ] {
        let result = send_tx(
            &context.banks_client,
            vec![instruction],
            &context.payer.pubkey(),
            vec![&context.payer],
        )
        .await;
        assert_transaction_failure(result);
    }

    let wrong_authority = Keypair::new();
    let wrong_permissioned_burn = permissioned_burn_checked_instruction(
        token_account,
        mint.pubkey(),
        wrong_authority.pubkey(),
        context.payer.pubkey(),
        1,
        6,
    );
    let result = send_tx(
        &context.banks_client,
        vec![wrong_permissioned_burn],
        &context.payer.pubkey(),
        vec![&context.payer, &wrong_authority],
    )
    .await;
    assert_transaction_failure(result);

    assert_eq!(
        get_mint_state(&mut context.banks_client, mint.pubkey())
            .await
            .base
            .supply,
        AMOUNT
    );
    assert_eq!(
        get_token_account_state(&mut context.banks_client, token_account)
            .await
            .base
            .amount,
        AMOUNT
    );

    let result = send_tx(
        &context.banks_client,
        ssts_burn_instructions(
            mint.pubkey(),
            token_account,
            burn_config,
            permanent_delegate,
            AMOUNT / 2,
        ),
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_transaction_success(result);
    assert_eq!(
        get_mint_state(&mut context.banks_client, mint.pubkey())
            .await
            .base
            .supply,
        AMOUNT / 2
    );
    assert_eq!(
        get_token_account_state(&mut context.banks_client, token_account)
            .await
            .base
            .amount,
        AMOUNT / 2
    );
}

#[tokio::test]
async fn ssts_burn_rejects_mismatched_permissioned_burn_authority() {
    let (mut context, mint, token_account, burn_config, permanent_delegate) =
        setup_protected_mint().await;
    let mut mint_account = get_account(&mut context, mint.pubkey()).await.unwrap();
    let header = permissioned_burn_header_offset(&mint_account.data);

    mint_account.data[header + 4..header + 36].fill(7);
    context.set_account(&mint.pubkey(), &AccountSharedData::from(mint_account));
    let result = send_tx(
        &context.banks_client,
        ssts_burn_instructions(
            mint.pubkey(),
            token_account,
            burn_config,
            permanent_delegate,
            1,
        ),
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_security_token_error(
        result,
        SecurityTokenProgramError::PermissionedBurnAuthorityMismatch,
    );
    assert_supply_and_balance(&mut context, mint.pubkey(), token_account, AMOUNT).await;
}

#[tokio::test]
async fn ssts_burn_rejects_malformed_permissioned_burn_config() {
    let (mut context, mint, token_account, burn_config, permanent_delegate) =
        setup_protected_mint().await;
    let mut mint_account = get_account(&mut context, mint.pubkey()).await.unwrap();
    let header = permissioned_burn_header_offset(&mint_account.data);

    mint_account.data[header + 2..header + 4].copy_from_slice(&31u16.to_le_bytes());
    context.set_account(&mint.pubkey(), &AccountSharedData::from(mint_account));
    let result = send_tx(
        &context.banks_client,
        ssts_burn_instructions(
            mint.pubkey(),
            token_account,
            burn_config,
            permanent_delegate,
            1,
        ),
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_security_token_error(result, SecurityTokenProgramError::MalformedPermissionedBurn);
    assert_supply_and_balance(&mut context, mint.pubkey(), token_account, AMOUNT).await;
}

#[tokio::test]
async fn cleared_permissioned_burn_authority_uses_native_burn() {
    let (mut context, mint, token_account, burn_config, permanent_delegate) =
        setup_protected_mint().await;
    let mut mint_account = get_account(&mut context, mint.pubkey()).await.unwrap();
    let header = permissioned_burn_header_offset(&mint_account.data);

    mint_account.data[header + 4..header + 36].fill(0);
    context.set_account(&mint.pubkey(), &AccountSharedData::from(mint_account));
    let result = send_tx(
        &context.banks_client,
        ssts_burn_instructions(
            mint.pubkey(),
            token_account,
            burn_config,
            permanent_delegate,
            1,
        ),
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;
    assert_transaction_success(result);
    assert_supply_and_balance(&mut context, mint.pubkey(), token_account, AMOUNT - 1).await;
}

#[tokio::test]
async fn legacy_initialize_payload_remains_accepted() {
    let mut context = start_with_context().await;
    let mint = Keypair::new();
    let (mint_authority, _) = find_mint_authority_pda(&mint.pubkey(), &context.payer.pubkey());
    let (freeze_authority, _) = find_mint_freeze_authority_pda(&mint.pubkey());
    let args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority,
        },
        ix_metadata_pointer: None,
        ix_metadata: None,
        ix_scaled_ui_amount: None,
        ix_default_account_state: None,
        ix_permissioned_burn: false,
    };
    let mut instruction = InitializeMintBuilder::new()
        .mint(mint.pubkey())
        .authority(mint_authority)
        .payer(context.payer.pubkey())
        .initialize_mint_args(args)
        .instruction();
    instruction.data.pop();

    let result = send_tx(
        &context.banks_client,
        vec![instruction],
        &context.payer.pubkey(),
        vec![&context.payer, &mint],
    )
    .await;
    assert_transaction_success(result);
    let mint_account = get_account(&mut context, mint.pubkey()).await.unwrap();
    assert!(permissioned_burn_entry(&mint_account.data).is_none());
}

#[tokio::test]
async fn all_optional_extensions_initialize_with_permissioned_burn() {
    let mut context = start_with_token_2022_v11_context().await;
    let mint = Keypair::new();
    let (mint_authority, _) = find_mint_authority_pda(&mint.pubkey(), &context.payer.pubkey());
    let (freeze_authority, _) = find_mint_freeze_authority_pda(&mint.pubkey());
    let args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority,
        },
        ix_metadata_pointer: Some(MetadataPointerArgs {
            authority: context.payer.pubkey(),
            metadata_address: mint.pubkey(),
        }),
        ix_metadata: Some(TokenMetadataArgs {
            name: "Protected".into(),
            symbol: "PRT".into(),
            uri: "https://example.com/protected.json".into(),
            additional_metadata: vec![],
        }),
        ix_scaled_ui_amount: Some(ScaledUiAmountConfigArgs {
            authority: mint_authority,
            multiplier: 1f64.to_le_bytes(),
            new_multiplier_effective_timestamp: 0,
            new_multiplier: 1f64.to_le_bytes(),
        }),
        ix_default_account_state: Some(1),
        ix_permissioned_burn: true,
    };
    initialize_mint(&mint, &mut context, mint_authority, &args).await;

    let mint_account = get_account(&mut context, mint.pubkey()).await.unwrap();
    let (permanent_delegate, _) = find_permanent_delegate_pda(&mint.pubkey());
    assert_eq!(
        permissioned_burn_authority(&mint_account.data),
        Some(permanent_delegate)
    );
}

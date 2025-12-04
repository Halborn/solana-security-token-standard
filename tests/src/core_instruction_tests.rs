//! Security Token Standard Integration Tests

use borsh::BorshDeserialize;
use security_token_client::accounts::{MintAuthority, VerificationConfig};
use security_token_client::instructions::{
    InitializeMintBuilder, TrimVerificationConfigBuilder, UpdateMetadataBuilder,
    UpdateVerificationConfigBuilder, UPDATE_METADATA_DISCRIMINATOR,
};
use security_token_client::programs::SECURITY_TOKEN_PROGRAM_ID;

use crate::helpers::{
    assert_transaction_failure, assert_transaction_success, initialize_mint,
    initialize_verification_config, send_tx,
};
use security_token_client::types::{
    InitializeMintArgs, InitializeVerificationConfigArgs, MetadataPointerArgs, MintArgs,
    ScaledUiAmountConfigArgs, TokenMetadataArgs, TrimVerificationConfigArgs, UpdateMetadataArgs,
    UpdateVerificationConfigArgs,
};
use solana_program_test::ProgramTest;
use solana_sdk::sysvar;
use solana_sdk::{pubkey::Pubkey, signature::Signer};
use spl_token_2022::extension::metadata_pointer::MetadataPointer as SolanaProgramMetadataPointer;
use spl_token_2022::extension::scaled_ui_amount::ScaledUiAmountConfig as SolanaProgramScaledUiAmountConfig;
use spl_token_2022::extension::{
    permanent_delegate::PermanentDelegate, transfer_hook::TransferHook, BaseStateWithExtensions,
    ExtensionType, StateWithExtensions,
};
use spl_token_2022::state::Mint;
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;
use spl_token_metadata_interface::state::TokenMetadata as SolanaProgramTokenMetadata;

fn encode_additional_metadata(pairs: &[(String, String)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (k, v) in pairs {
        let k_bytes = k.as_bytes();
        buf.extend_from_slice(&(k_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(k_bytes);

        let v_bytes = v.as_bytes();
        buf.extend_from_slice(&(v_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(v_bytes);
    }
    buf
}

#[tokio::test]
async fn test_program_loads() {
    let program_test = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);

    let (_banks_client, _payer, _recent_blockhash) = program_test.start().await;

    // Basic test that program loads successfully
    println!("Security Token program loaded successfully");
}

#[tokio::test]
async fn test_unknown_instruction_discriminator() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);
    let (banks_client, payer, recent_blockhash) = pt.start().await;

    let unknown_discriminator = 99u8;
    let instruction_data = vec![unknown_discriminator];

    let instruction = solana_sdk::instruction::Instruction {
        program_id: SECURITY_TOKEN_PROGRAM_ID,
        accounts: vec![],
        data: instruction_data,
    };
    let mut transaction =
        solana_sdk::transaction::Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    let result = banks_client.process_transaction(transaction).await;
    let error = result.unwrap_err();
    let error_string = format!("{:?}", error);
    assert!(
        error_string.contains("InvalidInstructionData")
            || error_string.contains("InvalidInstruction"),
        "Expected InvalidInstructionData error, got: {}",
        error_string
    );
}

#[tokio::test]
async fn test_initialize_mint_with_all_extensions() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);
    // Create mint keypair - mint account must be a signer when creating new account
    let mint_keypair = solana_sdk::signature::Keypair::new();
    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let (mint_authority_pda, mint_authority_bump) = Pubkey::find_program_address(
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

    println!("Mint authority PDA: {}", mint_authority_pda);

    let additional_metadata: Vec<(String, String)> = vec![
        ("type".to_string(), "security".to_string()),
        ("compliance".to_string(), "reg_d".to_string()),
        ("issuer".to_string(), "Hoodies Inc".to_string()),
        ("industry".to_string(), "blockchain".to_string()),
    ];

    let encoded = encode_additional_metadata(&additional_metadata);

    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: Some(MetadataPointerArgs {
            authority: context.payer.pubkey(),
            metadata_address: mint_keypair.pubkey(),
        }),
        ix_metadata: Some(TokenMetadataArgs {
            update_authority: context.payer.pubkey(),
            mint: mint_keypair.pubkey(),
            name: name.to_string().into(),
            symbol: symbol.to_string().into(),
            uri: uri.to_string().into(),
            additional_metadata: encoded,
        }),
        ix_scaled_ui_amount: Some(ScaledUiAmountConfigArgs {
            authority: mint_authority_pda,
            multiplier: [1u8; 8].into(),
            new_multiplier_effective_timestamp: 0,
            new_multiplier: [1u8; 8].into(),
        }),
    };

    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;
    // Verify mint account was created correctly
    let mint_account = context
        .banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .unwrap()
        .expect("Mint account should exist");
    assert_eq!(
        mint_account.owner, TOKEN_22_PROGRAM_ID,
        "Mint should be owned by Token-2022 program"
    );

    // Verify mint authority account
    let mint_authority_account = context
        .banks_client
        .get_account(mint_authority_pda)
        .await
        .unwrap()
        .expect("Mint authority PDA should exist");
    assert_eq!(
        mint_authority_account.owner, SECURITY_TOKEN_PROGRAM_ID,
        "Mint authority PDA should be owned by security token program"
    );

    let mint_authority_state = MintAuthority::try_from_slice(&mint_authority_account.data)
        .expect("Should deserialize MintAuthority state");
    assert_eq!(
        mint_authority_state.mint,
        mint_keypair.pubkey(),
        "MintAuthority mint should match created mint"
    );
    assert_eq!(
        mint_authority_state.mint_creator,
        context.payer.pubkey(),
        "MintAuthority creator should match payer"
    );
    assert_eq!(
        mint_authority_state.bump, mint_authority_bump,
        "MintAuthority bump should match PDA derivation"
    );

    let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_account.data)
        .expect("Should be able to unpack mint with extensions");

    // Verify basic mint properties
    assert_eq!(
        mint_with_extensions.base.decimals, 6,
        "Mint should have 6 decimals"
    );
    assert!(
        mint_with_extensions.base.is_initialized,
        "Mint should be initialized"
    );
    assert_eq!(
        mint_with_extensions.base.supply, 0,
        "Initial supply should be 0"
    );

    // Get all extension types present in the mint
    let extension_types = mint_with_extensions
        .get_extension_types()
        .expect("Should be able to get extension types");

    // Verify ALL extensions are present
    assert!(
        extension_types.contains(&ExtensionType::PermanentDelegate),
        "PermanentDelegate extension should be present"
    );
    assert!(
        extension_types.contains(&ExtensionType::TransferHook),
        "TransferHook extension should be present"
    );
    assert!(
        extension_types.contains(&ExtensionType::Pausable),
        "Pausable extension should be present"
    );
    assert!(
        extension_types.contains(&ExtensionType::MetadataPointer),
        "MetadataPointer extension should be present"
    );
    assert!(
        extension_types.contains(&ExtensionType::ScaledUiAmount),
        "ScaledUiAmount extension should be present"
    );

    // Verify extensions
    let metadata_pointer = mint_with_extensions
        .get_extension::<SolanaProgramMetadataPointer>()
        .expect("MetadataPointer extension should be accessible");

    assert_eq!(
        Option::<Pubkey>::from(metadata_pointer.authority),
        Some(context.payer.pubkey()),
        "MetadataPointer authority should be our mint authority PDA"
    );
    assert_eq!(
        Option::<Pubkey>::from(metadata_pointer.metadata_address),
        Some(mint_keypair.pubkey()),
        "MetadataPointer should point to mint address"
    );

    let scaled_ui_amount = mint_with_extensions
        .get_extension::<SolanaProgramScaledUiAmountConfig>()
        .expect("ScaledUiAmount extension should be accessible");

    assert_eq!(
        Option::<Pubkey>::from(scaled_ui_amount.authority),
        Some(mint_authority_pda),
        "ScaledUiAmount authority should be our mint authority PDA"
    );
    assert_eq!(
        f64::from(scaled_ui_amount.multiplier),
        f64::from_le_bytes([1u8; 8]),
        "ScaledUiAmount multiplier should match expected value"
    );

    // Try to get metadata from mint account using the SPL Token 2022 extension system
    let metadata_result =
        mint_with_extensions.get_variable_len_extension::<SolanaProgramTokenMetadata>();

    match metadata_result {
        Ok(metadata) => {
            // Verify metadata fields match what we set during initialization
            assert_eq!(
                metadata.name, name,
                "Metadata name should match initialization"
            );
            assert_eq!(
                metadata.symbol, symbol,
                "Metadata symbol should match initialization"
            );
            assert_eq!(
                metadata.uri, uri,
                "Metadata URI should match initialization"
            );

            // Verify update authority is set to creator (not PDA) since PDA can't sign initialization
            assert_eq!(
                Option::<Pubkey>::from(metadata.update_authority),
                Some(mint_authority_pda),
                "Metadata update authority should be mint authority PDA"
            );

            // Verify mint field points to correct mint
            assert_eq!(
                metadata.mint,
                mint_keypair.pubkey(),
                "Metadata mint field should point to correct mint"
            );

            // Check that expected additional metadata is present
            let additional_map: std::collections::HashMap<String, String> =
                metadata.additional_metadata.iter().cloned().collect();

            // Verify each expected additional metadata field automatically
            for (expected_key, expected_value) in &additional_metadata {
                assert_eq!(
                    additional_map.get(expected_key),
                    Some(expected_value),
                    "Additional metadata should contain '{}={}'",
                    expected_key,
                    expected_value
                );
            }
        }
        Err(_e) => {
            panic!("Failed to parse token metadata from mint account");
        }
    }

    // Verify PermanentDelegate configuration
    let permanent_delegate = mint_with_extensions
        .get_extension::<PermanentDelegate>()
        .expect("PermanentDelegate extension should be accessible");
    // Find permanent delegate PDA using the same seed as in the program
    let (expected_permanent_delegate, _bump) = Pubkey::find_program_address(
        &[b"mint.permanent_delegate", mint_keypair.pubkey().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    assert_eq!(
        Option::<Pubkey>::from(permanent_delegate.delegate),
        Some(expected_permanent_delegate),
        "PermanentDelegate should be our permanent delegate PDA"
    );
    // Verify TransferHook configuration
    let transfer_hook = mint_with_extensions
        .get_extension::<TransferHook>()
        .expect("TransferHook extension should be accessible");

    // Find transfer hook PDA using the same seed as in the program
    let (expected_transfer_hook_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.transfer_hook", mint_keypair.pubkey().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    assert_eq!(
        Option::<Pubkey>::from(transfer_hook.authority),
        Some(expected_transfer_hook_pda),
        "TransferHook authority should be our mint authority PDA"
    );

    // Verify mint authority
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let mint_authority_pubkey = mint_with_extensions.base.mint_authority.unwrap();
    assert_eq!(mint_authority_pubkey, mint_authority_pda);
}

#[tokio::test]
async fn test_update_metadata() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);

    // Create mint keypair - mint account must be a signer when creating new account
    let mint_keypair = solana_sdk::signature::Keypair::new();

    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let additional_metadata: Vec<(String, String)> = vec![
        ("type".to_string(), "security".to_string()),
        ("compliance".to_string(), "reg_d".to_string()),
        ("issuer".to_string(), "Hoodies Inc".to_string()),
        ("industry".to_string(), "blockchain".to_string()),
    ];

    let encoded = encode_additional_metadata(&additional_metadata);

    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";
    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );
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

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: Some(MetadataPointerArgs {
            authority: context.payer.pubkey(),
            metadata_address: mint_keypair.pubkey(),
        }),
        ix_metadata: Some(TokenMetadataArgs {
            update_authority: context.payer.pubkey(),
            mint: mint_keypair.pubkey(),
            name: name.to_string().into(),
            symbol: symbol.to_string().into(),
            uri: uri.to_string().into(),
            additional_metadata: encoded,
        }),
        ix_scaled_ui_amount: None,
    };

    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    let verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: vec![],
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &verification_config_args,
    )
    .await;

    let updated_name = "Updated Security Token";
    let updated_symbol = "UHST";
    let updated_uri = "https://example.com/tokens";

    let updated_additional_metadata: Vec<(String, String)> = vec![
        (
            "type".to_string(),
            "security wow!!!! security wow!!!! security wow!!!!".to_string(),
        ),
        (
            "compliance".to_string(),
            "reg_d req_g reg_d req_g reg_d req_g and overflow".to_string(),
        ),
        ("new_field".to_string(), "new_value".to_string()),
    ];

    let encoded = encode_additional_metadata(&updated_additional_metadata);

    let update_metadata_args = UpdateMetadataArgs {
        metadata: TokenMetadataArgs {
            update_authority: context.payer.pubkey(),
            mint: mint_keypair.pubkey(),
            name: updated_name.to_string().into(),
            symbol: updated_symbol.to_string().into(),
            uri: updated_uri.to_string().into(),
            additional_metadata: encoded,
        },
    };

    let update_metadata_ix = UpdateMetadataBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(verification_config_pda)
        .instructions_sysvar_or_creator(sysvar::instructions::ID)
        .mint_account(mint_keypair.pubkey())
        .mint_authority(mint_authority_pda)
        .payer(context.payer.pubkey())
        .update_metadata_args(update_metadata_args)
        .instruction();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[update_metadata_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    // Process transaction
    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
        .await;

    assert_transaction_success(result);

    // Verify metadata was updated correctly
    let mint_account = context
        .banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .unwrap()
        .unwrap();

    let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_account.data)
        .expect("Should be able to unpack mint with extensions");

    let metadata = mint_with_extensions
        .get_variable_len_extension::<SolanaProgramTokenMetadata>()
        .expect("Should be able to get updated metadata");

    // Verify updated metadata fields
    assert_eq!(metadata.name, updated_name, "Name should be updated");
    assert_eq!(metadata.symbol, updated_symbol, "Symbol should be updated");
    assert_eq!(metadata.uri, updated_uri, "URI should be updated");

    // Verify additional metadata was updated
    let additional_map: std::collections::HashMap<String, String> =
        metadata.additional_metadata.iter().cloned().collect();

    // Verify new values are set correctly
    assert_eq!(
        additional_map.get("type"),
        Some(&"security wow!!!! security wow!!!! security wow!!!!".to_string()),
        "Type should be updated"
    );
    assert_eq!(
        additional_map.get("compliance"),
        Some(&"reg_d req_g reg_d req_g reg_d req_g and overflow".to_string()),
        "Compliance should be updated"
    );

    assert_eq!(
        additional_map.get("new_field"),
        Some(&"new_value".to_string()),
        "new_field should be created"
    );

    // Verify old fields were removed (issuer and industry should no longer exist)
    assert_eq!(
        additional_map.get("issuer"),
        None,
        "Issuer field should be removed during atomic update"
    );
    assert_eq!(
        additional_map.get("industry"),
        None,
        "Industry field should be removed during atomic update"
    );

    assert_eq!(
        additional_map.len(),
        3,
        "Should only have 3 additional metadata fields after update (type and compliance) and new_field"
    );
}

#[tokio::test]
async fn test_initialize_mint_with_different_decimals() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);

    let mut context = pt.start_with_context().await;

    // Test different decimal values
    for decimals in [0, 2, 6, 9, 18] {
        let mint_keypair = solana_sdk::signature::Keypair::new();
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

        let mint_args = InitializeMintArgs {
            ix_mint: MintArgs {
                decimals,
                mint_authority: context.payer.pubkey(),
                freeze_authority: freeze_authority_pda,
            },
            ix_metadata_pointer: None, // No metadata pointer for this test
            ix_metadata: None,
            ix_scaled_ui_amount: None, // No scaled UI amount for this test
        };

        initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

        // Verify the mint was created with correct decimals
        let mint_account = context
            .banks_client
            .get_account(mint_keypair.pubkey())
            .await
            .unwrap()
            .unwrap();

        let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_account.data)
            .expect("Should be able to unpack mint with extensions");

        assert_eq!(
            mint_with_extensions.base.decimals, decimals,
            "Mint should have {} decimals",
            decimals
        );
    }
}

#[tokio::test]
async fn test_initialize_mint_error_cases() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);

    let context = pt.start_with_context().await;

    // Test Case 1: Mint account not a signer
    {
        let mint_keypair = solana_sdk::signature::Keypair::new();
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

        let ix = InitializeMintBuilder::new()
            .mint(mint_keypair.pubkey())
            .payer(context.payer.pubkey())
            .authority(mint_authority_pda)
            .initialize_mint_args(InitializeMintArgs {
                ix_mint: MintArgs {
                    decimals: 10,
                    mint_authority: context.payer.pubkey(),
                    freeze_authority: freeze_authority_pda,
                },
                ix_metadata_pointer: None, // No metadata pointer for this test
                ix_metadata: None,
                ix_scaled_ui_amount: None, // No scaled UI amount for this test
            })
            .instruction();

        let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

        let transaction_result = std::panic::catch_unwind(|| {
            solana_sdk::transaction::Transaction::new_signed_with_payer(
                &[ix],
                Some(&context.payer.pubkey()),
                &[&context.payer],
                recent_blockhash,
            )
        });
        assert!(
            transaction_result.is_err(),
            "Should fail when creator is not a signer"
        );
        let panic_payload = transaction_result.unwrap_err();
        let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
            s.clone()
        } else {
            format!("{:?}", panic_payload)
        };
        assert!(
            panic_msg.contains("NotEnoughSigners"),
            "Expected NotEnoughSigners error, got: {}",
            panic_msg
        );
    }

    // Test Case 2: Creator not a signer
    {
        let mint_keypair = solana_sdk::signature::Keypair::new();
        let fake_creator = solana_sdk::signature::Keypair::new();
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

        let ix = InitializeMintBuilder::new()
            .mint(mint_keypair.pubkey())
            .payer(fake_creator.pubkey())
            .authority(mint_authority_pda)
            .initialize_mint_args(InitializeMintArgs {
                ix_mint: MintArgs {
                    decimals: 10,
                    mint_authority: context.payer.pubkey(),
                    freeze_authority: freeze_authority_pda,
                },
                ix_metadata_pointer: None, // No metadata pointer for this test
                ix_metadata: None,
                ix_scaled_ui_amount: None, // No scaled UI amount for this test
            })
            .instruction();

        let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

        let transaction_result = std::panic::catch_unwind(|| {
            solana_sdk::transaction::Transaction::new_signed_with_payer(
                &[ix],
                Some(&context.payer.pubkey()),
                &[&context.payer, &mint_keypair],
                recent_blockhash,
            )
        });
        assert!(
            transaction_result.is_err(),
            "Should fail when creator is not a signer"
        );
        let panic_payload = transaction_result.unwrap_err();
        let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
            s.clone()
        } else {
            format!("{:?}", panic_payload)
        };
        assert!(
            panic_msg.contains("NotEnoughSigners"),
            "Expected NotEnoughSigners error, got: {}",
            panic_msg
        );
    }
}

#[tokio::test]
async fn test_verification_config() {
    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_PROGRAM_ID, None);
    pt.prefer_bpf(true);

    // Create mint keypair - we need this to derive the verification config PDA
    let mint_keypair = solana_sdk::signature::Keypair::new();
    let mut context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
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

    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";

    let mint_args = InitializeMintArgs {
        ix_mint: MintArgs {
            decimals: 6,
            mint_authority: context.payer.pubkey(),
            freeze_authority: freeze_authority_pda,
        },
        ix_metadata_pointer: Some(MetadataPointerArgs {
            authority: context.payer.pubkey(),
            metadata_address: mint_keypair.pubkey(),
        }),
        ix_metadata: Some(TokenMetadataArgs {
            update_authority: context.payer.pubkey(),
            mint: mint_keypair.pubkey(),
            name: name.to_string().into(),
            symbol: symbol.to_string().into(),
            uri: uri.to_string().into(),
            additional_metadata: vec![],
        }),
        ix_scaled_ui_amount: None,
    };

    initialize_mint(&mint_keypair, &mut context, mint_authority_pda, &mint_args).await;

    let (program_1, program_2) = (Pubkey::new_unique(), Pubkey::new_unique());

    // Define some test verification programs (using known program IDs)
    let verification_programs = vec![program_1, program_2];

    // Derive the expected VerificationConfig PDA
    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            &mint_keypair.pubkey().to_bytes(),
            &[UPDATE_METADATA_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let verification_config_args = InitializeVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: verification_programs.clone(),
    };

    initialize_verification_config(
        &mint_keypair,
        &mut context,
        mint_authority_pda,
        verification_config_pda,
        &verification_config_args,
    )
    .await;

    // Verify the PDA account was created correctly
    let config_account = context
        .banks_client
        .get_account(verification_config_pda)
        .await
        .unwrap()
        .expect("VerificationConfig PDA should exist");

    // Verify account owner is our security token program
    assert_eq!(
        config_account.owner, SECURITY_TOKEN_PROGRAM_ID,
        "Config PDA should be owned by security token program"
    );

    let stored_config = VerificationConfig::try_from_slice(&config_account.data)
        .expect("Should be able to deserialize VerificationConfig");

    assert_eq!(
        stored_config.instruction_discriminator, UPDATE_METADATA_DISCRIMINATOR,
        "Instruction discriminator should match"
    );

    assert_eq!(
        stored_config.verification_programs.len(),
        verification_programs.len(),
        "Number of verification programs should match"
    );

    for (i, expected_program) in verification_programs.iter().enumerate() {
        assert_eq!(
            stored_config.verification_programs[i], *expected_program,
            "Program at index {} should match",
            i
        );
    }

    let (program_3, program_4) = (Pubkey::new_unique(), Pubkey::new_unique());

    // Define new verification programs to add (at offset 1)
    let new_verification_programs = vec![program_3, program_4];
    let offset = 1u8; // Start replacing at index 1
    let update_verification_config_args = UpdateVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: new_verification_programs.clone(),
        offset,
    };

    let update_config_ix = UpdateVerificationConfigBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(context.payer.pubkey())
        .config_account(verification_config_pda)
        .mint_account(mint_keypair.pubkey())
        .payer(context.payer.pubkey())
        .update_verification_config_args(update_verification_config_args)
        .instruction();

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[update_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;
    assert_transaction_success(result);

    // Verify the updated configuration
    let updated_config_account = context
        .banks_client
        .get_account(verification_config_pda)
        .await
        .unwrap()
        .unwrap();

    let updated_config = VerificationConfig::try_from_slice(&updated_config_account.data)
        .expect("Should be able to deserialize updated VerificationConfig");

    // Verify the configuration was updated correctly
    assert_eq!(
        updated_config.instruction_discriminator, UPDATE_METADATA_DISCRIMINATOR,
        "Instruction discriminator should remain unchanged"
    );

    // The original program at index 0 should remain
    assert_eq!(
        updated_config.verification_programs[0], verification_programs[0],
        "Original program at index 0 should remain unchanged"
    );

    // The programs starting at offset should be updated
    for (i, expected_program) in new_verification_programs.iter().enumerate() {
        let config_index = offset as usize + i;
        assert_eq!(
            updated_config.verification_programs[config_index], *expected_program,
            "Updated program at index {} should match",
            config_index
        );
    }

    let original_recipient_balance = context
        .banks_client
        .get_account(context.payer.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    // Test offset gap
    let update_verification_config_args = UpdateVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        cpi_mode: false,
        program_addresses: [Pubkey::new_unique(), Pubkey::new_unique()].to_vec(),
        offset: 4, // Current len is 3
    };

    let update_config_ix = UpdateVerificationConfigBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(context.payer.pubkey())
        .config_account(verification_config_pda)
        .mint_account(mint_keypair.pubkey())
        .payer(context.payer.pubkey())
        .update_verification_config_args(update_verification_config_args)
        .instruction();

    let result = send_tx(
        &context.banks_client,
        vec![update_config_ix],
        &context.payer.pubkey(),
        vec![&context.payer],
    )
    .await;

    assert_transaction_failure(result);

    // Test Case 1: Trim the array from 3 programs to 2 programs (recover some rent)
    let new_size = 2u8;
    let close = false;

    let trim_verification_config_args = TrimVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        size: new_size,
        close,
    };

    let trim_verification_config_ix = TrimVerificationConfigBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(context.payer.pubkey())
        .config_account(verification_config_pda)
        .mint_account(mint_keypair.pubkey())
        .recipient(context.payer.pubkey())
        .trim_verification_config_args(trim_verification_config_args)
        .instruction();

    let trim_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[trim_verification_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(trim_transaction)
        .await;

    assert_transaction_success(result);

    // Verify the trimmed configuration
    let trimmed_config_account = context
        .banks_client
        .get_account(verification_config_pda)
        .await
        .unwrap()
        .unwrap();

    let trimmed_config = VerificationConfig::try_from_slice(&trimmed_config_account.data)
        .expect("Should be able to deserialize trimmed VerificationConfig");

    // Verify the configuration was trimmed correctly
    assert_eq!(
        trimmed_config.instruction_discriminator, UPDATE_METADATA_DISCRIMINATOR,
        "Instruction discriminator should remain unchanged"
    );

    assert_eq!(
        trimmed_config.verification_programs.len(),
        new_size as usize,
        "Verification programs count should be trimmed to {}",
        new_size
    );

    // Verify that remaining programs are correct (first 2 programs should remain)
    assert_eq!(
        trimmed_config.verification_programs[0], verification_programs[0],
        "First program should remain unchanged"
    );
    assert_eq!(
        trimmed_config.verification_programs[1], new_verification_programs[0],
        "Second program should be the first updated program"
    );

    // Verify that some rent was recovered
    let new_recipient_balance = context
        .banks_client
        .get_account(context.payer.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    assert!(
        new_recipient_balance > original_recipient_balance,
        "Rent recipient should have received recovered lamports"
    );

    let close_verification_config_args = TrimVerificationConfigArgs {
        instruction_discriminator: UPDATE_METADATA_DISCRIMINATOR,
        size: 0,
        close: true,
    };

    let close_verification_config_ix = TrimVerificationConfigBuilder::new()
        .mint(mint_keypair.pubkey())
        .verification_config_or_mint_authority(mint_authority_pda)
        .instructions_sysvar_or_creator(context.payer.pubkey())
        .config_account(verification_config_pda)
        .mint_account(mint_keypair.pubkey())
        .recipient(context.payer.pubkey())
        .trim_verification_config_args(close_verification_config_args)
        .instruction();

    // Get config account balance before closing
    let config_balance_before_close = trimmed_config_account.lamports;

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[close_verification_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;
    assert_transaction_success(result);

    // Verify the account was closed
    let closed_config_account = context
        .banks_client
        .get_account(verification_config_pda)
        .await
        .unwrap();

    assert!(
        closed_config_account.is_none(),
        "Config account should be closed"
    );

    // Verify all lamports were transferred to recipient
    let final_recipient_balance = context
        .banks_client
        .get_account(context.payer.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    let total_recovered_rent = final_recipient_balance - original_recipient_balance;
    assert!(
        total_recovered_rent >= config_balance_before_close,
        "Should have recovered at least {} lamports, got {}",
        config_balance_before_close,
        total_recovered_rent
    );
}

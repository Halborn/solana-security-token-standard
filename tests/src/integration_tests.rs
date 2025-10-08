//! Security Token Standard Integration Tests

use borsh::BorshDeserialize;
use kaigan::types::RemainderVec;
use security_token_client::{
    InitializeArgs, InitializeMint, InitializeMintArgs, InitializeMintInstructionArgs,
    InitializeVerificationConfig, InitializeVerificationConfigArgs,
    InitializeVerificationConfigInstructionArgs, MetadataPointer, MintAuthority,
    ScaledUiAmountConfig, TokenMetadata, TrimVerificationConfig, TrimVerificationConfigArgs,
    TrimVerificationConfigInstructionArgs, UpdateMetadata, UpdateMetadataArgs,
    UpdateMetadataInstructionArgs, UpdateVerificationConfig, UpdateVerificationConfigArgs,
    UpdateVerificationConfigInstructionArgs, VerificationConfig, SECURITY_TOKEN_ID,
};
use solana_program_test::ProgramTest;
use solana_sdk::sysvar;
use solana_sdk::{pubkey::Pubkey, signature::Signer};
use solana_system_interface::program as system_program;
use spl_token_2022::extension::{
    permanent_delegate::PermanentDelegate, transfer_hook::TransferHook,
};

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
    let program_test = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);

    let (_banks_client, _payer, _recent_blockhash) = program_test.start().await;

    // Basic test that program loads successfully
    println!("Security Token program loaded successfully");
}

#[tokio::test]
async fn test_unknown_instruction_discriminator() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);
    let (banks_client, payer, recent_blockhash) = pt.start().await;

    let unknown_discriminator = 99u8;
    let instruction_data = vec![unknown_discriminator];

    let instruction = solana_sdk::instruction::Instruction {
        program_id: SECURITY_TOKEN_ID,
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
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    // Create mint keypair - mint account must be a signer when creating new account
    let mint_keypair = solana_sdk::signature::Keypair::new();

    let context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    // NOTE: Taken from the pinocchio program
    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    println!("Mint keypair {}", mint_keypair.pubkey());
    println!("Context payer {}", context.payer.pubkey());

    let (mint_authority_pda, mint_authority_bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
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

    let ix = InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        mint_authority_account: mint_authority_pda,
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
        rent: sysvar::rent::ID,
    }
    .instruction(InitializeMintInstructionArgs {
        args: InitializeArgs {
            ix_mint: InitializeMintArgs {
                decimals: 6,
                mint_authority: context.payer.pubkey(),
                freeze_authority: None, // No freeze authority for this test
            },
            ix_metadata_pointer: Some(MetadataPointer {
                authority: context.payer.pubkey(),
                metadata_address: mint_keypair.pubkey(),
            }),
            ix_metadata: Some(TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: name.len() as u32,
                name: name.to_string().into(),
                symbol_len: symbol.len() as u32,
                symbol: symbol.to_string().into(),
                uri_len: uri.len() as u32,
                uri: uri.to_string().into(),
                additional_metadata_len: encoded.len() as u32,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&encoded).unwrap(),
            }),
            ix_scaled_ui_amount: Some(ScaledUiAmountConfig {
                authority: mint_authority_pda,
                multiplier: [1u8; 8].into(),
                new_multiplier_effective_timestamp: 0,
                new_multiplier: [1u8; 8].into(),
            }),
        },
    });

    // let banks_client = &mut context.banks_client;
    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    // Process transaction
    let result = context.banks_client.process_transaction(transaction).await;

    if let Err(error) = &result {
        println!("Transaction failed: {}", error);
        panic!("Transaction failed: {}", error);
    }

    // Verify mint account was created correctly
    let mint_account = context
        .banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .unwrap()
        .expect("Mint account should exist");
    assert_eq!(
        mint_account.owner, spl_token_2022_program,
        "Mint should be owned by Token-2022 program"
    );

    println!("Security Token Mint with ALL extensions created successfully!");
    println!("   Account size: {} bytes", mint_account.data.len());

    // Verify mint authority account
    let mint_authority_account = context
        .banks_client
        .get_account(mint_authority_pda)
        .await
        .unwrap()
        .expect("Mint authority PDA should exist");
    assert_eq!(
        mint_authority_account.owner, SECURITY_TOKEN_ID,
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

    // Parse mint data to verify all parameters (with extensions)
    use spl_token_2022::extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions};
    use spl_token_2022::state::Mint;

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

    println!("Extension types found:");
    for ext_type in &extension_types {
        println!("   - {:?}", ext_type);
    }

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
    use spl_token_2022::extension::metadata_pointer::MetadataPointer as SolanaProgramMetadataPointer;
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
    println!("MetadataPointer extension verified");

    use spl_token_2022::extension::scaled_ui_amount::ScaledUiAmountConfig as SolanaProgramScaledUiAmountConfig;
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
    println!(
        "ScaledUiAmount extension verified: multiplier = {}x",
        f64::from(scaled_ui_amount.multiplier)
    );

    // Verify token metadata through SPL Token Metadata Interface
    println!("Verifying token metadata...");

    // Since metadata is stored in the mint account itself (self-referencing),
    // we can read it directly from the mint account data using the metadata interface
    use spl_token_metadata_interface::state::TokenMetadata as SolanaProgramTokenMetadata;

    // Try to get metadata from mint account using the SPL Token 2022 extension system
    let metadata_result =
        mint_with_extensions.get_variable_len_extension::<SolanaProgramTokenMetadata>();

    match metadata_result {
        Ok(metadata) => {
            println!("Token metadata found and parsed successfully!");

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
                Some(context.payer.pubkey()),
                "Metadata update authority should be creator (payer) during initialization"
            );

            // Verify mint field points to correct mint
            assert_eq!(
                metadata.mint,
                mint_keypair.pubkey(),
                "Metadata mint field should point to correct mint"
            );

            // Verify additional metadata fields
            println!(
                "Additional metadata fields: {}",
                metadata.additional_metadata.len()
            );
            for (key, value) in &metadata.additional_metadata {
                println!("  {} = {}", key, value);
            }

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

            println!("Token metadata verified successfully!");
            println!("  Name: {}", metadata.name);
            println!("  Symbol: {}", metadata.symbol);
            println!("  URI: {}", metadata.uri);
            println!(
                "  Update Authority: {:?}",
                Option::<Pubkey>::from(metadata.update_authority)
            );
            println!(
                "  Additional fields: {}",
                metadata.additional_metadata.len()
            );
            println!("  All expected additional metadata fields verified automatically");
        }
        Err(e) => {
            // If we can't read metadata directly, let's at least verify the extension is present
            println!("Could not parse metadata directly (error: {:?}), but MetadataPointer extension is verified", e);
            println!("This might be expected if metadata requires special parsing or is stored differently");

            // Let's still verify the basic structure exists by checking if TokenMetadata extension type exists
            if extension_types.contains(&ExtensionType::TokenMetadata) {
                println!("TokenMetadata extension type is present in mint");
            } else {
                println!("TokenMetadata extension type not found - metadata may be stored via MetadataPointer only");
            }
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
        &SECURITY_TOKEN_ID,
    );

    assert_eq!(
        Option::<Pubkey>::from(permanent_delegate.delegate),
        Some(expected_permanent_delegate),
        "PermanentDelegate should be our permanent delegate PDA"
    );
    println!("PermanentDelegate extension verified");

    // Verify TransferHook configuration
    let transfer_hook = mint_with_extensions
        .get_extension::<TransferHook>()
        .expect("TransferHook extension should be accessible");

    // Find transfer hook PDA using the same seed as in the program
    let (expected_transfer_hook_pda, _bump) = Pubkey::find_program_address(
        &[b"mint.transfer_hook", mint_keypair.pubkey().as_ref()],
        &SECURITY_TOKEN_ID,
    );

    assert_eq!(
        Option::<Pubkey>::from(transfer_hook.authority),
        Some(expected_transfer_hook_pda),
        "TransferHook authority should be our mint authority PDA"
    );
    println!("TransferHook extension verified");

    // Verify mint authority
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
    );

    let mint_authority_pubkey = mint_with_extensions.base.mint_authority.unwrap();
    assert_eq!(mint_authority_pubkey, mint_authority_pda);
    println!(
        "Mint authority successfully transferred to PDA: {}",
        mint_authority_pda
    );

    //TODO: Verify more
    println!("All extensions verified successfully!");
}

#[tokio::test]
async fn test_update_metadata() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    // Create mint keypair - mint account must be a signer when creating new account
    let mint_keypair = solana_sdk::signature::Keypair::new();

    let context: solana_program_test::ProgramTestContext = pt.start_with_context().await;

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

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

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[b"verification_config", mint_keypair.pubkey().as_ref(), &[1]],
        &SECURITY_TOKEN_ID,
    );
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
    );

    let ix = InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        mint_authority_account: mint_authority_pda,
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
        rent: sysvar::rent::ID,
    }
    .instruction(InitializeMintInstructionArgs {
        args: InitializeArgs {
            ix_mint: InitializeMintArgs {
                decimals: 6,
                mint_authority: context.payer.pubkey(),
                freeze_authority: None, // No freeze authority for this test
            },
            ix_metadata_pointer: Some(MetadataPointer {
                authority: context.payer.pubkey(),
                metadata_address: mint_keypair.pubkey(),
            }),
            ix_metadata: Some(TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: name.len() as u32,
                name: name.to_string().into(),
                symbol_len: symbol.len() as u32,
                symbol: symbol.to_string().into(),
                uri_len: uri.len() as u32,
                uri: uri.to_string().into(),
                additional_metadata_len: encoded.len() as u32,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&encoded).unwrap(),
            }),
            ix_scaled_ui_amount: None,
        },
    });

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let result = context.banks_client.process_transaction(transaction).await;

    if let Err(error) = &result {
        println!("Transaction failed: {}", error);
        panic!("Transaction failed: {}", error);
    }

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

    let update_metadata_instruction = UpdateMetadata {
        verification_config: Some(verification_config_pda),
        instructions_sysvar: sysvar::instructions::ID,
        mint: mint_keypair.pubkey(),
        mint_for_update: mint_keypair.pubkey(),
        mint_authority: context.payer.pubkey(),
        token_program: spl_token_2022_program,
        system_program: system_program::ID,
    }
    .instruction(UpdateMetadataInstructionArgs {
        args: UpdateMetadataArgs {
            metadata: TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: updated_name.len() as u32,
                name: updated_name.to_string().into(),
                symbol_len: updated_symbol.len() as u32,
                symbol: updated_symbol.to_string().into(),
                uri_len: updated_uri.len() as u32,
                uri: updated_uri.to_string().into(),
                additional_metadata_len: encoded.len() as u32,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&encoded).unwrap(),
            },
        },
    });

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let tx_update_metadata = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[update_metadata_instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    // Process transaction
    let result = context
        .banks_client
        .process_transaction(tx_update_metadata)
        .await;

    if let Err(error) = &result {
        println!("Transaction failed: {}", error);
        panic!("Transaction failed: {}", error);
    }

    // Verify metadata was updated correctly
    let mint_account = context
        .banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .unwrap()
        .unwrap();

    use spl_token_2022::extension::{BaseStateWithExtensions, StateWithExtensions};
    use spl_token_2022::state::Mint;
    use spl_token_metadata_interface::state::TokenMetadata as SolanaProgramTokenMetadata;

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
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    let context = pt.start_with_context().await;

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    // Test different decimal values
    for decimals in [0, 2, 6, 9, 18] {
        println!("\n Testing mint initialization with {decimals} decimals");

        let mint_keypair = solana_sdk::signature::Keypair::new();
        let (mint_authority_pda, _bump) = Pubkey::find_program_address(
            &[
                b"mint.authority",
                &mint_keypair.pubkey().to_bytes(),
                &context.payer.pubkey().to_bytes(),
            ],
            &SECURITY_TOKEN_ID,
        );

        let ix = InitializeMint {
            mint: mint_keypair.pubkey(),
            payer: context.payer.pubkey(),
            mint_authority_account: mint_authority_pda,
            token_program: spl_token_2022_program,
            system_program: system_program::ID,
            rent: sysvar::rent::ID,
        }
        .instruction(InitializeMintInstructionArgs {
            args: InitializeArgs {
                ix_mint: InitializeMintArgs {
                    decimals,
                    mint_authority: context.payer.pubkey(),
                    freeze_authority: None, // No freeze authority for this test
                },
                ix_metadata_pointer: None, // No metadata pointer for this test
                ix_metadata: None,
                ix_scaled_ui_amount: None, // No scaled UI amount for this test
            },
        });

        let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[ix],
            Some(&context.payer.pubkey()),
            &[&context.payer, &mint_keypair],
            recent_blockhash,
        );

        let result = context.banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Initialize mint with {} decimals should succeed",
            decimals
        );

        // Verify the mint was created with correct decimals
        let mint_account = context
            .banks_client
            .get_account(mint_keypair.pubkey())
            .await
            .unwrap()
            .unwrap();

        use spl_token_2022::extension::StateWithExtensions;
        use spl_token_2022::state::Mint;

        let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_account.data)
            .expect("Should be able to unpack mint with extensions");

        assert_eq!(
            mint_with_extensions.base.decimals, decimals,
            "Mint should have {} decimals",
            decimals
        );
        println!(
            "Actual mint account size: {} bytes",
            mint_account.data.len()
        );

        println!("{} decimals: verified successfully", decimals);
    }
}

#[tokio::test]
async fn test_initialize_mint_error_cases() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    let context = pt.start_with_context().await;

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    // Test Case 1: Mint account not a signer
    {
        println!("\n Testing error case: mint account not a signer");
        let mint_keypair = solana_sdk::signature::Keypair::new();
        let (mint_authority_pda, _bump) = Pubkey::find_program_address(
            &[
                b"mint.authority",
                &mint_keypair.pubkey().to_bytes(),
                &context.payer.pubkey().to_bytes(),
            ],
            &SECURITY_TOKEN_ID,
        );

        let ix = InitializeMint {
            mint: mint_keypair.pubkey(),
            payer: context.payer.pubkey(),
            mint_authority_account: mint_authority_pda,
            token_program: spl_token_2022_program,
            system_program: system_program::ID,
            rent: sysvar::rent::ID,
        }
        .instruction(InitializeMintInstructionArgs {
            args: InitializeArgs {
                ix_mint: InitializeMintArgs {
                    decimals: 10,
                    mint_authority: context.payer.pubkey(),
                    freeze_authority: None, // No freeze authority for this test
                },
                ix_metadata_pointer: None, // No metadata pointer for this test
                ix_metadata: None,
                ix_scaled_ui_amount: None, // No scaled UI amount for this test
            },
        });

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
        println!("Correctly rejected creator not being signer");
    }

    // Test Case 2: Creator not a signer
    {
        println!("\nTesting error case: creator not a signer");
        let mint_keypair = solana_sdk::signature::Keypair::new();
        let fake_creator = solana_sdk::signature::Keypair::new();
        let (mint_authority_pda, _bump) = Pubkey::find_program_address(
            &[
                b"mint.authority",
                &mint_keypair.pubkey().to_bytes(),
                &context.payer.pubkey().to_bytes(),
            ],
            &SECURITY_TOKEN_ID,
        );

        let ix = InitializeMint {
            mint: mint_keypair.pubkey(),
            payer: fake_creator.pubkey(),
            mint_authority_account: mint_authority_pda,
            token_program: spl_token_2022_program,
            system_program: system_program::ID,
            rent: sysvar::rent::ID,
        }
        .instruction(InitializeMintInstructionArgs {
            args: InitializeArgs {
                ix_mint: InitializeMintArgs {
                    decimals: 10,
                    mint_authority: context.payer.pubkey(),
                    freeze_authority: None, // No freeze authority for this test
                },
                ix_metadata_pointer: None, // No metadata pointer for this test
                ix_metadata: None,
                ix_scaled_ui_amount: None, // No scaled UI amount for this test
            },
        });

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
        println!("Correctly rejected creator not being signer");
    }
}

#[tokio::test]
async fn test_verification_config() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    // Create mint keypair - we need this to derive the verification config PDA
    let mint_keypair = solana_sdk::signature::Keypair::new();
    let context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
    );

    println!("Testing InitializeVerificationConfig");
    println!("Mint keypair: {}", mint_keypair.pubkey());
    println!("Context payer: {}", context.payer.pubkey());

    // First, we need to create a mint (requirement for verification config)
    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    let name = "Test Token";
    let symbol = "TEST";
    let uri = "https://example.com";

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
                freeze_authority: None,
            },
            ix_metadata_pointer: Some(security_token_client::MetadataPointer {
                authority: context.payer.pubkey(),
                metadata_address: mint_keypair.pubkey(),
            }),
            ix_metadata: Some(security_token_client::TokenMetadata {
                update_authority: context.payer.pubkey(),
                mint: mint_keypair.pubkey(),
                name_len: name.len() as u32,
                name: name.to_string().into(),
                symbol_len: symbol.len() as u32,
                symbol: symbol.to_string().into(),
                uri_len: uri.len() as u32,
                uri: uri.to_string().into(),
                additional_metadata_len: 0,
                additional_metadata: RemainderVec::<u8>::try_from_slice(&[]).unwrap(),
            }),
            ix_scaled_ui_amount: None,
        },
    });

    // Create and process mint transaction
    let mint_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[initialize_mint_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let mint_result = context
        .banks_client
        .process_transaction(mint_transaction)
        .await;
    if let Err(error) = &mint_result {
        println!("Mint transaction failed: {}", error);
        panic!("Mint transaction failed: {}", error);
    }
    println!("Mint created successfully");

    // Now test InitializeVerificationConfig

    // Define instruction discriminator (1 byte for "UpdateMetadata" instruction as example)
    let instruction_discriminator: u8 = 1; // UpdateMetadata discriminator

    let (program_1, program_2) = (Pubkey::new_unique(), Pubkey::new_unique());

    // Define some test verification programs (using known program IDs)
    let verification_programs = vec![program_1, program_2];

    // Derive the expected VerificationConfig PDA
    let (config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            &mint_keypair.pubkey().to_bytes(),
            &[instruction_discriminator],
        ],
        &SECURITY_TOKEN_ID,
    );

    println!("Expected config PDA: {}", config_pda);

    // Create InitializeVerificationConfig instruction using generated client code
    let initialize_config_ix = InitializeVerificationConfig {
        config_account: config_pda,
        payer: context.payer.pubkey(),
        mint_account: mint_keypair.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(InitializeVerificationConfigInstructionArgs {
        args: InitializeVerificationConfigArgs {
            instruction_discriminator,
            program_addresses: verification_programs.clone(),
        },
    });

    // Create and process verification config transaction
    let config_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[initialize_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let config_result = context
        .banks_client
        .process_transaction(config_transaction)
        .await;
    if let Err(error) = &config_result {
        println!("VerificationConfig transaction failed: {}", error);
        panic!("VerificationConfig transaction failed: {}", error);
    }

    println!("VerificationConfig created successfully");

    // Verify the PDA account was created correctly
    let config_account = context
        .banks_client
        .get_account(config_pda)
        .await
        .unwrap()
        .expect("VerificationConfig PDA should exist");
    println!(
        "VerificationConfig account data length: {}",
        config_account.data.len()
    );

    // Verify account owner is our security token program
    assert_eq!(
        config_account.owner, SECURITY_TOKEN_ID,
        "Config PDA should be owned by security token program"
    );

    let stored_config = VerificationConfig::try_from_slice(&config_account.data)
        .expect("Should be able to deserialize VerificationConfig");

    assert_eq!(
        stored_config.instruction_discriminator, instruction_discriminator,
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

    println!("VerificationConfig PDA validation successful");

    println!("\nTesting UpdateVerificationConfig");

    let (program_3, program_4) = (Pubkey::new_unique(), Pubkey::new_unique());

    // Define new verification programs to add (at offset 1)
    let new_verification_programs = vec![program_3, program_4];
    let offset = 1u8; // Start replacing at index 1

    // Create UpdateVerificationConfig instruction
    let update_config_ix = UpdateVerificationConfig {
        config_account: config_pda,
        mint_account: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(UpdateVerificationConfigInstructionArgs {
        args: UpdateVerificationConfigArgs {
            instruction_discriminator,
            program_addresses: new_verification_programs.clone(),
            offset,
        },
    });

    // Create and process update transaction
    let update_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[update_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let update_result = context
        .banks_client
        .process_transaction(update_transaction)
        .await;
    if let Err(error) = &update_result {
        println!("UpdateVerificationConfig transaction failed: {}", error);
        panic!("UpdateVerificationConfig transaction failed: {}", error);
    }

    println!("VerificationConfig updated successfully");

    // Verify the updated configuration
    let updated_config_account = context
        .banks_client
        .get_account(config_pda)
        .await
        .unwrap()
        .unwrap();

    let updated_config = VerificationConfig::try_from_slice(&updated_config_account.data)
        .expect("Should be able to deserialize updated VerificationConfig");

    // Verify the configuration was updated correctly
    assert_eq!(
        updated_config.instruction_discriminator, instruction_discriminator,
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

    println!("UpdateVerificationConfig validation successful");
    println!(
        "Final verification programs count: {}",
        updated_config.verification_programs.len()
    );

    println!("\nTesting TrimVerificationConfig");

    let original_recipient_balance = context
        .banks_client
        .get_account(context.payer.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    // Test Case 1: Trim the array from 3 programs to 2 programs (recover some rent)
    let new_size = 2u8;
    let close = false;

    let trim_config_ix = TrimVerificationConfig {
        config_account: config_pda,
        mint_account: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(TrimVerificationConfigInstructionArgs {
        args: TrimVerificationConfigArgs {
            instruction_discriminator,
            size: new_size,
            close,
        },
    });

    // Create and process trim transaction
    let trim_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[trim_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let trim_result = context
        .banks_client
        .process_transaction(trim_transaction)
        .await;
    if let Err(error) = &trim_result {
        println!("TrimVerificationConfig transaction failed: {}", error);
        panic!("TrimVerificationConfig transaction failed: {}", error);
    }

    println!("VerificationConfig trimmed successfully");

    // Verify the trimmed configuration
    let trimmed_config_account = context
        .banks_client
        .get_account(config_pda)
        .await
        .unwrap()
        .unwrap();

    let trimmed_config = VerificationConfig::try_from_slice(&trimmed_config_account.data)
        .expect("Should be able to deserialize trimmed VerificationConfig");

    // Verify the configuration was trimmed correctly
    assert_eq!(
        trimmed_config.instruction_discriminator, instruction_discriminator,
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

    let recovered_rent = new_recipient_balance - original_recipient_balance;
    println!("Recovered {} lamports from trimming", recovered_rent);

    println!("TrimVerificationConfig (resize) validation successful");

    // Test Case 2: Close the account completely
    println!("\nTesting TrimVerificationConfig with close=true");

    let close_config_ix = TrimVerificationConfig {
        config_account: config_pda,
        mint_account: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        system_program: solana_system_interface::program::ID,
    }
    .instruction(TrimVerificationConfigInstructionArgs {
        args: TrimVerificationConfigArgs {
            instruction_discriminator,
            size: 0,
            close: true,
        },
    });

    // Get config account balance before closing
    let config_balance_before_close = trimmed_config_account.lamports;

    let close_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[close_config_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let close_result = context
        .banks_client
        .process_transaction(close_transaction)
        .await;
    if let Err(error) = &close_result {
        println!("TrimVerificationConfig close transaction failed: {}", error);
        panic!("TrimVerificationConfig close transaction failed: {}", error);
    }

    println!("VerificationConfig closed successfully");

    // Verify the account was closed
    let closed_config_account = context.banks_client.get_account(config_pda).await.unwrap();

    if let Some(account) = closed_config_account {
        // Account exists but should have 0 lamports and 0 data
        assert_eq!(account.lamports, 0, "Closed account should have 0 lamports");
        assert_eq!(
            account.data.len(),
            0,
            "Closed account should have 0 data length"
        );
        println!("Config account closed - 0 lamports, 0 data length");
    } else {
        println!("Config account completely deleted");
    }

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

    println!("Total recovered rent: {} lamports", total_recovered_rent);
    println!("TrimVerificationConfig (close) validation successful");
}

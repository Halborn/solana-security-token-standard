//! Security Token Standard Integration Tests

use security_token_program::{
    instruction::{InitializeArgs, SecurityTokenInstruction},
    processor::Processor,
    state::{Rate, Receipt, SecurityTokenMint, VerificationConfig, VerificationStatus},
    utils,
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::signature::Signer;
use spl_pod::optional_keys::OptionalNonZeroPubkey;
use spl_token_2022::extension::permanent_delegate::PermanentDelegate;
use spl_token_2022::extension::transfer_hook::TransferHook;
use spl_token_metadata_interface::state::TokenMetadata;

fn create_initialize_mint_instruction(
    _program_id: Pubkey,
    decimals: u8,
    mint_authority: Pubkey,
    freeze_authority: Option<Pubkey>,
) -> Vec<u8> {
    let args = InitializeArgs::new(
        decimals,
        mint_authority,
        freeze_authority,
        None, // metadata_pointer
        None, // metadata
        None, // scaled_ui_amount
    );

    let mut instruction_data = vec![SecurityTokenInstruction::InitializeMint as u8];
    instruction_data.extend(args.pack());
    instruction_data
}

fn create_initialize_mint_with_metadata_instruction(
    program_id: Pubkey,
    decimals: u8,
    mint_pubkey: &Pubkey,
    creator_pubkey: &Pubkey,
    freeze_authority: Option<Pubkey>,
) -> Vec<u8> {
    use spl_pod::optional_keys::OptionalNonZeroPubkey;
    use spl_token_2022::extension::metadata_pointer::MetadataPointer;
    use spl_token_2022::extension::scaled_ui_amount::instruction::InitializeInstructionData as ScaledUiAmountInitialize;

    // Calculate the mint authority PDA that will be used by the program
    let (mint_authority_pda, _bump) =
        utils::find_mint_authority_pda(mint_pubkey, creator_pubkey, &program_id);

    // Create metadata pointer with the correct PDA
    let metadata_pointer = MetadataPointer {
        authority: OptionalNonZeroPubkey::try_from(Some(mint_authority_pda)).unwrap(),
        metadata_address: OptionalNonZeroPubkey::try_from(Some(*mint_pubkey)).unwrap(), // Point to mint address
    };

    // Create metadata
    let metadata = TokenMetadata {
        update_authority: OptionalNonZeroPubkey::try_from(Some(mint_authority_pda)).unwrap(),
        mint: *mint_pubkey, // Actual mint pubkey
        name: "Solana Security Token".to_string(),
        symbol: "HST".to_string(),
        uri: "https://example.com/tokens/hst".to_string(),
        additional_metadata: vec![
            ("type".to_string(), "security".to_string()),
            ("compliance".to_string(), "reg_d".to_string()),
            ("issuer".to_string(), "Hoodies Inc".to_string()),
            ("industry".to_string(), "blockchain".to_string()),
        ],
    };

    // Create scaled UI amount config (1.5x multiplier)
    let scaled_ui_amount = ScaledUiAmountInitialize {
        authority: OptionalNonZeroPubkey::try_from(Some(mint_authority_pda)).unwrap(),
        multiplier: 1.5f64.into(), // 1.5x multiplier
    };

    let args = InitializeArgs::new(
        decimals,
        *creator_pubkey, // Use creator as mint authority parameter (will be replaced by PDA in processor)
        freeze_authority,
        Some(metadata_pointer),
        Some(metadata),
        Some(scaled_ui_amount),
    );

    let mut instruction_data = vec![SecurityTokenInstruction::InitializeMint as u8];
    instruction_data.extend(args.pack());
    instruction_data
}

#[tokio::test]
async fn test_program_loads() {
    let program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "security_token_program",
        program_id,
        processor!(Processor::process),
    );

    let (_banks_client, _payer, _recent_blockhash) = program_test.start().await;

    // Basic test that program loads successfully
    println!("Security Token program loaded successfully");
}

#[tokio::test]
async fn test_initialize_mint_with_all_extensions() {
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "security_token_program",
        program_id,
        processor!(Processor::process),
    );

    // Create mint keypair - mint account must be a signer when creating new account
    let mint_keypair = solana_sdk::signature::Keypair::new();

    let payer = solana_sdk::signature::Keypair::new();
    program_test.add_account(
        payer.pubkey(),
        solana_sdk::account::Account {
            lamports: 1_000_000_000, // 1 SOL
            data: vec![],
            owner: solana_program::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (banks_client, _default_payer, recent_blockhash) = program_test.start().await;
    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    let instruction = Instruction::new_with_bytes(
        program_id,
        &create_initialize_mint_with_metadata_instruction(
            // Use full version with metadata
            program_id,
            6,
            &mint_keypair.pubkey(),
            &payer.pubkey(),
            None,
        ),
        vec![
            AccountMeta::new(mint_keypair.pubkey(), true), // 0. Mint account (must be signer)
            AccountMeta::new(payer.pubkey(), true), // 1. Creator (signer, mutable for funding)
            AccountMeta::new_readonly(spl_token_2022_program, false), // 2. SPL Token 2022 program
            AccountMeta::new_readonly(solana_program::system_program::ID, false), // 3. System program
            AccountMeta::new_readonly(solana_program::sysvar::rent::ID, false),   // 4. Rent sysvar
        ],
    );

    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer, &mint_keypair], // Both payer and mint must sign
        recent_blockhash,
    );

    // Process transaction
    let result = banks_client.process_transaction(transaction).await;

    if let Err(error) = &result {
        println!("Transaction failed with error: {:?}", error);
        panic!(
            "Initialize mint with all extensions should succeed, but got error: {:?}",
            error
        );
    }

    assert!(
        result.is_ok(),
        "Initialize mint with all extensions should succeed"
    );

    // Verify mint account was created correctly
    let mint_account = banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .unwrap();
    assert!(mint_account.is_some(), "Mint account should exist");

    let mint_account = mint_account.unwrap();
    assert_eq!(
        mint_account.owner, spl_token_2022_program,
        "Mint should be owned by Token-2022 program"
    );

    println!("Security Token Mint with ALL extensions created successfully!");
    println!("   Account size: {} bytes", mint_account.data.len());

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

    // Get expected PDAs
    let expected_mint_authority =
        utils::find_mint_authority_pda(&mint_keypair.pubkey(), &payer.pubkey(), &program_id).0;
    let expected_freeze_authority =
        utils::find_freeze_authority_pda(&mint_keypair.pubkey(), &program_id).0;
    let expected_permanent_delegate =
        utils::find_permanent_delegate_pda(&mint_keypair.pubkey(), &program_id).0;

    assert_eq!(
        mint_with_extensions.base.mint_authority.unwrap(),
        expected_mint_authority,
        "Mint authority should be the calculated PDA"
    );
    assert_eq!(
        mint_with_extensions.base.freeze_authority.unwrap(),
        expected_freeze_authority,
        "Freeze authority should be the calculated PDA"
    );

    println!("Basic mint properties verified");

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

    use spl_token_2022::extension::metadata_pointer::MetadataPointer;
    let metadata_pointer = mint_with_extensions
        .get_extension::<MetadataPointer>()
        .expect("MetadataPointer extension should be accessible");

    assert_eq!(
        Option::<Pubkey>::from(metadata_pointer.authority),
        Some(expected_mint_authority),
        "MetadataPointer authority should be our mint authority PDA"
    );
    assert_eq!(
        Option::<Pubkey>::from(metadata_pointer.metadata_address),
        Some(mint_keypair.pubkey()),
        "MetadataPointer should point to mint address"
    );
    println!("MetadataPointer extension verified");

    use spl_token_2022::extension::scaled_ui_amount::ScaledUiAmountConfig;
    let scaled_ui_amount = mint_with_extensions
        .get_extension::<ScaledUiAmountConfig>()
        .expect("ScaledUiAmount extension should be accessible");

    assert_eq!(
        Option::<Pubkey>::from(scaled_ui_amount.authority),
        Some(expected_mint_authority),
        "ScaledUiAmount authority should be our mint authority PDA"
    );
    assert_eq!(
        f64::from(scaled_ui_amount.multiplier),
        1.5f64,
        "ScaledUiAmount multiplier should be 1.5"
    );
    println!(
        "ScaledUiAmount extension verified: multiplier = {}x",
        f64::from(scaled_ui_amount.multiplier)
    );

    // TODO: Verify token metadata

    // Verify PermanentDelegate configuration
    let permanent_delegate = mint_with_extensions
        .get_extension::<PermanentDelegate>()
        .expect("PermanentDelegate extension should be accessible");

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

    let expected_transfer_hook_pda =
        utils::find_transfer_hook_pda(&mint_keypair.pubkey(), &program_id).0;

    assert_eq!(
        Option::<Pubkey>::from(transfer_hook.authority),
        Some(expected_mint_authority),
        "TransferHook authority should be our mint authority PDA"
    );
    assert_eq!(
        Option::<Pubkey>::from(transfer_hook.program_id),
        Some(expected_transfer_hook_pda),
        "TransferHook program should be our transfer hook PDA"
    );
}

#[tokio::test]
async fn test_initialize_mint_with_different_decimals() {
    let program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "security_token_program",
        program_id,
        processor!(Processor::process),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;
    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    // Test different decimal values
    for decimals in [0, 2, 6, 9, 18] {
        println!("\n Testing mint initialization with {} decimals", decimals);

        let mint_keypair = solana_sdk::signature::Keypair::new();

        let instruction = Instruction::new_with_bytes(
            program_id,
            &create_initialize_mint_instruction(program_id, decimals, payer.pubkey(), None),
            vec![
                AccountMeta::new(mint_keypair.pubkey(), true),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(spl_token_2022_program, false),
                AccountMeta::new_readonly(solana_program::system_program::ID, false),
                AccountMeta::new_readonly(solana_program::sysvar::rent::ID, false),
            ],
        );

        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer, &mint_keypair],
            recent_blockhash,
        );

        let result = banks_client.process_transaction(transaction).await;
        assert!(
            result.is_ok(),
            "Initialize mint with {} decimals should succeed",
            decimals
        );

        // Verify the mint was created with correct decimals
        let mint_account = banks_client
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

        // Security token mints with metadata should auto-expand to include metadata
        // Expected: ~435 bytes (base + extensions) initially, then auto-expand for metadata
        println!(
            "Actual mint account size: {} bytes",
            mint_account.data.len()
        );

        println!("{} decimals: verified successfully", decimals);
    }
}

#[tokio::test]
async fn test_initialize_mint_error_cases() {
    let program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "security_token_program",
        program_id,
        processor!(Processor::process),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;
    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    // Test Case 1: Mint account not a signer
    {
        println!("\n Testing error case: mint account not a signer");
        let mint_keypair = solana_sdk::signature::Keypair::new();

        let instruction = Instruction::new_with_bytes(
            program_id,
            &create_initialize_mint_instruction(program_id, 9, payer.pubkey(), None),
            vec![
                AccountMeta::new(mint_keypair.pubkey(), false), // mint not signer!
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(spl_token_2022_program, false),
                AccountMeta::new_readonly(solana_program::system_program::ID, false),
                AccountMeta::new_readonly(solana_program::sysvar::rent::ID, false),
            ],
        );

        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );

        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err(), "Should fail when mint is not a signer");
        println!("Correctly rejected mint account not being signer");
    }

    // Test Case 2: Creator not a signer
    {
        println!("\nTesting error case: creator not a signer");
        let mint_keypair = solana_sdk::signature::Keypair::new();
        let fake_creator = solana_sdk::signature::Keypair::new();

        let instruction = Instruction::new_with_bytes(
            program_id,
            &create_initialize_mint_instruction(program_id, 9, fake_creator.pubkey(), None),
            vec![
                AccountMeta::new(mint_keypair.pubkey(), true),
                AccountMeta::new_readonly(fake_creator.pubkey(), false), // creator not signer!
                AccountMeta::new_readonly(spl_token_2022_program, false),
                AccountMeta::new_readonly(solana_program::system_program::ID, false),
                AccountMeta::new_readonly(solana_program::sysvar::rent::ID, false),
            ],
        );

        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer, &mint_keypair],
            recent_blockhash,
        );

        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err(), "Should fail when creator is not a signer");
        println!("Correctly rejected creator not being signer");
    }
}

#[test]
fn test_state_structure_sizes() {
    // Verify all state structure sizes are reasonable for on-chain storage
    let mint_size = std::mem::size_of::<SecurityTokenMint>();
    let verification_config_size = std::mem::size_of::<VerificationConfig>();
    let verification_status_size = std::mem::size_of::<VerificationStatus>();
    let rate_size = std::mem::size_of::<Rate>();
    let receipt_size = std::mem::size_of::<Receipt>();

    println!("SecurityTokenMint size: {} bytes", mint_size);
    println!(
        "VerificationConfig size: {} bytes",
        verification_config_size
    );
    println!(
        "VerificationStatus size: {} bytes",
        verification_status_size
    );
    println!("Rate size: {} bytes", rate_size);
    println!("Receipt size: {} bytes", receipt_size);

    // All structures should be reasonable for on-chain storage
    assert!(mint_size <= 512, "SecurityTokenMint should be <= 512 bytes");
    assert!(
        verification_config_size <= 256,
        "VerificationConfig should be <= 256 bytes"
    );
    assert!(
        verification_status_size <= 256,
        "VerificationStatus should be <= 256 bytes"
    );
    assert!(rate_size <= 64, "Rate should be <= 64 bytes");
    assert!(receipt_size <= 128, "Receipt should be <= 128 bytes");
}

#[test]
fn test_verification_structures_defaults() {
    let config = VerificationConfig::default();
    // Test that all verification programs are None by default
    for program in config.verification_programs.iter() {
        assert_eq!(*program, OptionalNonZeroPubkey::default());
    }
    // Copy values to avoid packed field references
    let discriminator = config.instruction_discriminator;
    let flags = config.flags;
    assert_eq!(discriminator, [0; 8]);
    assert_eq!(flags, 0);

    let status = VerificationStatus::default();
    // Copy values to avoid packed field references
    let kyc_timestamp = status.kyc_timestamp;
    let aml_timestamp = status.aml_timestamp;
    let is_whitelisted = status.is_whitelisted;

    assert_eq!(kyc_timestamp, 0);
    assert_eq!(aml_timestamp, 0);
    assert_eq!(is_whitelisted, 0);
}

#[test]
fn test_corporate_actions_structures() {
    // Test Rate structure
    let rate = Rate {
        numerator: 3,
        denominator: 2,
        rounding: 0,
        _reserved: [0; 7],
    };
    // Copy values to avoid packed field references
    let numerator = rate.numerator;
    let denominator = rate.denominator;
    assert_eq!(numerator, 3);
    assert_eq!(denominator, 2);

    // Test Receipt structure
    let receipt = Receipt {
        action_id: 12345,
        account: solana_program::pubkey::Pubkey::new_unique(),
        amount: 1000,
        timestamp: 1640995200, // Jan 1, 2022
        _reserved: [0; 8],
    };
    // Copy values to avoid packed field references
    let action_id = receipt.action_id;
    let amount = receipt.amount;
    assert_eq!(action_id, 12345);
    assert_eq!(amount, 1000);
}

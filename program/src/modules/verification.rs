//! Verification Module
//!
//! Handles authorization checks, compliance verification, and instruction validation
//! according to the Security Token specification.

use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use pinocchio::ProgramResult;
use pinocchio::{
    msg,
    sysvars::rent::{
        Rent, DEFAULT_BURN_PERCENT, DEFAULT_EXEMPTION_THRESHOLD, DEFAULT_LAMPORTS_PER_BYTE_YEAR,
    },
};
use pinocchio_log::log;
use pinocchio_system::instructions::{CreateAccount, Transfer};
use pinocchio_token_2022::extensions::metadata_pointer::{
    Initialize as MetadataPointerInitialize, MetadataPointer,
};
use pinocchio_token_2022::extensions::pausable::InitializePausable;
use pinocchio_token_2022::extensions::permanent_delegate::InitializePermanentDelegate;
use pinocchio_token_2022::extensions::scaled_ui_amount::Initialize as ScaledUiAmountInitialize;
use pinocchio_token_2022::extensions::transfer_hook::Initialize as TransferHookInitialize;
use pinocchio_token_2022::extensions::{
    get_extension_data_bytes_for_variable_pack, get_extension_from_bytes, ExtensionType,
};
use pinocchio_token_2022::instructions::{InitializeMint2, SetAuthority};
use pinocchio_token_2022::state::Mint;
use pinocchio_token_2022::{
    extensions::metadata::{Field, TokenMetadata, UpdateField},
    instructions::AuthorityType,
};

use crate::instruction::SecurityTokenInstruction;
use crate::instructions::token_wrappers::{CustomInitializeTokenMetadata, CustomRemoveKey};
use crate::instructions::verification_config::TrimVerificationConfigArgs;
use crate::instructions::{InitializeArgs, UpdateMetadataArgs};
use crate::modules::verify_signer;
use crate::state::VerificationConfig;
use crate::utils;
use borsh::{BorshDeserialize, BorshSerialize};

/// Verification Module - handles all authorization and compliance checks
pub struct VerificationModule;

impl VerificationModule {
    /// Initialize mint with all extensions and metadata
    /// Creates initial configuration of the verification module  
    pub fn initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &InitializeArgs,
    ) -> ProgramResult {
        log!("Processing InitializeMint with Token-2022 extensions");

        let decimals = args.ix_mint.decimals;
        let client_mint_authority = args.ix_mint.mint_authority;
        let freeze_authority_opt = args.ix_mint.freeze_authority;
        let metadata_pointer_opt = &args.ix_metadata_pointer;
        let metadata_opt = &args.ix_metadata;
        let scaled_ui_amount_opt = &args.ix_scaled_ui_amount;
        log!("Initializing mint with {} decimals", decimals);

        if let Some(metadata) = &metadata_opt {
            log!("Token name: {}", metadata.name);
            log!("Token symbol: {}", metadata.symbol);
            log!("Token URI: {}", metadata.uri);
            log!(
                "With metadata: {} ({}) - {}",
                metadata.name,
                metadata.symbol,
                metadata.uri
            );
        }
        if let Some(_metadata_pointer) = &metadata_pointer_opt {
            log!("MetadataPointer configuration provided by client");
        }
        if let Some(_scaled_ui_amount) = &scaled_ui_amount_opt {
            log!("ScaledUiAmount configuration provided by client");
        }

        let [mint_info, creator_info, token_program_info, _system_program_info, rent_info] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_signer(creator_info, false)?;
        verify_signer(mint_info, false)?;

        let mut extensions_buf: [ExtensionType; 5] = [ExtensionType::Pausable; 5];
        let mut ext_count: usize = 0;
        let required_extensions: &[ExtensionType] = &[
            ExtensionType::PermanentDelegate,
            ExtensionType::TransferHook,
            ExtensionType::Pausable,
        ];
        for &ext in required_extensions {
            extensions_buf[ext_count] = ext;
            ext_count += 1;
        }

        // Add MetadataPointer if metadata is provided
        if metadata_opt.is_some() || metadata_pointer_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::MetadataPointer;
            ext_count += 1;
            log!("MetadataPointer extension will be initialized");
        }

        // Add ScaledUiAmount if provided by client
        if scaled_ui_amount_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::ScaledUiAmount;
            ext_count += 1;
            log!("ScaledUiAmount extension will be initialized");
        }

        log!("Extensions for mint: {}", ext_count);

        // Calculate mint size with extensions (but without metadata TLV data)
        let mint_size = if ext_count == 0 {
            Mint::LEN
        } else {
            utils::calculate_mint_size_with_extensions(&extensions_buf[..ext_count])
        };

        let metadata_size = if let Some(metadata) = &metadata_opt {
            utils::calculate_metadata_tlv_size(metadata)?
        } else {
            0
        };

        log!("Mint size: {} bytes", mint_size);
        log!("Metadata size: {} bytes", metadata_size);
        log!("Total account size: {} bytes", mint_size + metadata_size);

        let total_size = mint_size + metadata_size;

        let rent = Rent::from_account_info(rent_info)?;
        let required_lamports = rent.minimum_balance(total_size);

        log!(
            "Creating mint account with {} lamports for {} bytes",
            required_lamports,
            total_size
        );

        let create_account_instruction = CreateAccount {
            from: creator_info,              // from (payer)
            to: mint_info,                   // to (new account)
            lamports: required_lamports,     // amount
            space: mint_size as u64,         // space (full size including metadata)
            owner: token_program_info.key(), // owner (SPL Token 2022 program)
        };

        create_account_instruction.invoke()?;

        msg!("Mint account created successfully");

        // Calculate all PDAs that will be used for extensions and mint initialization
        let (transfer_hook_pda, _bump) = utils::find_transfer_hook_pda(mint_info.key(), program_id);
        let (permanent_delegate_pda, _bump) =
            utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        let (freeze_authority_pda, _bump) =
            utils::find_freeze_authority_pda(mint_info.key(), program_id);

        // Initialize extensions BEFORE base mint initialization
        msg!("Extensions setup - initializing extensions BEFORE basic mint");

        let permanent_delegate_initialize = InitializePermanentDelegate {
            mint: mint_info,
            delegate: permanent_delegate_pda,
        };

        permanent_delegate_initialize.invoke()?;

        let transfer_hook_initialize = TransferHookInitialize {
            mint: mint_info,
            authority: transfer_hook_pda.into(),
            program_id: Some(*program_id),
        };

        transfer_hook_initialize.invoke()?;

        let pausable_initialize = InitializePausable {
            mint: mint_info,
            authority: freeze_authority_pda,
        };

        pausable_initialize.invoke()?;

        // Initialize MetadataPointer extension if needed and store metadata address for later use
        let metadata_account_address = if metadata_opt.is_some() || metadata_pointer_opt.is_some() {
            let (metadata_authority, metadata_address) =
                if let Some(client_metadata_pointer) = &metadata_pointer_opt {
                    // Use client-provided MetadataPointer configuration
                    msg!("Using client-provided MetadataPointer configuration");
                    let authority = client_metadata_pointer.authority.into();
                    let address = client_metadata_pointer.metadata_address.into();
                    (authority, address)
                } else {
                    // Fallback to default: creator as authority, mint as metadata storage
                    log!("Using default MetadataPointer configuration");
                    (Some(*creator_info.key()), Some(*mint_info.key()))
                };

            let metadata_pointer_initialize = MetadataPointerInitialize {
                mint: mint_info,
                authority: metadata_authority,
                metadata_address,
            };

            metadata_pointer_initialize.invoke()?;
            log!("MetadataPointer extension initialized");

            // Return the metadata address for later use
            metadata_address
        } else {
            None
        };

        // Initialize ScaledUiAmount extension if provided by client
        if let Some(scaled_ui_amount_config) = &scaled_ui_amount_opt {
            msg!("Initializing ScaledUiAmount extension with client configuration");

            let scaled_ui_amount_initialize = ScaledUiAmountInitialize {
                mint: mint_info,
                authority: scaled_ui_amount_config.authority.into(),
                multiplier: f64::from_le_bytes(scaled_ui_amount_config.multiplier),
            };

            scaled_ui_amount_initialize.invoke()?;
            log!("ScaledUiAmount extension initialized");
        }

        log!("All security token extensions initialized successfully");

        // Now initialize the basic mint AFTER extensions
        log!("Initializing basic mint AFTER extensions");

        // Use client-provided authorities for base initialize to match client expectations/tests
        let initialize_mint_instruction = InitializeMint2 {
            mint: mint_info,
            decimals,
            mint_authority: &client_mint_authority,
            freeze_authority: freeze_authority_opt.as_ref(),
        };

        initialize_mint_instruction.invoke()?;

        log!(
            "Basic mint initialized successfully with {} decimals",
            decimals
        );

        if let Some(metadata) = &metadata_opt {
            msg!("Preparing to initialize token metadata through SPL Token Metadata Interface");

            // Determine which account to use for metadata
            let metadata_account_info = if let Some(metadata_addr) = metadata_account_address {
                if metadata_addr == *mint_info.key() {
                    // Metadata is stored in mint account (in-mint storage)
                    log!("Using mint account for metadata");
                    mint_info.clone()
                } else {
                    // Metadata is stored in external account - find it in accounts list
                    accounts
                        .iter()
                        .find(|acc| acc.key() == &metadata_addr)
                        .ok_or_else(|| {
                            msg!("Metadata account {metadata_addr} not found in accounts list");
                            ProgramError::InvalidAccountData
                        })?
                        .clone()
                }
            } else {
                // No metadata pointer, shouldn't happen if we have metadata
                return Err(ProgramError::InvalidInstructionData);
            };

            msg!("Initializing token metadata");
            let metadata_init_instruction = CustomInitializeTokenMetadata::new(
                &metadata_account_info,
                creator_info,
                mint_info,
                creator_info,
                metadata.name,
                metadata.symbol,
                metadata.uri,
            );
            let invoke_result = metadata_init_instruction.invoke();

            if let Err(err) = &invoke_result {
                let err_str = format!("{:?}", err);
                log!(
                    "CustomInitializeTokenMetadata invoke failed with error: {}",
                    err_str.as_str()
                );
                return Err(err.clone());
            }

            log!("TokenMetadata invoke succeeded");
            // Add additional metadata fields if present - each field requires separate instruction
            if !metadata.additional_metadata.is_empty() {
                let additional_metadata_len = metadata.additional_metadata.len();
                log!(
                    "Adding {} bytes of additional metadata",
                    additional_metadata_len
                );

                // Parse additional metadata from raw bytes and process each field
                utils::parse_additional_metadata(metadata.additional_metadata, |key, value| {
                    let update_field_instruction = UpdateField {
                        metadata: &metadata_account_info,
                        update_authority: creator_info,
                        field: Field::Key(key),
                        value,
                    };
                    update_field_instruction.invoke()?;
                    Ok(())
                })?;
            }
            msg!("All metadata initialized successfully");
        } else {
            msg!("No metadata provided, skipping metadata initialization");
        }

        // NOTE: Transfer mint authority to PDA, review it
        // Get mint authority PDA - this will be the mint authority for the token
        let (mint_authority_pda, _mint_authority_bump) =
            utils::find_mint_authority_pda(mint_info.key(), creator_info.key(), program_id);

        let set_authority_instruction = SetAuthority {
            account: mint_info,
            authority: creator_info,
            authority_type: AuthorityType::MintTokens,
            new_authority: Some(&mint_authority_pda),
        };

        set_authority_instruction.invoke()?;
        msg!("Security token mint initialization completed successfully");
        Ok(())
    }

    /// Update metadata for existing mint
    /// Wrapper for Metadata token program extension
    pub fn update_metadata(
        _program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &UpdateMetadataArgs,
    ) -> ProgramResult {
        log!("Processing UpdateMetadata instruction");

        // Validate arguments
        args.validate()?;

        let [mint_info, authority_info, _token_program_info, _system_program_info] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_signer(authority_info, false)?;

        // Get metadata account address from MetadataPointer extension
        let metadata_address: Option<Pubkey> = {
            let mint_data = mint_info.try_borrow_data()?;

            // Use pinocchio's get_extension_from_bytes instead of StateWithExtensions
            let metadata_pointer = get_extension_from_bytes::<MetadataPointer>(&mint_data)
                .ok_or(ProgramError::InvalidAccountData)?;

            metadata_pointer.metadata_address.into()
        }; // Borrow is released here
        let metadata_address = metadata_address.ok_or(ProgramError::InvalidAccountData)?;

        // Determine metadata account (could be mint itself or external account)
        let metadata_account_info = if metadata_address == *mint_info.key() {
            // Metadata is stored in mint account (in-mint storage)
            mint_info.clone()
        } else {
            // Metadata is stored in external account - would need to be passed in accounts
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Update base metadata fields using SPL Token Metadata Interface
        log!("Updating base metadata fields (name, symbol, URI)");

        // Calculate additional space needed for metadata updates and transfer rent if needed

        log!("Calculating additional rent for metadata updates");

        // Calculate current and new metadata sizes
        let new_metadata_size = utils::calculate_metadata_tlv_size(&args.metadata)?;
        let current_account_size = metadata_account_info.data_len();

        log!("Current account size: {} bytes", current_account_size);
        log!("New metadata TLV size needed: {} bytes", new_metadata_size);

        // Get current metadata size to calculate the difference
        let current_metadata_size = {
            let mint_data = metadata_account_info.try_borrow_data()?;

            // Use pinocchio's get_extension_data_bytes_for_variable_pack to get current metadata
            if let Some(metadata_bytes) =
                get_extension_data_bytes_for_variable_pack::<TokenMetadata>(&mint_data)
            {
                // The length of the raw extension data includes TLV headers
                // For simplification, use the raw byte length as the current size
                metadata_bytes.len() + 4 // Add 4 bytes for TLV header (type + length)
            } else {
                // No metadata currently, so current size is 0
                0
            }
        };

        log!("Current metadata TLV size: {} bytes", current_metadata_size);

        if new_metadata_size > current_metadata_size {
            let additional_metadata_space = new_metadata_size - current_metadata_size;
            let rent = Rent {
                lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
                exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
                burn_percent: DEFAULT_BURN_PERCENT,
            };
            let additional_rent = rent.minimum_balance(additional_metadata_space);

            log!(
                "Additional metadata space needed: {} bytes",
                additional_metadata_space
            );
            log!("Additional rent needed: {} lamports", additional_rent);

            let transfer = Transfer {
                from: authority_info,       // from (authority pays)
                to: &metadata_account_info, // to (metadata account)
                lamports: additional_rent,  // amount
            };

            transfer.invoke()?;

            log!(
                "Transferred {} lamports for additional metadata space",
                additional_rent
            );
        } else {
            log!("No additional rent needed - current metadata space is sufficient");
        }

        let update_field_instruction = UpdateField {
            metadata: &metadata_account_info,
            update_authority: authority_info,
            field: Field::Name,
            value: args.metadata.name,
        };

        update_field_instruction.invoke()?;

        // Update symbol
        let update_symbol_instruction = UpdateField {
            metadata: &metadata_account_info,
            update_authority: authority_info,
            field: Field::Symbol,
            value: args.metadata.symbol,
        };

        update_symbol_instruction.invoke()?;

        // Update URI
        let update_uri_instruction = UpdateField {
            metadata: &metadata_account_info,
            update_authority: authority_info,
            field: Field::Uri,
            value: args.metadata.uri,
        };

        update_uri_instruction.invoke()?;

        log!("Name updated to: {}", args.metadata.name);
        log!("Symbol updated to: {}", args.metadata.symbol);
        log!("URI updated to: {}", args.metadata.uri);

        // Handle additional metadata fields atomically
        // Step 1: Read all existing additional metadata fields and remove them
        // Step 2: Add new additional metadata fields
        log!("Processing additional metadata fields atomically");

        // Step 1: Read current metadata to get all existing additional fields
        log!("Reading existing metadata to find all additional fields");

        let existing_additional_fields = {
            // Create a temporary AccountInfo wrapper for the metadata account to use from_account_info
            let metadata_account_clone = metadata_account_info.clone();

            // Try to parse existing metadata using pinocchio's from_account_info
            if let Ok(existing_metadata) = TokenMetadata::from_account_info(metadata_account_clone)
            {
                log!("Successfully parsed existing metadata");

                let mut fields_buffer: [[u8; 64]; 16] = [[0u8; 64]; 16]; // Static buffer for field names
                let mut field_lengths: [usize; 16] = [0; 16];
                let mut field_count = 0;

                // Parse existing additional metadata to extract all field keys
                let parse_result = utils::parse_additional_metadata(
                    existing_metadata.additional_metadata,
                    |key, _value| {
                        if field_count < 16 && key.len() <= 64 {
                            // Copy key bytes to static buffer
                            let key_bytes = key.as_bytes();
                            fields_buffer[field_count][..key_bytes.len()]
                                .copy_from_slice(key_bytes);
                            field_lengths[field_count] = key_bytes.len();
                            field_count += 1;
                            log!("Found existing additional metadata field: {}", key);
                        } else {
                            log!("Skipping field (buffer full or key too long): {}", key);
                        }
                        Ok(())
                    },
                );

                if parse_result.is_err() {
                    log!("Warning: Failed to parse existing additional metadata");
                    field_count = 0; // Reset to 0 if parsing failed
                }

                (fields_buffer, field_lengths, field_count)
            } else {
                log!("No existing metadata found or failed to parse - assuming no existing additional fields");
                let fields_buffer: [[u8; 64]; 16] = [[0u8; 64]; 16];
                let field_lengths: [usize; 16] = [0; 16];
                let field_count = 0;
                (fields_buffer, field_lengths, field_count)
            }
        };

        let (fields_buffer, field_lengths, field_count) = existing_additional_fields;

        // Step 2: Remove only existing fields that are NOT in the new metadata
        if field_count > 0 {
            log!("Checking {} existing fields for removal", field_count);

            for i in 0..field_count {
                let key_bytes = &fields_buffer[i][..field_lengths[i]];
                if let Ok(existing_key) = core::str::from_utf8(key_bytes) {
                    // Check if this existing field is in the new metadata by parsing new metadata
                    let mut found_in_new = false;

                    if !args.metadata.additional_metadata.is_empty() {
                        let _check_result = utils::parse_additional_metadata(
                            args.metadata.additional_metadata,
                            |new_key, _value| {
                                if existing_key == new_key {
                                    found_in_new = true;
                                }
                                Ok(())
                            },
                        );
                    }

                    if !found_in_new {
                        log!(
                            "Removing existing metadata field not in update: {}",
                            existing_key
                        );
                        let remove_field_instruction = CustomRemoveKey::new(
                            &metadata_account_info,
                            authority_info,
                            existing_key,
                            true, // idempotent - don't error if key doesn't exist
                        );

                        let remove_result = remove_field_instruction.invoke();
                        if remove_result.is_ok() {
                            log!("Removed existing metadata field: {}", existing_key);
                        }
                        // Ignore errors since we're using idempotent flag
                    } else {
                        log!(
                            "Keeping existing metadata field (will be updated): {}",
                            existing_key
                        );
                    }
                }
            }
        } else {
            log!("No existing additional metadata fields found to check");
        }

        // Step 4: Add/update new additional metadata fields
        if !args.metadata.additional_metadata.is_empty() {
            let additional_metadata_len = args.metadata.additional_metadata.len();
            log!(
                "Adding/updating {} bytes of new additional metadata",
                additional_metadata_len
            );

            let result = utils::parse_additional_metadata(
                args.metadata.additional_metadata,
                |key, value| {
                    log!(
                        "Adding/updating additional metadata field: {} = {}",
                        key,
                        value
                    );
                    let update_field_instruction = UpdateField {
                        metadata: &metadata_account_info,
                        update_authority: authority_info,
                        field: Field::Key(key),
                        value,
                    };
                    update_field_instruction.invoke()
                },
            );

            result.map_err(|_e| ProgramError::InvalidInstructionData)?;
            log!("All additional metadata fields added/updated successfully");
        } else {
            log!("No new additional metadata fields to add/update");
        }

        log!(
            "Metadata updated successfully for mint: {}",
            mint_info.key()
        );
        Ok(())
    }

    /// Verify authorization for Security Token instructions
    ///
    /// Supports two modes:
    /// - Instruction Introspection Mode: reads prior instructions in transaction
    /// - CPI Mode: executes CPIs to verification programs
    pub fn verify_authorization(
        _accounts: &[AccountInfo],
        _instruction: &SecurityTokenInstruction,
    ) -> ProgramResult {
        // TODO: Load VerificationConfig account if exists
        // TODO: Check if custom verification workflow is configured
        // TODO: If configured, execute verification flow
        // TODO: If not configured, use standard authorization (creator signature)

        // Placeholder implementation
        Ok(())
    }

    /// Initialize verification configuration for an instruction
    ///
    /// Creates a VerificationConfig PDA for a specific instruction type.
    /// Each instruction (burn, transfer, mint, etc.) gets its own config.
    pub fn initialize_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &crate::instructions::InitializeVerificationConfigArgs,
    ) -> ProgramResult {
        // Expected accounts:
        // 0. [writable] VerificationConfig PDA (derived from instruction_id + mint)
        // 1. [writable, signer] Payer (for account creation)
        // 2. [] Mint account
        // 3. [signer] Authority (mint authority or designated config authority)
        // 4. [] System program

        let [config_account, payer, mint_account, authority, _system_program] = &accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_signer(payer, false)?;
        verify_signer(authority, false)?;

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        // Derive expected PDA address
        let (expected_config_pda, bump) =
            utils::find_verification_config_pda(mint_account.key(), discriminator, program_id);

        // Verify that the provided config account matches the expected PDA
        if *config_account.key() != expected_config_pda {
            log!("Invalid config account");
            return Err(ProgramError::InvalidAccountData);
        }

        // Check if account already exists
        if config_account.data_len() > 0 {
            log!("VerificationConfig account already exists");
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // Create the VerificationConfig data first to calculate exact size
        let config = VerificationConfig::new(discriminator, args.program_addresses())?;

        let account_size = config.serialized_size();

        // Calculate rent for the account
        let rent = Rent {
            lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
            exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
            burn_percent: DEFAULT_BURN_PERCENT,
        };
        let required_lamports = rent.minimum_balance(account_size);

        // Create the PDA account
        let create_account_instruction = CreateAccount {
            from: payer,
            to: config_account,
            lamports: required_lamports,
            space: account_size as u64,
            owner: program_id,
        };

        // Create seeds for PDA signing
        let bump_seed = [bump];
        let discriminator_seed = [discriminator];
        let seeds = [
            Seed::from(utils::seeds::VERIFICATION_CONFIG),
            Seed::from(mint_account.key().as_ref()),
            Seed::from(discriminator_seed.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let signer = Signer::from(&seeds);

        create_account_instruction.invoke_signed(&[signer])?;

        // Write data to the account using Borsh serialization
        let mut data = config_account.try_borrow_mut_data()?;
        let config_bytes = config
            .try_to_vec()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        data[..config_bytes.len()].copy_from_slice(&config_bytes);

        log!(
            "VerificationConfig PDA created for {} programs",
            args.program_count()
        );
        log!("Config PDA address: {}", config_account.key());
        log!("Mint: {}", mint_account.key());
        log!("Authority: {}", authority.key());

        Ok(())
    }

    /// Update verification configuration for an instruction
    pub fn update_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &crate::instructions::UpdateVerificationConfigArgs,
    ) -> ProgramResult {
        // Expected accounts:
        // 0. [writable] VerificationConfig PDA account
        // 1. [] Mint account
        // 2. [signer] Authority (mint authority or designated config authority)
        // 3. [] System program (if resizing is needed)
        let [config_account, mint_account, authority, _system_program_info] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_signer(authority, false)?;
        // TODO: Add proper authority validation
        // For now, we accept any signer as authority
        // In production, should validate against mint authority or config-specific authority

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        // Derive expected PDA address
        let (expected_config_pda, _bump) =
            utils::find_verification_config_pda(mint_account.key(), discriminator, program_id);

        // Verify that the provided config account matches the expected PDA
        if *config_account.key() != expected_config_pda {
            log!("Invalid config account");
            return Err(ProgramError::InvalidAccountData);
        }

        // Check if account exists
        if config_account.data_len() == 0 {
            log!("VerificationConfig account does not exist");
            return Err(ProgramError::UninitializedAccount);
        }

        // Load existing config
        let mut existing_config = {
            let data = config_account.try_borrow_data()?;
            VerificationConfig::try_from_slice(&data)
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Verify discriminator matches
        if existing_config.instruction_discriminator != discriminator {
            log!("Discriminator mismatch");
            return Err(ProgramError::InvalidAccountData);
        }

        // Update verification programs starting at the specified offset
        let offset = args.offset() as usize;
        let new_programs = args.program_addresses();

        if offset + new_programs.len() > existing_config.verification_programs.len() {
            existing_config
                .verification_programs
                .resize(offset + new_programs.len(), Pubkey::default());
        }

        // Replace programs starting at offset
        for (i, &new_program) in new_programs.iter().enumerate() {
            existing_config.verification_programs[offset + i] = new_program;
        }

        existing_config.validate()?;

        let new_size = existing_config.serialized_size();
        let current_size = config_account.data_len();

        if new_size > current_size {
            let additional_space = new_size - current_size;
            let rent = Rent {
                lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
                exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
                burn_percent: DEFAULT_BURN_PERCENT,
            };
            let additional_rent = rent.minimum_balance(additional_space);

            log!(
                "Expanding account from {} to {} bytes",
                current_size,
                new_size
            );
            log!("Additional rent needed: {} lamports", additional_rent);

            let transfer = Transfer {
                from: authority,
                to: config_account,
                lamports: additional_rent,
            };
            transfer.invoke()?;
            config_account.realloc(new_size, false)?;
        }

        let config_bytes = existing_config
            .try_to_vec()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        {
            let mut data = config_account.try_borrow_mut_data()?;
            data[..config_bytes.len()].copy_from_slice(&config_bytes);
        }

        log!(
            "VerificationConfig updated: {} programs at offset {}",
            new_programs.len(),
            offset
        );
        Ok(())
    }

    /// Trim verification configuration to recover rent
    pub fn trim_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &TrimVerificationConfigArgs,
    ) -> ProgramResult {
        // Expected accounts:
        // 0. [writable] VerificationConfig PDA account
        // 1. [] Mint account
        // 2. [signer] Authority (mint authority or designated config authority)
        // 3. [writable] Rent recipient account (to receive recovered lamports)
        // 4. [] System program ID (optional for closing account)

        let [config_account, mint_account, authority, rent_recipient, _system_program] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_signer(authority, false)?;
        // TODO: Add proper authority validation
        // For now, we accept any signer as authority
        // In production, should validate against mint authority or config-specific authority

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        // Derive expected PDA address
        let (expected_config_pda, _bump) =
            utils::find_verification_config_pda(mint_account.key(), discriminator, program_id);

        // Verify that the provided config account matches the expected PDA
        if *config_account.key() != expected_config_pda {
            log!("Invalid config account");
            return Err(ProgramError::InvalidAccountData);
        }

        // Check if account exists
        if config_account.data_len() == 0 {
            log!("VerificationConfig account does not exist");
            return Err(ProgramError::UninitializedAccount);
        }

        // Load existing config
        let mut existing_config = {
            let data = config_account.try_borrow_data()?;
            VerificationConfig::try_from_slice(&data)
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Verify discriminator matches
        if existing_config.instruction_discriminator != discriminator {
            log!("Discriminator mismatch");
            return Err(ProgramError::InvalidAccountData);
        }

        let current_program_count = existing_config.verification_programs.len();
        let new_size = args.size as usize;

        // Validate new size
        if new_size > current_program_count {
            log!("Cannot trim to a larger size");
            return Err(ProgramError::InvalidArgument);
        }

        if args.close {
            // Close the account completely - transfer all lamports to recipient
            log!("Closing VerificationConfig account completely");

            let config_lamports = config_account.lamports();

            // Transfer all lamports to recipient
            *config_account.try_borrow_mut_lamports()? = 0;
            *rent_recipient.try_borrow_mut_lamports()? = rent_recipient
                .lamports()
                .checked_add(config_lamports)
                .ok_or(ProgramError::InsufficientFunds)?;

            // Clear account data
            config_account.realloc(0, false)?;

            log!("Account closed, recovered {} lamports", config_lamports);
        } else if new_size < current_program_count {
            // Trim the array and resize account
            log!(
                "Trimming VerificationConfig from {} to {} programs",
                current_program_count,
                new_size
            );

            // Trim the verification programs array
            existing_config.verification_programs.truncate(new_size);

            // Validate the trimmed configuration
            existing_config.validate()?;

            // Calculate new account size
            let new_account_size = existing_config.serialized_size();
            let current_account_size = config_account.data_len();

            if new_account_size < current_account_size {
                // Calculate recovered rent
                let space_recovered = current_account_size - new_account_size;
                let rent = Rent {
                    lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
                    exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
                    burn_percent: DEFAULT_BURN_PERCENT,
                };
                let recovered_rent = rent.minimum_balance(space_recovered);

                log!("Recovering {} bytes of space", space_recovered);
                log!("Recovered rent: {} lamports", recovered_rent);

                // Transfer recovered rent to recipient
                *config_account.try_borrow_mut_lamports()? = config_account
                    .lamports()
                    .checked_sub(recovered_rent)
                    .ok_or(ProgramError::InsufficientFunds)?;

                *rent_recipient.try_borrow_mut_lamports()? = rent_recipient
                    .lamports()
                    .checked_add(recovered_rent)
                    .ok_or(ProgramError::InsufficientFunds)?;

                // Resize account to new size
                config_account.realloc(new_account_size, false)?;
            }

            // Write the trimmed config back to the account
            let config_bytes = existing_config
                .try_to_vec()
                .map_err(|_| ProgramError::InvalidAccountData)?;

            {
                let mut data = config_account.try_borrow_mut_data()?;
                data[..config_bytes.len()].copy_from_slice(&config_bytes);
            } // data borrow is released here

            log!(
                "VerificationConfig trimmed to {} programs, recovered {} lamports",
                new_size,
                if new_account_size < current_account_size {
                    let space_recovered = current_account_size - new_account_size;
                    let rent = Rent {
                        lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
                        exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
                        burn_percent: DEFAULT_BURN_PERCENT,
                    };
                    rent.minimum_balance(space_recovered)
                } else {
                    0
                }
            );
        } else {
            log!("No trimming needed - current size equals requested size");
        }

        Ok(())
    }
}

/// Verify specific operation against configured verification programs
pub fn verify(_accounts: &[AccountInfo], _instruction: &SecurityTokenInstruction) -> ProgramResult {
    // Main verification entry point
    VerificationModule::verify_authorization(_accounts, _instruction)
}

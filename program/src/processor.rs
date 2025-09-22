use crate::{
    instruction::{
        CustomInitializeTokenMetadata, CustomRemoveKey, CustomUpdateField, InitializeArgs,
        SecurityTokenInstruction, UpdateMetadataArgs,
    },
    utils,
};
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::rent::{
        Rent, DEFAULT_BURN_PERCENT, DEFAULT_EXEMPTION_THRESHOLD, DEFAULT_LAMPORTS_PER_BYTE_YEAR,
    },
    ProgramResult,
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
    extensions::metadata::{Field, TokenMetadata},
    instructions::AuthorityType,
};

/// Program state handler
pub struct Processor;

impl Processor {
    /// Processes an instruction
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if instruction_data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (discriminant, rest) = instruction_data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        match SecurityTokenInstruction::try_from(*discriminant)? {
            SecurityTokenInstruction::InitializeMint => {
                Self::process_initialize_mint(program_id, accounts, rest)
            }
            SecurityTokenInstruction::UpdateMetadata => {
                Self::process_update_metadata(program_id, accounts, rest)
            }
        }
    }

    fn process_update_metadata(
        _program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        log!("Processing UpdateMetadata instruction");

        // Parse the UpdateMetadataArgs structure
        let args = UpdateMetadataArgs::unpack(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        // Validate arguments
        args.validate()?;

        // Parse accounts
        let account_info_iter = &mut accounts.iter();
        let mint_info = utils::next_account_info(account_info_iter)?; // 0. Mint account
        let authority_info = utils::next_account_info(account_info_iter)?; // 1. Authority (signer)
        let _token_program_info = utils::next_account_info(account_info_iter).ok(); // 2. Optional Token program
        let system_program_info = utils::next_account_info(account_info_iter).ok(); // 3. Optional System program

        if !authority_info.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

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
        if let Some(_system_program) = system_program_info {
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
        } else {
            log!("No system program provided - assuming current space is sufficient");
        }

        let update_field_instruction = CustomUpdateField::new(
            &metadata_account_info,
            authority_info,
            Field::Name,
            args.metadata.name,
        );

        update_field_instruction.invoke()?;

        // Update symbol
        let update_symbol_instruction = CustomUpdateField::new(
            &metadata_account_info,
            authority_info,
            Field::Symbol,
            args.metadata.symbol,
        );

        update_symbol_instruction.invoke()?;

        // Update URI
        let update_uri_instruction = CustomUpdateField::new(
            &metadata_account_info,
            authority_info,
            Field::Uri,
            args.metadata.uri,
        );

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
                    let update_field_instruction = CustomUpdateField::new(
                        &metadata_account_info,
                        authority_info,
                        Field::Key(key),
                        value,
                    );
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

    /// Process InitializeMint instruction
    fn process_initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        log!("Processing InitializeMint with Token-2022 extensions");

        // Parse the full InitializeArgs structure
        let args =
            InitializeArgs::unpack(args_data).map_err(|_| ProgramError::InvalidInstructionData)?;

        let decimals = args.ix_mint.decimals;
        let client_mint_authority = args.ix_mint.mint_authority;
        let freeze_authority_opt = args.ix_mint.freeze_authority;
        let metadata_pointer_opt = args.ix_metadata_pointer;
        let metadata_opt = args.ix_metadata;
        let scaled_ui_amount_opt = args.ix_scaled_ui_amount;
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

        // Parse accounts
        let account_info_iter = &mut accounts.iter();
        let mint_info = utils::next_account_info(account_info_iter)?; // 0. Mint account
        let creator_info = utils::next_account_info(account_info_iter)?; // 1. Creator (signer)
        let token_program_info = utils::next_account_info(account_info_iter)?; // 2. SPL Token 2022 program
        let _system_program_info = utils::next_account_info(account_info_iter)?; // 3. System program
        let rent_info = utils::next_account_info(account_info_iter)?; // 4. Rent sysvar

        if !creator_info.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if !mint_info.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Build required extensions list without heap allocations (SBF no-allocator)
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
            space: mint_size as u64, // space (full size including metadata for SBF compatibility)
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
                    let update_field_instruction = CustomUpdateField::new(
                        &metadata_account_info,
                        creator_info,
                        Field::Key(key),
                        value,
                    );
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
}

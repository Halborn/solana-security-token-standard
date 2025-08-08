use crate::{
    instruction::{InitializeArgs, SecurityTokenInstruction, UpdateMetadataArgs},
    utils,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::instruction as system_instruction;
use spl_token_2022::{extension::ExtensionType, instruction, state::Mint};

/// Program state handler
pub struct Processor;

impl Processor {
    /// Processes an instruction
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        // Extract instruction type from the first byte
        let (&instruction_type, args_data) = instruction_data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        let instruction = SecurityTokenInstruction::from(instruction_type);

        match instruction {
            SecurityTokenInstruction::InitializeMint => {
                msg!("Instruction: Initialize Mint");
                Self::process_initialize_mint(program_id, accounts, args_data)
            }
            SecurityTokenInstruction::UpdateMetadata => {
                msg!("Instruction: Update Metadata");
                Self::process_update_metadata(program_id, accounts, args_data)
            }
        }
    }

    fn process_update_metadata(
        _program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        msg!("Processing UpdateMetadata instruction");

        // Parse the UpdateMetadataArgs structure
        let args = UpdateMetadataArgs::unpack(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        // Validate arguments
        args.validate()?;

        msg!("Updating metadata for token");
        msg!("New name: {}", args.metadata.name);
        msg!("New symbol: {}", args.metadata.symbol);
        msg!("New URI: {}", args.metadata.uri);

        // Parse accounts
        let account_info_iter = &mut accounts.iter();
        let mint_info = next_account_info(account_info_iter)?; // 0. Mint account
        let authority_info = next_account_info(account_info_iter)?; // 1. Authority (signer)
        let token_program_info = next_account_info(account_info_iter).ok(); // 2. Optional Token program
        let system_program_info = next_account_info(account_info_iter).ok(); // 3. Optional System program

        if !authority_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Get the SPL Token 2022 program (should be the mint's owner, or passed explicitly)
        let token_program_id = if let Some(token_program) = token_program_info {
            *token_program.key
        } else {
            *mint_info.owner
        };

        // Get metadata account address from MetadataPointer extension
        use spl_token_2022::extension::{BaseStateWithExtensions, StateWithExtensions};
        use spl_token_2022::state::Mint;

        let metadata_address: Option<Pubkey> = {
            let mint_data = mint_info.try_borrow_data()?;
            let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_data)?;

            // Get metadata pointer to find where metadata is stored
            let metadata_pointer = mint_with_extensions
                .get_extension::<spl_token_2022::extension::metadata_pointer::MetadataPointer>()
                .map_err(|_| ProgramError::InvalidAccountData)?;

            metadata_pointer.metadata_address.into()
        }; // Borrow is released here
        let metadata_address = metadata_address.ok_or(ProgramError::InvalidAccountData)?;

        msg!("Metadata stored at address: {}", metadata_address);

        // Determine metadata account (could be mint itself or external account)
        let metadata_account_info = if metadata_address == *mint_info.key {
            // Metadata is stored in mint account (in-mint storage)
            mint_info.clone()
        } else {
            // Metadata is stored in external account - would need to be passed in accounts
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Update base metadata fields using SPL Token Metadata Interface
        msg!("Updating base metadata fields (name, symbol, URI)");

        // Calculate additional space needed for metadata updates and transfer rent if needed
        if let Some(system_program) = system_program_info {
            msg!("Calculating additional rent for metadata updates");

            // Calculate current and new metadata sizes
            let new_metadata_size = args.metadata.tlv_size_of()?;
            let current_account_size = metadata_account_info.data_len();

            msg!("Current account size: {} bytes", current_account_size);
            msg!("New metadata TLV size needed: {} bytes", new_metadata_size);

            // Get current metadata size to calculate the difference
            let current_metadata_size = {
                let mint_data = metadata_account_info.try_borrow_data()?;
                let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_data)?;

                // Try to get current metadata size
                if let Ok(current_metadata) = mint_with_extensions.get_variable_len_extension::<spl_token_metadata_interface::state::TokenMetadata>() {
                    current_metadata.tlv_size_of()?
                } else {
                    // No metadata currently, so current size is 0
                    0
                }
            };

            msg!("Current metadata TLV size: {} bytes", current_metadata_size);

            if new_metadata_size > current_metadata_size {
                let additional_metadata_space = new_metadata_size - current_metadata_size;
                let rent = Rent::get()?;
                let additional_rent = rent.minimum_balance(additional_metadata_space);

                msg!(
                    "Additional metadata space needed: {} bytes",
                    additional_metadata_space
                );
                msg!("Additional rent needed: {} lamports", additional_rent);

                // Transfer additional rent from authority to metadata account
                let transfer_instruction = system_instruction::transfer(
                    authority_info.key,        // from (authority pays)
                    metadata_account_info.key, // to (metadata account)
                    additional_rent,           // amount
                );

                invoke(
                    &transfer_instruction,
                    &[
                        authority_info.clone(),
                        metadata_account_info.clone(),
                        system_program.clone(),
                    ],
                )?;

                msg!(
                    "Transferred {} lamports for additional metadata space",
                    additional_rent
                );
            } else {
                msg!("No additional rent needed - current metadata space is sufficient");
            }
        } else {
            msg!("No system program provided - assuming current space is sufficient");
        }

        // Update name
        let update_name_instruction = spl_token_metadata_interface::instruction::update_field(
            &token_program_id,         // Token-2022 program ID
            metadata_account_info.key, // metadata account
            authority_info.key,        // update authority
            spl_token_metadata_interface::state::Field::Name,
            args.metadata.name.clone(),
        );

        invoke(
            &update_name_instruction,
            &[metadata_account_info.clone(), authority_info.clone()],
        )?;
        msg!("Name updated to: {}", args.metadata.name);

        // Update symbol
        let update_symbol_instruction = spl_token_metadata_interface::instruction::update_field(
            &token_program_id,         // Token-2022 program ID
            metadata_account_info.key, // metadata account
            authority_info.key,        // update authority
            spl_token_metadata_interface::state::Field::Symbol,
            args.metadata.symbol.clone(),
        );

        invoke(
            &update_symbol_instruction,
            &[metadata_account_info.clone(), authority_info.clone()],
        )?;
        msg!("Symbol updated to: {}", args.metadata.symbol);

        // Update URI
        let update_uri_instruction = spl_token_metadata_interface::instruction::update_field(
            &token_program_id,         // Token-2022 program ID
            metadata_account_info.key, // metadata account
            authority_info.key,        // update authority
            spl_token_metadata_interface::state::Field::Uri,
            args.metadata.uri.clone(),
        );

        invoke(
            &update_uri_instruction,
            &[metadata_account_info.clone(), authority_info.clone()],
        )?;
        msg!("URI updated to: {}", args.metadata.uri);

        // Handle additional metadata fields atomically
        // First, get current metadata to remove old fields
        let current_additional_fields = {
            let mint_data = metadata_account_info.try_borrow_data()?;
            let mint_with_extensions = StateWithExtensions::<Mint>::unpack(&mint_data)?;

            if let Ok(current_metadata) = mint_with_extensions
                .get_variable_len_extension::<spl_token_metadata_interface::state::TokenMetadata>(
            ) {
                current_metadata.additional_metadata.clone()
            } else {
                Vec::new()
            }
        };

        // Remove all existing additional metadata fields
        if !current_additional_fields.is_empty() {
            msg!(
                "Removing {} existing additional metadata fields",
                current_additional_fields.len()
            );

            for (key, _value) in &current_additional_fields {
                let remove_field_instruction =
                    spl_token_metadata_interface::instruction::remove_key(
                        &token_program_id,         // Token-2022 program ID
                        metadata_account_info.key, // metadata account
                        authority_info.key,        // update authority
                        key.clone(),               // key to remove
                        false,                     // idempotent
                    );

                invoke(
                    &remove_field_instruction,
                    &[metadata_account_info.clone(), authority_info.clone()],
                )?;
                msg!("Removed old metadata field: {}", key);
            }
        }

        // Add new additional metadata fields
        if !args.metadata.additional_metadata.is_empty() {
            msg!(
                "Adding {} new additional metadata fields",
                args.metadata.additional_metadata.len()
            );

            for (key, value) in &args.metadata.additional_metadata {
                let update_field_instruction =
                    spl_token_metadata_interface::instruction::update_field(
                        &token_program_id,         // Token-2022 program ID
                        metadata_account_info.key, // metadata account
                        authority_info.key,        // update authority
                        spl_token_metadata_interface::state::Field::Key(key.clone()),
                        value.clone(),
                    );

                invoke(
                    &update_field_instruction,
                    &[metadata_account_info.clone(), authority_info.clone()],
                )?;
                msg!("Added new metadata field: {} = {}", key, value);
            }
        }

        msg!("Metadata updated successfully for mint: {}", mint_info.key);
        Ok(())
    }

    /// Process InitializeMint instruction
    fn process_initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        msg!("Processing InitializeMint with Token-2022 extensions");

        // Parse the full InitializeArgs structure
        let args =
            InitializeArgs::unpack(args_data).map_err(|_| ProgramError::InvalidInstructionData)?;

        let decimals = args.ix_mint.decimals;
        let mint_authority = args.ix_mint.mint_authority;
        let freeze_authority_opt = args.ix_mint.freeze_authority;
        let metadata_pointer_opt = args.ix_metadata_pointer;
        let metadata_opt = args.ix_metadata;
        let scaled_ui_amount_opt = args.ix_scaled_ui_amount;

        msg!("Initializing mint with {} decimals", decimals);
        msg!("Mint authority: {}", mint_authority);
        if let Some(freeze_auth) = freeze_authority_opt {
            msg!("Freeze authority: {}", freeze_auth);
        }

        if let Some(metadata) = &metadata_opt {
            msg!("Token name: {}", metadata.name);
            msg!("Token symbol: {}", metadata.symbol);
            msg!("Token URI: {}", metadata.uri);
            msg!(
                "With metadata: {} ({}) - {}",
                metadata.name,
                metadata.symbol,
                metadata.uri
            );
        }
        if let Some(_metadata_pointer) = &metadata_pointer_opt {
            msg!("MetadataPointer configuration provided by client");
        }
        if let Some(_scaled_ui_amount) = &scaled_ui_amount_opt {
            msg!("ScaledUiAmount configuration provided by client");
        }

        // Parse accounts
        let account_info_iter = &mut accounts.iter();
        let mint_info = next_account_info(account_info_iter)?; // 0. Mint account
        let creator_info = next_account_info(account_info_iter)?; // 1. Creator (signer)
        let token_program_info = next_account_info(account_info_iter)?; // 2. SPL Token 2022 program
        let system_program_info = next_account_info(account_info_iter)?; // 3. System program
        let rent_info = next_account_info(account_info_iter)?; // 4. Rent sysvar

        if !creator_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if !mint_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Get mint authority PDA - this will be the mint authority for the token
        let (mint_authority_pda, _mint_authority_bump) =
            utils::find_mint_authority_pda(mint_info.key, creator_info.key, program_id);

        // Build required extensions list based on client data and our security requirements
        let mut required_extensions: Vec<ExtensionType> = vec![
            ExtensionType::PermanentDelegate,
            ExtensionType::TransferHook,
            ExtensionType::Pausable,
        ];

        // Add MetadataPointer if metadata is provided
        if metadata_opt.is_some() || metadata_pointer_opt.is_some() {
            required_extensions.push(ExtensionType::MetadataPointer);
        }

        // Add ScaledUiAmount if provided by client
        if scaled_ui_amount_opt.is_some() {
            required_extensions.push(ExtensionType::ScaledUiAmount);
            msg!("ScaledUiAmount extension will be initialized");
        }

        // Calculate mint size with extensions (but without metadata TLV data)
        let mint_size = ExtensionType::try_calculate_account_len::<Mint>(&required_extensions)
            .map_err(|_| ProgramError::InvalidAccountData)?;

        // Calculate total size for rent (mint + metadata)
        let metadata_size = if let Some(metadata) = &metadata_opt {
            metadata.tlv_size_of()?
        } else {
            0
        };
        let total_size = mint_size + metadata_size;

        msg!("Mint size: {} bytes", mint_size);
        msg!("Metadata TLV size: {} bytes", metadata_size);
        msg!("Total size for rent: {} bytes", total_size);

        let rent = Rent::from_account_info(rent_info)?;
        let required_lamports = rent.minimum_balance(total_size);

        msg!(
            "Creating mint account with {} lamports for {} bytes",
            required_lamports,
            mint_size
        );

        let create_account_instruction = system_instruction::create_account(
            creator_info.key,       // from (payer)
            mint_info.key,          // to (new account)
            required_lamports,      // lamports (calculated from total size)
            mint_size as u64,       // space (only mint size, not metadata)
            token_program_info.key, // owner (SPL Token 2022 program)
        );

        invoke(
            &create_account_instruction,
            &[
                creator_info.clone(),
                mint_info.clone(),
                system_program_info.clone(),
            ],
        )?;

        msg!("Mint account created successfully");

        // Calculate all PDAs that will be used for extensions and mint initialization
        let (transfer_hook_pda, _bump) = utils::find_transfer_hook_pda(mint_info.key, program_id);
        let (permanent_delegate_pda, _bump) =
            utils::find_permanent_delegate_pda(mint_info.key, program_id);
        let (freeze_authority_pda, _bump) =
            utils::find_freeze_authority_pda(mint_info.key, program_id);

        msg!("TransferHook PDA: {}", transfer_hook_pda);
        msg!("PermanentDelegate PDA: {}", permanent_delegate_pda);
        msg!("FreezeAuthority PDA: {}", freeze_authority_pda);
        msg!("All extension PDAs calculated successfully");

        msg!("Extensions setup - initializing extensions BEFORE basic mint");

        // Initialize all extensions first, then basic mint
        msg!("Initializing Token-2022 extensions before basic mint");

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
                    msg!("Using default MetadataPointer configuration");
                    (Some(*creator_info.key), Some(*mint_info.key))
                };

            let metadata_pointer_init_instruction =
                spl_token_2022::extension::metadata_pointer::instruction::initialize(
                    token_program_info.key, // SPL Token 2022 program ID
                    mint_info.key,          // mint account
                    metadata_authority,     // metadata authority (from client or our PDA)
                    metadata_address,       // metadata address (from client or mint)
                )?;
            invoke(
                &metadata_pointer_init_instruction,
                &[mint_info.clone(), token_program_info.clone()],
            )?;
            msg!("MetadataPointer extension initialized");

            // Return the metadata address for later use
            metadata_address
        } else {
            None
        };

        msg!("Mint authority PDA: {}", mint_authority_pda);

        let transfer_hook_init_instruction =
            spl_token_2022::extension::transfer_hook::instruction::initialize(
                token_program_info.key,   // SPL Token 2022 program ID
                mint_info.key,            // mint account
                Some(mint_authority_pda), // hook authority (our PDA)
                Some(transfer_hook_pda),  // hook program ID (our transfer hook PDA)
            )?;
        invoke(
            &transfer_hook_init_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;
        msg!("TransferHook extension initialized");

        let permanent_delegate_init_instruction = instruction::initialize_permanent_delegate(
            token_program_info.key,  // SPL Token 2022 program ID
            mint_info.key,           // mint account
            &permanent_delegate_pda, // delegate authority (our PDA)
        )?;

        invoke(
            &permanent_delegate_init_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;
        msg!("PermanentDelegate extension initialized");

        let pausable_init_instruction =
            spl_token_2022::extension::pausable::instruction::initialize(
                token_program_info.key, // SPL Token 2022 program ID
                mint_info.key,          // mint account
                &mint_authority_pda,    // pause authority (our PDA)
            )?;

        invoke(
            &pausable_init_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;
        msg!("Pausable extension initialized");

        // Initialize ScaledUiAmount extension if provided by client
        if let Some(scaled_ui_amount_config) = &scaled_ui_amount_opt {
            msg!("Initializing ScaledUiAmount extension with client configuration");

            let scaled_ui_amount_init_instruction =
                spl_token_2022::extension::scaled_ui_amount::instruction::initialize(
                    token_program_info.key,                        // SPL Token 2022 program ID
                    mint_info.key,                                 // mint account
                    scaled_ui_amount_config.authority.into(),      // authority from client
                    f64::from(scaled_ui_amount_config.multiplier), // multiplier from client
                )?;
            invoke(
                &scaled_ui_amount_init_instruction,
                &[mint_info.clone(), token_program_info.clone()],
            )?;
            msg!(
                "ScaledUiAmount extension initialized with multiplier: {}",
                f64::from(scaled_ui_amount_config.multiplier)
            );
        }

        msg!("All security token extensions initialized successfully");
        msg!("Initializing basic mint AFTER extensions");

        let initialize_mint_instruction = instruction::initialize_mint2(
            token_program_info.key,              // SPL Token 2022 program ID
            mint_info.key,                       // mint account
            creator_info.key,                    // temporary mint authority (creator)
            Some(freeze_authority_pda).as_ref(), // freeze authority (optional)
            decimals,                            // decimals
        )?;

        invoke(
            &initialize_mint_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;

        msg!(
            "Basic mint initialized successfully with {} decimals",
            decimals
        );

        if let Some(metadata) = &metadata_opt {
            msg!("Preparing to initialize token metadata through SPL Token Metadata Interface");

            // Determine which account to use for metadata
            let metadata_account_info = if let Some(metadata_addr) = metadata_account_address {
                if metadata_addr == *mint_info.key {
                    // Metadata is stored in mint account (in-mint storage)
                    mint_info.clone()
                } else {
                    // Metadata is stored in external account - find it in accounts list
                    accounts
                        .iter()
                        .find(|acc| acc.key == &metadata_addr)
                        .ok_or_else(|| {
                            msg!(
                                "Metadata account {} not found in accounts list",
                                metadata_addr
                            );
                            ProgramError::InvalidAccountData
                        })?
                        .clone()
                }
            } else {
                // No metadata pointer, shouldn't happen if we have metadata
                return Err(ProgramError::InvalidInstructionData);
            };

            msg!("Initializing token metadata");

            // First initialize base metadata with name, symbol, uri
            // Use creator as update authority since PDA might not have funds
            let metadata_init_instruction = spl_token_metadata_interface::instruction::initialize(
                token_program_info.key, // Token-2022 program ID (handles metadata interface)
                metadata_account_info.key, // metadata account (from MetadataPointer)
                creator_info.key,       // update authority (creator)
                mint_info.key,          // mint account
                creator_info.key, // mint authority (creator is still mint authority at this point)
                metadata.name.clone(),
                metadata.symbol.clone(),
                metadata.uri.clone(),
            );

            invoke(
                &metadata_init_instruction,
                &[
                    metadata_account_info.clone(), // metadata account (from MetadataPointer)
                    creator_info.clone(),          // update authority (creator)
                    mint_info.clone(),             // mint account
                    creator_info.clone(),          // mint authority (creator - must sign)
                ],
            )?;
            msg!("Base metadata initialized successfully");

            // Add additional metadata fields if present - each field requires separate instruction
            if !metadata.additional_metadata.is_empty() {
                msg!(
                    "Adding {} additional metadata fields",
                    metadata.additional_metadata.len()
                );

                for (key, value) in &metadata.additional_metadata {
                    let update_field_instruction =
                        spl_token_metadata_interface::instruction::update_field(
                            token_program_info.key,    // Token-2022 program ID
                            metadata_account_info.key, // metadata account (from MetadataPointer)
                            creator_info.key,          // update authority (creator)
                            spl_token_metadata_interface::state::Field::Key(key.clone()),
                            value.clone(),
                        );

                    invoke(
                        &update_field_instruction,
                        &[
                            metadata_account_info.clone(), // metadata account (from MetadataPointer)
                            creator_info.clone(),          // update authority (creator)
                        ],
                    )?;
                    msg!("Added metadata field: {} = {}", key, value);
                }
            }

            msg!("All metadata initialized successfully");
        } else {
            msg!("No metadata provided, skipping metadata initialization");
        }

        // Transfer mint authority from creator to our PDA for security token control
        msg!("Transferring mint authority from creator to PDA for security token control");
        let set_authority_instruction = spl_token_2022::instruction::set_authority(
            token_program_info.key,    // SPL Token 2022 program
            mint_info.key,             // mint account
            Some(&mint_authority_pda), // new authority (our PDA)
            spl_token_2022::instruction::AuthorityType::MintTokens, // authority type
            creator_info.key,          // current authority (creator)
            &[],                       // multisig signers (none)
        )?;

        invoke(
            &set_authority_instruction,
            &[
                mint_info.clone(),
                creator_info.clone(), // current authority must sign
                token_program_info.clone(),
            ],
        )?;

        msg!(
            "Mint authority successfully transferred to PDA: {}",
            mint_authority_pda
        );
        msg!("Security token mint initialization completed successfully");
        Ok(())
    }
}

impl From<u8> for SecurityTokenInstruction {
    fn from(value: u8) -> Self {
        match value {
            0 => SecurityTokenInstruction::InitializeMint,
            1 => SecurityTokenInstruction::UpdateMetadata,
            _ => SecurityTokenInstruction::InitializeMint,
        }
    }
}

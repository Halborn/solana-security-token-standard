use crate::{
    instruction::{InitializeArgs, SecurityTokenInstruction},
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
        }
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

        let mint_size = ExtensionType::try_calculate_account_len::<Mint>(&required_extensions)
            .map_err(|_| ProgramError::InvalidAccountData)?;

        msg!("Calculated mint account size: {} bytes", mint_size);

        let rent = Rent::from_account_info(rent_info)?;
        let required_lamports = rent.minimum_balance(mint_size);

        msg!("Creating mint account with {} lamports", required_lamports);

        // CPI to System Program to create account
        let create_account_instruction = system_instruction::create_account(
            creator_info.key,       // from (payer)
            mint_info.key,          // to (new account)
            required_lamports,      // lamports
            mint_size as u64,       // space
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
        msg!("Extensions setup - checking account structure and PDAs");

        // For now, we'll verify that extensions are properly calculated in account size
        // The actual extension initialization will be done after basic mint initialization
        msg!(
            "Extension space allocated in mint account: {} bytes",
            mint_size
        );
        msg!("Required extensions: MetadataPointer, PermanentDelegate, TransferHook");

        // Calculate all PDAs that will be used for extensions
        let (transfer_hook_pda, _bump) = utils::find_transfer_hook_pda(mint_info.key, program_id);
        let (permanent_delegate_pda, _bump) =
            utils::find_permanent_delegate_pda(mint_info.key, program_id);
        let (freeze_authority_pda, _bump) =
            utils::find_freeze_authority_pda(mint_info.key, program_id);

        msg!("TransferHook PDA: {}", transfer_hook_pda);
        msg!("PermanentDelegate PDA: {}", permanent_delegate_pda);
        msg!("FreezeAuthority PDA: {}", freeze_authority_pda);
        msg!("All extension PDAs calculated successfully");
        msg!("Initializing Token-2022 extensions before mint");

        msg!("Mint authority PDA: {}", mint_authority_pda);

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

        // Now initialize the basic mint
        msg!("Initializing basic mint after all extensions");

        // Initialize basic mint with creator as temporary mint authority
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
            "Mint initialized successfully with {} decimals and all security token extensions",
            decimals
        );

        if let Some(metadata) = &metadata_opt {
            msg!("Initializing token metadata through SPL Token Metadata Interface");

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
            _ => SecurityTokenInstruction::InitializeMint,
        }
    }
}

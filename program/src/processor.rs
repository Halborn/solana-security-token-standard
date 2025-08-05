use crate::{
    instruction::{InitializeArgs, InitializeMintArgs, SecurityTokenInstruction},
    utils,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
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

        // Support three formats:
        // 1. Simple - only decimals (one byte)
        // 2. Mint only - InitializeMintArgs structure
        // 3. Full - InitializeArgs with mint + metadata
        let (decimals, _mint_authority_opt, _freeze_authority_opt, metadata_opt) = if args_data
            .is_empty()
        {
            (6u8, None, None, None) // Default decimals
        } else if args_data.len() == 1 {
            // Simple format - only decimals
            (args_data[0], None, None, None)
        } else {
            // Try full InitializeArgs first (with metadata)
            match InitializeArgs::unpack(args_data) {
                Ok(full_args) => {
                    msg!("Successfully unpacked full InitializeArgs");
                    if let Some(metadata) = &full_args.ix_metadata {
                        msg!("Token name: {}", metadata.name);
                        msg!("Token symbol: {}", metadata.symbol);
                        msg!("Token URI: {}", metadata.uri);
                    }
                    msg!("Mint authority: {}", full_args.ix_mint.mint_authority);
                    if let Some(freeze_auth) = full_args.ix_mint.freeze_authority {
                        msg!("Freeze authority: {}", freeze_auth);
                    }
                    (
                        full_args.ix_mint.decimals,
                        Some(full_args.ix_mint.mint_authority),
                        full_args.ix_mint.freeze_authority,
                        full_args.ix_metadata,
                    )
                }
                Err(_) => {
                    // Fallback to mint-only format
                    match InitializeMintArgs::unpack(args_data) {
                        Ok(mint_args) => {
                            msg!("Successfully unpacked InitializeMintArgs (mint only)");
                            msg!("Mint authority: {}", mint_args.mint_authority);
                            if let Some(freeze_auth) = mint_args.freeze_authority {
                                msg!("Freeze authority: {}", freeze_auth);
                            }
                            (
                                mint_args.decimals,
                                Some(mint_args.mint_authority),
                                mint_args.freeze_authority,
                                None,
                            )
                        }
                        Err(_) => {
                            // Final fallback to simple format
                            msg!("Failed to unpack structured data, using first byte as decimals");
                            (args_data[0], None, None, None)
                        }
                    }
                }
            }
        };

        msg!("Initializing mint with {} decimals", decimals);
        if let Some(metadata) = &metadata_opt {
            msg!(
                "With metadata: {} ({}) - {}",
                metadata.name,
                metadata.symbol,
                metadata.uri
            );
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

        let required_extensions: Vec<ExtensionType> = vec![
            ExtensionType::MetadataPointer,
            ExtensionType::PermanentDelegate,
            ExtensionType::TransferHook,
            ExtensionType::Pausable,
        ];

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

        // TODO: Figure out how they come
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

        // Get mint authority PDA - this will be the mint authority for the token
        let (mint_authority_pda, _mint_authority_bump) =
            utils::find_mint_authority_pda(mint_info.key, creator_info.key, program_id);

        msg!("Mint authority PDA: {}", mint_authority_pda);

        let metadata_pointer_init_instruction =
            spl_token_2022::extension::metadata_pointer::instruction::initialize(
                token_program_info.key,   // SPL Token 2022 program ID
                mint_info.key,            // mint account
                Some(mint_authority_pda), // metadata authority (our PDA)
                Some(*mint_info.key),     // metadata address (store metadata ON the mint account)
            )?;
        invoke(
            &metadata_pointer_init_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;
        msg!("MetadataPointer extension initialized");
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

        msg!("All security token extensions initialized successfully");

        // Now initialize the basic mint
        msg!("Initializing basic mint after all extensions");

        // Initialize basic mint with all security token extensions
        let initialize_mint_instruction = instruction::initialize_mint2(
            token_program_info.key,              // SPL Token 2022 program ID
            mint_info.key,                       // mint account
            &mint_authority_pda,                 // mint authority
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

        // Now initialize the metadata through SPL Token Metadata Interface
        if let Some(metadata) = &metadata_opt {
            msg!("Initializing token metadata through SPL Token Metadata Interface");

            // Create metadata initialize instruction using SPL Token Metadata Interface
            // Note: For Token-2022 with MetadataPointer, metadata is handled by the token program itself
            let metadata_init_instruction = spl_token_metadata_interface::instruction::initialize(
                token_program_info.key, // Token-2022 program ID (handles metadata interface)
                mint_info.key,          // metadata account (same as mint due to MetadataPointer)
                &mint_authority_pda,    // update authority
                mint_info.key,          // mint account
                &mint_authority_pda,    // mint authority
                metadata.name.clone(),
                metadata.symbol.clone(),
                metadata.uri.clone(),
            );

            // Sign with mint authority PDA to create metadata
            let mint_authority_signer_seeds = utils::get_mint_authority_seeds(
                mint_info.key,
                creator_info.key,
                &_mint_authority_bump,
            );
            let mint_authority_signers = &[&mint_authority_signer_seeds[..]];

            invoke_signed(
                &metadata_init_instruction,
                &[
                    mint_info.clone(), // metadata account
                    mint_info.clone(), // update authority account
                    mint_info.clone(), // mint account
                    mint_info.clone(), // mint authority account (PDA)
                ],
                mint_authority_signers,
            )?;
            msg!("Basic metadata initialized");

            // Add additional metadata fields if present
            if !metadata.additional_metadata.is_empty() {
                msg!(
                    "Adding {} additional metadata fields",
                    metadata.additional_metadata.len()
                );

                for (key, value) in &metadata.additional_metadata {
                    let update_field_instruction =
                        spl_token_metadata_interface::instruction::update_field(
                            token_program_info.key, // Token-2022 program ID
                            mint_info.key,          // metadata account
                            &mint_authority_pda,    // update authority
                            spl_token_metadata_interface::state::Field::Key(key.clone()),
                            value.clone(),
                        );

                    invoke_signed(
                        &update_field_instruction,
                        &[
                            mint_info.clone(), // metadata account
                            mint_info.clone(), // update authority account (PDA)
                        ],
                        mint_authority_signers,
                    )?;
                    msg!("Added metadata field: {} = {}", key, value);
                }
            }

            msg!("All metadata initialized successfully");
        } else {
            msg!("No metadata provided, skipping metadata initialization");
        }
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

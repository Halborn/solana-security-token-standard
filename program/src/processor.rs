use crate::{instruction::SecurityTokenInstruction, utils};
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
        let instruction = SecurityTokenInstruction::from(instruction_data[0]);

        match instruction {
            SecurityTokenInstruction::InitializeMint => {
                msg!("Instruction: InitializeMint");
                Self::process_initialize_mint(program_id, accounts, instruction_data)
            }
            SecurityTokenInstruction::UpdateVerificationConfig => {
                msg!("Instruction: UpdateVerificationConfig");
                Err(ProgramError::InvalidInstructionData)
            }
            SecurityTokenInstruction::SetVerificationStatus => {
                msg!("Instruction: SetVerificationStatus");
                Err(ProgramError::InvalidInstructionData)
            }
            SecurityTokenInstruction::UpdateWhitelist => {
                msg!("Instruction: UpdateWhitelist");
                Err(ProgramError::InvalidInstructionData)
            }
        }
    }

    /// Process InitializeMint instruction
    /// Phase 2: Real Token-2022 mint initialization with extensions
    fn process_initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        msg!("Processing InitializeMint with Token-2022 extensions");

        // Parse decimals from instruction data (second byte, first is instruction discriminator)
        let decimals = if instruction_data.len() < 2 {
            6 // Default decimals
        } else {
            instruction_data[1]
        };

        msg!("Initializing mint with {} decimals", decimals);

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
        ];

        let mint_size = ExtensionType::try_calculate_account_len::<Mint>(&required_extensions)
            .map_err(|_| ProgramError::InvalidAccountData)?;

        msg!(
            "Calculated mint account size: {} bytes (with MetadataPointer extension)",
            mint_size
        );

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
        let (metadata_pointer_pda, _bump) =
            utils::find_metadata_pointer_pda(mint_info.key, program_id);

        let (permanent_delegate_pda, _bump) =
            utils::find_permanent_delegate_pda(mint_info.key, program_id);

        let (transfer_hook_pda, _bump) = utils::find_transfer_hook_pda(mint_info.key, program_id);

        msg!("MetadataPointer PDA: {}", metadata_pointer_pda);
        msg!("PermanentDelegate PDA: {}", permanent_delegate_pda);
        msg!("TransferHook PDA: {}", transfer_hook_pda);
        msg!("All extension PDAs calculated successfully");
        msg!("Step 4: Initializing Token-2022 extensions before mint");

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
            token_program_info.key, // SPL Token 2022 program ID
            mint_info.key,          // mint account
            &mint_authority_pda,    // delegate authority (our PDA)
        )?;

        invoke(
            &permanent_delegate_init_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;
        msg!("PermanentDelegate extension initialized");
        msg!("All security token extensions initialized successfully");

        // Now initialize the basic mint
        msg!("Initializing basic mint after all extensions");

        // Initialize basic mint with all security token extensions
        let freeze_authority = Some(mint_authority_pda); // Same PDA can freeze tokens

        let initialize_mint_instruction = instruction::initialize_mint2(
            token_program_info.key,    // SPL Token 2022 program ID
            mint_info.key,             // mint account
            &mint_authority_pda,       // mint authority
            freeze_authority.as_ref(), // freeze authority (optional)
            decimals,                  // decimals
        )?;

        invoke(
            &initialize_mint_instruction,
            &[mint_info.clone(), token_program_info.clone()],
        )?;

        msg!(
            "Mint initialized successfully with {} decimals and all security token extensions",
            decimals
        );
        Ok(())
    }
}

impl From<u8> for SecurityTokenInstruction {
    fn from(value: u8) -> Self {
        match value {
            0 => SecurityTokenInstruction::InitializeMint,
            1 => SecurityTokenInstruction::UpdateVerificationConfig,
            2 => SecurityTokenInstruction::SetVerificationStatus,
            3 => SecurityTokenInstruction::UpdateWhitelist,
            _ => SecurityTokenInstruction::InitializeMint,
        }
    }
}

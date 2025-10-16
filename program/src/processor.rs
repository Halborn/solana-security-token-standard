use crate::{
    instruction::SecurityTokenInstruction,
    instructions::{
        verification_config::TrimVerificationConfigInstructionArgs, InitializeArgs,
        InitializeVerificationConfigInstructionArgs, UpdateMetadataArgs,
        UpdateVerificationConfigInstructionArgs, VerifyArgs,
    },
    modules::{verification::VerificationModule, OperationsModule},
};
use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
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
        let (instruction, args_data) =
            SecurityTokenInstruction::parse_instruction(instruction_data)?;

        match instruction {
            SecurityTokenInstruction::InitializeMint => {
                Self::process_initialize_mint(program_id, accounts, args_data)
            }
            SecurityTokenInstruction::InitializeVerificationConfig => {
                Self::process_initialize_verification_config(program_id, accounts, args_data)
            }
            SecurityTokenInstruction::UpdateVerificationConfig => {
                Self::process_update_verification_config(program_id, accounts, args_data)
            }
            SecurityTokenInstruction::TrimVerificationConfig => {
                Self::process_trim_verification_config(program_id, accounts, args_data)
            }
            SecurityTokenInstruction::Verify => {
                Self::process_verify(program_id, accounts, args_data)
            }
            // Methods require verification
            SecurityTokenInstruction::UpdateMetadata => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_update_metadata(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Mint => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_mint(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Burn => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_burn(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Pause => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_pause(program_id, instruction_accounts)
            }
            SecurityTokenInstruction::Resume => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_resume(program_id, instruction_accounts)
            }
            SecurityTokenInstruction::Freeze => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_freeze(program_id, instruction_accounts)
            }
            SecurityTokenInstruction::Thaw => {
                let instruction_accounts = Self::verify_instruction_if_needed(
                    program_id,
                    accounts,
                    instruction.discriminant(),
                )?;
                Self::process_thaw(program_id, instruction_accounts)
            }
        }
    }

    fn verify_instruction_if_needed<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo],
        instruction_discriminator: u8,
    ) -> Result<&'a [AccountInfo], ProgramError> {
        // Expected accounts:
        // 0. [readonly] Mint account - to derive VerificationConfig PDA
        // 1. [readonly] VerificationConfig PDA - client derives from (mint + ix + program_id)
        // 2. [readonly] Instructions sysvar - SysvarS1nstructions1111111111111111111111
        // 3+ [any] Accounts for the target instruction and comparison with verification program calls
        let [_mint_info, _verification_config_account, _instructions_sysvar, instruction_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Run verification if configured, all checks must be inside the module
        VerificationModule::verify(
            program_id,
            accounts,
            &VerifyArgs {
                ix: instruction_discriminator,
            },
        )?;

        Ok(instruction_accounts)
    }

    fn process_update_metadata(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args = UpdateMetadataArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerificationModule::update_metadata(program_id, accounts, &args)
    }

    fn process_initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args = InitializeArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerificationModule::initialize_mint(program_id, accounts, &args)
    }

    fn process_initialize_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args =
            InitializeVerificationConfigInstructionArgs::try_from_bytes(args_data)
                .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::initialize_verification_config(
            program_id,
            accounts,
            &instruction_args.args,
        )
    }

    fn process_update_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args = UpdateVerificationConfigInstructionArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::update_verification_config(program_id, accounts, &instruction_args.args)
    }

    /// Process TrimVerificationConfig instruction
    fn process_trim_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args = TrimVerificationConfigInstructionArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::trim_verification_config(program_id, accounts, &instruction_args.args)
    }

    fn process_verify(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args = VerifyArgs::try_from_bytes(args_data)?;
        VerificationModule::verify(program_id, accounts, &instruction_args)?;
        Ok(())
    }

    fn process_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        // NOTE: Change to MintArgs structure?
        let amount = args_data
            .get(..8)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ProgramError::InvalidInstructionData)?;
        OperationsModule::execute_mint(program_id, accounts, amount)?;
        Ok(())
    }

    fn process_burn(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        // NOTE: Change to BurnArgs structure?
        let amount = args_data
            .get(..8)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ProgramError::InvalidInstructionData)?;
        OperationsModule::execute_burn(program_id, accounts, amount)?;
        Ok(())
    }

    fn process_pause(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        OperationsModule::execute_pause(program_id, accounts)?;
        Ok(())
    }

    fn process_resume(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        OperationsModule::execute_resume(program_id, accounts)?;
        Ok(())
    }

    fn process_freeze(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        OperationsModule::execute_freeze_account(program_id, accounts)?;
        Ok(())
    }

    fn process_thaw(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        OperationsModule::execute_thaw_account(program_id, accounts)?;
        Ok(())
    }
}

use crate::{
    constants::INSTRUCTION_ACCOUNTS_OFFSET,
    instruction::SecurityTokenInstruction,
    instructions::{
        InitializeMintArgs, InitializeVerificationConfigArgs, TrimVerificationConfigArgs,
        UpdateMetadataArgs, UpdateVerificationConfigArgs, VerifyArgs,
    },
    modules::{verification::VerificationModule, OperationsModule, VerificationProfile},
};
use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

/// Program state handler
pub struct Processor;

impl Processor {
    /// Find the authorization profile for the given instruction
    /// NOTE: It might be moved to helpers or constants but keeping in processor makes this more visible and obvious
    fn instruction_verification_profile(
        instruction: &SecurityTokenInstruction,
    ) -> VerificationProfile {
        use SecurityTokenInstruction::*;
        use VerificationProfile::*;

        match instruction {
            InitializeMint | Verify => None,
            InitializeVerificationConfig
            | UpdateVerificationConfig
            | TrimVerificationConfig
            | UpdateMetadata => VerificationProgramsOrMintAuthority,
            Burn | Mint | Pause | Resume | Freeze | Thaw => VerificationPrograms,
        }
    }

    /// Runs the verification process for the given instruction
    /// Explicit cuts the verification overhead if needed
    fn verify<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo],
        ix_discriminator: u8,
        verification_profile: VerificationProfile,
    ) -> Result<&'a [AccountInfo], ProgramError> {
        match verification_profile {
            VerificationProfile::None => Ok(accounts),
            VerificationProfile::VerificationPrograms => {
                VerificationModule::verify_by_programs(program_id, accounts, ix_discriminator)?;
                Ok(&accounts[INSTRUCTION_ACCOUNTS_OFFSET..])
            }
            VerificationProfile::VerificationProgramsOrMintAuthority => {
                VerificationModule::verify_by_strategy(program_id, accounts, ix_discriminator)?;
                Ok(&accounts[INSTRUCTION_ACCOUNTS_OFFSET..])
            }
        }
    }

    /// Processes an instruction
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let (instruction, args_data) =
            SecurityTokenInstruction::parse_instruction(instruction_data)?;

        let verification_profile = Self::instruction_verification_profile(&instruction);
        let instruction_accounts = Self::verify(
            program_id,
            accounts,
            instruction.discriminant(),
            verification_profile,
        )?;

        match instruction {
            SecurityTokenInstruction::InitializeMint => {
                Self::process_initialize_mint(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Verify => {
                Self::process_verify(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::InitializeVerificationConfig => {
                Self::process_initialize_verification_config(
                    program_id,
                    instruction_accounts,
                    args_data,
                )
            }
            SecurityTokenInstruction::UpdateVerificationConfig => {
                Self::process_update_verification_config(
                    program_id,
                    instruction_accounts,
                    args_data,
                )
            }
            SecurityTokenInstruction::TrimVerificationConfig => {
                Self::process_trim_verification_config(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::UpdateMetadata => {
                Self::process_update_metadata(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Mint => {
                Self::process_mint(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Burn => {
                Self::process_burn(program_id, instruction_accounts, args_data)
            }
            SecurityTokenInstruction::Pause => {
                Self::process_pause(program_id, instruction_accounts)
            }
            SecurityTokenInstruction::Resume => {
                Self::process_resume(program_id, instruction_accounts)
            }
            SecurityTokenInstruction::Freeze => {
                Self::process_freeze(program_id, instruction_accounts)
            }
            SecurityTokenInstruction::Thaw => Self::process_thaw(program_id, instruction_accounts),
        }
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
        let args = InitializeMintArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerificationModule::initialize_mint(program_id, accounts, &args)
    }

    fn process_initialize_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args = InitializeVerificationConfigArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::initialize_verification_config(program_id, accounts, &args)
    }

    fn process_update_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args = UpdateVerificationConfigArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerificationModule::update_verification_config(program_id, accounts, &args)
    }

    /// Process TrimVerificationConfig instruction
    fn process_trim_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args = TrimVerificationConfigArgs::try_from_bytes(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::trim_verification_config(program_id, accounts, &args)
    }

    fn process_verify(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args = VerifyArgs::try_from_bytes(args_data)?;
        VerificationModule::verify_instruction(program_id, accounts, &instruction_args)?;
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

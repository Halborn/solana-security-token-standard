use crate::{
    instruction::SecurityTokenInstruction,
    instructions::{
        verification_config::TrimVerificationConfigInstructionArgs, InitializeArgs,
        InitializeVerificationConfigInstructionArgs, UpdateMetadataArgs,
        UpdateVerificationConfigInstructionArgs,
    },
    modules::verification::VerificationModule,
};
use borsh::BorshDeserialize;
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
            SecurityTokenInstruction::UpdateMetadata => {
                Self::process_update_metadata(program_id, accounts, args_data)
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
        }
    }

    fn process_update_metadata(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args = UpdateMetadataArgs::unpack(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerificationModule::update_metadata(program_id, accounts, &args)
    }

    /// Process InitializeMint instruction
    fn process_initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let args =
            InitializeArgs::unpack(args_data).map_err(|_| ProgramError::InvalidInstructionData)?;
        VerificationModule::initialize_mint(program_id, accounts, &args)
    }

    /// Process InitializeVerificationConfig instruction
    fn process_initialize_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args =
            InitializeVerificationConfigInstructionArgs::try_from_slice(args_data)
                .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::initialize_verification_config(
            program_id,
            accounts,
            &instruction_args.args,
        )
    }

    /// Process UpdateVerificationConfig instruction
    fn process_update_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args = UpdateVerificationConfigInstructionArgs::try_from_slice(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::update_verification_config(program_id, accounts, &instruction_args.args)
    }

    /// Process TrimVerificationConfig instruction
    fn process_trim_verification_config(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        let instruction_args = TrimVerificationConfigInstructionArgs::try_from_slice(args_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        VerificationModule::trim_verification_config(program_id, accounts, &instruction_args.args)
    }
}

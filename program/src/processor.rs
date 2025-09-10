use crate::{
    instruction::{
        InitializeArgs, InitializeVerificationConfigInstructionArgs, SecurityTokenInstruction,
        UpdateMetadataArgs,
    },
    modules::verification::VerificationModule,
};
use borsh::BorshDeserialize;
use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};
use pinocchio_log::log;

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
            SecurityTokenInstruction::InitializeVerificationConfig => {
                Self::process_initialize_verification_config(program_id, accounts, rest)
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
            &instruction_args.args.instruction_discriminator,
            &instruction_args.args.program_addresses,
            instruction_args.args.program_count,
        )
    }
}

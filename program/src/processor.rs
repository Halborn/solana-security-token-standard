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
        let (discriminant, rest) = instruction_data.split_first().unwrap();
        match discriminant {
            0 => Self::process_initialize_mint(program_id, accounts, rest),
            1 => Self::process_update_metadata(program_id, accounts, rest),
            2 => Self::process_initialize_verification_config(program_id, accounts, rest),
            _ => Err(ProgramError::InvalidInstructionData),
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

impl From<u8> for SecurityTokenInstruction {
    fn from(value: u8) -> Self {
        match value {
            0 => SecurityTokenInstruction::InitializeMint,
            1 => SecurityTokenInstruction::UpdateMetadata,
            2 => SecurityTokenInstruction::InitializeVerificationConfig,
            _ => SecurityTokenInstruction::InitializeMint,
        }
    }
}

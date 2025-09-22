use crate::{
    instruction::SecurityTokenInstruction,
    instructions::{
        verification_config::TrimVerificationConfigInstructionArgs, InitializeArgs,
        InitializeVerificationConfigInstructionArgs, UpdateMetadataArgs,
        UpdateVerificationConfigInstructionArgs, VerifyArgs,
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
            SecurityTokenInstruction::Verify => {
                Self::process_verify(program_id, accounts, args_data)
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

    /// Process Verify instruction
    fn process_verify(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args_data: &[u8],
    ) -> ProgramResult {
        // Client sends Borsh-serialized data with wrapper structure
        // Let's parse it directly without complex structures

        // Debug: log what we received
        pinocchio_log::log!("Verify instruction received {} bytes", args_data.len());

        // The client sends VerifyInstructionArgs { args: VerifyArgs { ix: u8 } }
        // This gets Borsh-serialized, so we need to deserialize it
        // But since it's just a wrapper around one byte, let's try a simpler approach

        if args_data.len() < 1 {
            return Err(ProgramError::InvalidInstructionData);
        }

        // For now, assume the first byte is our discriminant
        // TODO: Properly deserialize Borsh if needed
        let discriminant = args_data[0];
        let args = VerifyArgs { ix: discriminant };

        // Call the verify function from VerificationModule
        VerificationModule::verify(program_id, accounts, &args)
    }
}

use crate::instruction::SecurityTokenInstruction;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
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
        let instruction = SecurityTokenInstruction::from(instruction_data[0]);

        match instruction {
            SecurityTokenInstruction::InitializeMint => {
                msg!("Instruction: InitializeMint");
                Ok(())
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

use pinocchio::program_error::ProgramError;

use crate::instruction::SecurityTokenInstruction;
use shank::ShankType;

const MAX_INSTRUCTION_DATA_LEN: usize = 10240; // 10KB

/// Arguments for the Verify instruction
#[repr(C)]
#[derive(ShankType)]
pub struct VerifyArgs {
    /// The Security Token instruction discriminant to verify
    pub ix: u8,
    /// The instruction data to verify
    pub instruction_data: Vec<u8>,
}

impl VerifyArgs {
    /// Parse VerifyArgs from instruction data
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 5 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let discriminant = data[0];
        SecurityTokenInstruction::from_discriminant(discriminant)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let vec_len = u32::from_le_bytes(
            data[1..5]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;

        if vec_len > MAX_INSTRUCTION_DATA_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        if data.len() < 5 + vec_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let instruction_data = data[5..5 + vec_len].to_vec();

        Ok(VerifyArgs {
            ix: discriminant,
            instruction_data,
        })
    }
}

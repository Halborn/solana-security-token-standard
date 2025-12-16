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
    /// Minimum length: discriminant (1 byte) + vector length (4 bytes)
    pub const MIN_LEN: usize = 1 + 4;

    /// Parse VerifyArgs from instruction data
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read discriminant (1 byte)
        let discriminant = data[offset];
        SecurityTokenInstruction::from_discriminant(discriminant)
            .ok_or(ProgramError::InvalidInstructionData)?;
        offset += 1;

        // Read vec_len (4 bytes)
        let vec_len = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset += 4;

        if vec_len > MAX_INSTRUCTION_DATA_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        if data.len() < offset + vec_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read instruction_data (vec_len bytes)
        let instruction_data = data[offset..offset + vec_len].to_vec();

        Ok(VerifyArgs {
            ix: discriminant,
            instruction_data,
        })
    }
}

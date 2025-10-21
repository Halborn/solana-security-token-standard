use pinocchio::program_error::ProgramError;

use crate::instruction::SecurityTokenInstruction;
use shank::ShankType;

/// Arguments for the Verify instruction
#[repr(C)]
#[derive(ShankType)]
pub struct VerifyArgs {
    /// The Security Token instruction discriminant to verify
    pub ix: u8,
}

impl VerifyArgs {
    /// Parse VerifyArgs from instruction data
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let discriminant = data[0];
        // Validate that discriminant is valid
        SecurityTokenInstruction::from_discriminant(discriminant)
            .ok_or(ProgramError::InvalidInstructionData)?;

        Ok(VerifyArgs { ix: discriminant })
    }
}

use pinocchio::program_error::ProgramError;

use crate::instruction::SecurityTokenInstruction;

/// Arguments for the Verify instruction
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyArgs {
    /// The Security Token instruction discriminant to verify
    pub ix: u8,
}

impl VerifyArgs {
    /// Parse VerifyArgs from raw instruction data - just one byte
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let discriminant = data[0];
        // Validate that discriminant is valid
        SecurityTokenInstruction::from_discriminant(discriminant)
            .ok_or(ProgramError::InvalidInstructionData)?;

        Ok(VerifyArgs { ix: discriminant })
    }

    /// Get the SecurityTokenInstruction from discriminant
    pub fn get_instruction(&self) -> Result<SecurityTokenInstruction, ProgramError> {
        SecurityTokenInstruction::from_discriminant(self.ix)
            .ok_or(ProgramError::InvalidInstructionData)
    }

    /// Serialize to bytes - just one byte
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.ix]
    }
}

//! Transfer instruction arguments and implementation

use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::program_error::ProgramError;

/// Arguments for Transfer instruction
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct TransferArgs {
    /// Amount to transfer
    pub amount: u64,
}

impl TransferArgs {
    /// Create new TransferArgs
    pub fn new(amount: u64) -> Self {
        Self { amount }
    }

    /// Validate the arguments
    pub fn validate(&self) -> Result<(), ProgramError> {
        if self.amount == 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}
//! Security Token program errors

use pinocchio::program_error::ProgramError;
use thiserror::Error;

/// Errors that may be returned by the Security Token program
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SecurityTokenError {
    /// Verification Errors
    /// Verification program not found
    #[error("Verification program not found")]
    VerificationProgramNotFound = 1,
    /// Not enough accounts for verification
    #[error("Not enough accounts for verification")]
    NotEnoughAccountsForVerification = 2,
    /// Account intersection mismatch
    #[error("Account intersection mismatch")]
    AccountIntersectionMismatch = 3,
    /// Invalid Verification Config PDA
    #[error("Invalid Verification Config PDA")]
    InvalidVerificationConfigPda = 4,
}

impl From<SecurityTokenError> for ProgramError {
    fn from(e: SecurityTokenError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

//! Security Token program errors

use num_derive::FromPrimitive;
use pinocchio::program_error::ProgramError;
use thiserror::Error;

/// Errors that may be returned by the Security Token program
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum SecurityTokenError {
    /// Invalid instruction
    #[error("Invalid instruction")]
    InvalidInstruction = 0,
    /// Not rent exempt
    #[error("Not rent exempt")]
    NotRentExempt = 1,
    /// Expected mint
    #[error("Expected mint")]
    ExpectedMint = 2,
    /// Expected token account
    #[error("Expected token account")]
    ExpectedTokenAccount = 3,
    /// Expected mint authority
    #[error("Expected mint authority")]
    ExpectedMintAuthority = 4,
    /// Invalid mint authority
    #[error("Invalid mint authority")]
    InvalidMintAuthority = 5,
    /// Invalid token owner
    #[error("Invalid token owner")]
    InvalidTokenOwner = 6,
    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed = 7,
    /// Transfer restricted
    #[error("Transfer restricted")]
    TransferRestricted = 8,
    /// Account frozen
    #[error("Account frozen")]
    AccountFrozen = 9,
    /// Token paused
    #[error("Token paused")]
    TokenPaused = 10,
    /// Insufficient compliance
    #[error("Insufficient compliance")]
    InsufficientCompliance = 11,
    /// Invalid verification config
    #[error("Invalid verification config")]
    InvalidVerificationConfig = 12,
    /// Missing verification signature
    #[error("Missing verification signature")]
    MissingVerificationSignature = 13,
    /// Corporate action not found
    #[error("Corporate action not found")]
    CorporateActionNotFound = 14,
    /// Invalid rate configuration
    #[error("Invalid rate configuration")]
    InvalidRateConfiguration = 15,
    /// Receipt already exists
    #[error("Receipt already exists")]
    ReceiptAlreadyExists = 16,
    /// Invalid merkle proof
    #[error("Invalid merkle proof")]
    InvalidMerkleProof = 17,
    /// Distribution already claimed
    #[error("Distribution already claimed")]
    DistributionAlreadyClaimed = 18,
    /// Insufficient balance
    #[error("Insufficient balance")]
    InsufficientBalance = 19,
    /// Math overflow
    #[error("Math overflow")]
    MathOverflow = 20,
    /// Invalid account data
    #[error("Invalid account data")]
    InvalidAccountData = 21,
    /// Account not initialized
    #[error("Account not initialized")]
    AccountNotInitialized = 22,
    /// Account already initialized
    #[error("Account already initialized")]
    AccountAlreadyInitialized = 23,
}

impl From<SecurityTokenError> for ProgramError {
    fn from(e: SecurityTokenError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

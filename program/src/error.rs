//! Security Token program errors

use num_derive::FromPrimitive;
use solana_program::program_error::ProgramError;
use thiserror::Error;

/// Errors that may be returned by the Security Token program
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum SecurityTokenError {
    /// Invalid instruction
    #[error("Invalid instruction")]
    InvalidInstruction,
    /// Not rent exempt
    #[error("Not rent exempt")]
    NotRentExempt,
    /// Expected mint
    #[error("Expected mint")]
    ExpectedMint,
    /// Expected token account
    #[error("Expected token account")]
    ExpectedTokenAccount,
    /// Expected mint authority
    #[error("Expected mint authority")]
    ExpectedMintAuthority,
    /// Invalid mint authority
    #[error("Invalid mint authority")]
    InvalidMintAuthority,
    /// Invalid token owner
    #[error("Invalid token owner")]
    InvalidTokenOwner,
    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,
    /// Transfer restricted
    #[error("Transfer restricted")]
    TransferRestricted,
    /// Account frozen
    #[error("Account frozen")]
    AccountFrozen,
    /// Token paused
    #[error("Token paused")]
    TokenPaused,
    /// Insufficient compliance
    #[error("Insufficient compliance")]
    InsufficientCompliance,
    /// Invalid verification config
    #[error("Invalid verification config")]
    InvalidVerificationConfig,
    /// Missing verification signature
    #[error("Missing verification signature")]
    MissingVerificationSignature,
    /// Corporate action not found
    #[error("Corporate action not found")]
    CorporateActionNotFound,
    /// Invalid rate configuration
    #[error("Invalid rate configuration")]
    InvalidRateConfiguration,
    /// Receipt already exists
    #[error("Receipt already exists")]
    ReceiptAlreadyExists,
    /// Invalid merkle proof
    #[error("Invalid merkle proof")]
    InvalidMerkleProof,
    /// Distribution already claimed
    #[error("Distribution already claimed")]
    DistributionAlreadyClaimed,
    /// Insufficient balance
    #[error("Insufficient balance")]
    InsufficientBalance,
    /// Math overflow
    #[error("Math overflow")]
    MathOverflow,
    /// Invalid account data
    #[error("Invalid account data")]
    InvalidAccountData,
    /// Account not initialized
    #[error("Account not initialized")]
    AccountNotInitialized,
    /// Account already initialized
    #[error("Account already initialized")]
    AccountAlreadyInitialized,
}

impl From<SecurityTokenError> for ProgramError {
    fn from(e: SecurityTokenError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

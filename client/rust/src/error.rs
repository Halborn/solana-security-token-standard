//! Error types for Security Token client - Phase 1: Foundation

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityTokenClientError {
    #[error("Program error: {0}")]
    ProgramError(String),

    #[error("Invalid data")]
    InvalidData,

    #[error("Unauthorized")]
    Unauthorized,
}

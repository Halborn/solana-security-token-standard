//! Security Token Rust Client
//!
//! This crate provides a basic Rust client for interacting with the Security Token program.

pub mod error;

pub use error::SecurityTokenClientError;

// Re-export program types
pub use security_token_program::{
    id as program_id,
    instruction::SecurityTokenInstruction,
    state::{SecurityTokenMint, VerificationConfig, VerificationStatus},
};

/// Client library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Basic client struct
pub struct SecurityTokenClient {
    /// Program ID for the security token program
    pub program_id: solana_program::pubkey::Pubkey,
}

impl SecurityTokenClient {
    /// Create a new client instance
    pub fn new() -> Self {
        Self {
            program_id: program_id(),
        }
    }
}

impl Default for SecurityTokenClient {
    fn default() -> Self {
        Self::new()
    }
}

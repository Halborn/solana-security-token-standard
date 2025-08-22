//! Security Token Client
//!
//! This crate provides a Rust client for interacting with the Security Token Standard program.
//! It includes generated instruction builders, types, and error handling for the security token program.

pub mod generated;

// Re-export commonly used items for convenience
pub use generated::{
    errors::SecurityTokenError, instructions::*, programs::SECURITY_TOKEN_ID, types::*,
};

pub use solana_account_info::AccountInfo;
pub use solana_instruction::{AccountMeta, Instruction};
/// Convenience re-exports from solana crates
pub use solana_pubkey::Pubkey;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_id() {
        // Verify the program ID is accessible
        let _program_id = SECURITY_TOKEN_ID;
    }
}

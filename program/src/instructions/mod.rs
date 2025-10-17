//! Instruction argument structures and implementations for the Security Token Program
//!
//! Contains optimized wrappers for SPL Token 2022 operations

/// Create Rate account instruction arguments and implementations
pub mod create_rate_account;
/// Initialize mint instruction arguments and implementations
pub mod initialize_mint;
/// Token wrapper utilities
pub mod token_wrappers;
/// Update metadata instruction arguments and implementations
pub mod update_metadata;
/// Verification configuration instruction arguments and implementations
pub mod verification_config;
/// Verify instruction arguments and implementations
pub mod verify;

// Re-export all public types for easy access
pub use create_rate_account::*;
pub use initialize_mint::*;
pub use token_wrappers::*;
pub use update_metadata::*;
pub use verification_config::*;
pub use verify::VerifyArgs;

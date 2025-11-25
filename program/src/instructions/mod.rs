//! Instruction argument structures and implementations for the Security Token Program
//!
//! Contains optimized wrappers for SPL Token 2022 operations

mod proof_account;
mod rate_account;
mod receipt_account;

/// Create Proof account instruction arguments and implementations
pub mod create_proof_account {
    pub use super::proof_account::create_proof_account::*;
}
/// Update Proof account instruction arguments and implementations
pub mod update_proof_account {
    pub use super::proof_account::update_proof_account::*;
}
/// Update Rate account instruction arguments and implementations
pub mod update_rate_account {
    pub use super::rate_account::update_rate_account::*;
}
/// Create Rate account instruction arguments and implementations
pub mod create_rate_account {
    pub use super::rate_account::create_rate_account::*;
}
/// Close Rate account instruction arguments and implementations
pub mod close_rate_account {
    pub use super::rate_account::close_rate_account::*;
}
/// Claim instruction arguments and implementations
pub mod claim_distribution;
/// Close Receipt account instruction arguments and implementations
pub mod close_receipt_account {
    pub use super::receipt_account::close_action_receipt_account::*;
    pub use super::receipt_account::close_claim_receipt_account::*;
}
/// Convert instruction arguments and implementations
pub mod convert;
/// CreateDistributionEscrow instruction arguments and implementations
pub mod create_distribution_escrow;
/// Initialize mint instruction arguments and implementations
pub mod initialize_mint;
/// Split instruction arguments and implementations
pub mod split;
/// Token wrapper utilities
pub mod token_wrappers;
/// Update metadata instruction arguments and implementations
pub mod update_metadata;
/// Verification configuration instruction arguments and implementations
pub mod verification_config;
/// Verify instruction arguments and implementations
pub mod verify;

// Re-export all public types for easy access
pub use claim_distribution::*;
pub use close_rate_account::*;
pub use close_receipt_account::*;
pub use convert::*;
pub use create_distribution_escrow::*;
pub use create_proof_account::*;
pub use create_rate_account::*;
pub use initialize_mint::*;
pub use split::*;
pub use token_wrappers::*;
pub use update_metadata::*;
pub use update_proof_account::*;
pub use update_rate_account::*;
pub use verification_config::*;
pub use verify::VerifyArgs;

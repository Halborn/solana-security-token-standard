//! State structures for Security Token Standard
//!
//! Contains all account structures and data types used by the Security Token program:
//! - Mint and token account configurations
//! - Verification configurations and status
//! - Corporate action rates and receipts

pub mod verification;

// Re-export all structures for convenience
pub use verification::*;

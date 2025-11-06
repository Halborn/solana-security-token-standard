//! Security Token Program modules according to specification
//!
//! Two main components:
//! - Verification Module: validates authorization and compliance
//! - Operations Module: executes token operations

/// Shared utilities and types used across modules.
pub mod account_checks;
pub mod constants;
pub mod operations;
/// Utility functions
pub mod token_helpers;
pub mod utils;
pub mod verification;

// Re-export modules for convenience
pub use account_checks::*;
pub use constants::*;
pub use operations::*;
pub use token_helpers::*;
pub use utils::*;
pub use verification::*;

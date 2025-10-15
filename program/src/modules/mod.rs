//! Security Token Program modules according to specification
//!
//! Two main components:
//! - Verification Module: validates authorization and compliance
//! - Operations Module: executes token operations

pub mod operations;
/// Shared utilities and types used across modules.
pub mod shared;
/// Utility functions
pub mod utils;
pub mod verification;
pub mod constants;

// Re-export modules for convenience
pub use operations::*;
pub use shared::*;
pub use utils::*;
pub use constants::*;
pub use verification::*;

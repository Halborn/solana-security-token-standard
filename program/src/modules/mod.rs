//! Security Token Program modules according to specification
//!
//! Two main components:
//! - Verification Module: validates authorization and compliance
//! - Operations Module: executes token operations

pub mod operations;
/// Shared utilities and types used across modules.
pub mod shared;
pub mod verification;

// Re-export modules for convenience
pub use operations::*;
pub use shared::*;
pub use verification::*;

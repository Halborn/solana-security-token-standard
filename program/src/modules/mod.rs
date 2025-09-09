//! Security Token Program modules according to specification
//!
//! Two main components:
//! - Verification Module: validates authorization and compliance
//! - Operations Module: executes token operations

pub mod operations;
pub mod verification;

// Re-export modules for convenience
pub use operations::*;
pub use verification::*;

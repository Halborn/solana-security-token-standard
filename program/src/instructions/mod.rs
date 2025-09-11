//! Instruction argument structures and implementations for the Security Token Program
//! 
//! Contains optimized wrappers for SPL Token 2022 operations
//! that work within SBF constraints (no Vec, no heap allocation)

/// Corporate action instruction arguments and implementations
pub mod corporate_actions;
/// Initialize mint instruction arguments and implementations
pub mod initialize_mint;
/// Token wrapper utilities for SBF compatibility
pub mod token_wrappers;
/// Update metadata instruction arguments and implementations
pub mod update_metadata;
/// Verification configuration instruction arguments and implementations
pub mod verification_config;

// Re-export all public types for easy access
pub use corporate_actions::*;
pub use initialize_mint::*;
pub use token_wrappers::*;
pub use update_metadata::*;
pub use verification_config::*;

//! SBF-compatible instruction wrappers
//! 
//! Contains optimized wrappers for SPL Token 2022 operations
//! that work within SBF constraints (no Vec, no heap allocation)

pub mod token_wrappers;
pub mod corporate_actions;

// Re-export all wrappers
pub use token_wrappers::*;
pub use corporate_actions::*;

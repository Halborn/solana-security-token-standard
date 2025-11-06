//! State structures for Security Token Standard
//!
//! Contains all account structures and data types used by the Security Token program:
//! - Mint and token account configurations
//! - Verification configurations
//! - Discriminator configurations

pub mod discriminator;
pub mod mint_authority;
pub mod program_account;
pub mod rate;
pub mod verification;

// Re-export all structures for convenience
pub use discriminator::*;
pub use mint_authority::*;
pub use program_account::*;
pub use rate::*;
pub use verification::*;

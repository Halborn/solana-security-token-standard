//! Security Token Standard program for Solana blockchain
//!
//! This program provides a foundation for security tokens with compliance features.

#![allow(clippy::arithmetic_side_effects)]
#![deny(missing_docs)]

/// Constants
pub mod constants;
/// Program entrypoint
pub mod entrypoint;
/// Error types
pub mod error;
/// Instruction definitions
pub mod instruction;
/// Instruction wrappers
pub mod instructions;
/// Macros used throughout the Security Token program
pub mod macros;
/// Security Token program modules (verification & operations)
pub mod modules;
/// Instruction processor
pub mod processor;
/// State structures
pub mod state;
/// Utility functions
pub mod utils;
use pinocchio_pubkey::declare_id;

declare_id!("Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH");

//! Security Token Standard program for Solana blockchain
//!
//! This program provides a foundation for security tokens with compliance features.

#![allow(clippy::arithmetic_side_effects)]
#![deny(missing_docs)]

/// Program entrypoint
pub mod entrypoint;
/// Error types
pub mod error;
/// Instruction definitions
pub mod instruction;
/// SBF-compatible instruction wrappers
pub mod instructions;
/// Security Token program modules (verification & operations)
pub mod modules;
/// Instruction processor
pub mod processor;
/// State structures
pub mod state;
/// Utility functions
pub mod utils;
use pinocchio_pubkey::declare_id;

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};

declare_id!("Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH");

/// Program entrypoint implementation
#[cfg(not(feature = "no-entrypoint"))]
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::Processor::process(program_id, accounts, instruction_data)
}

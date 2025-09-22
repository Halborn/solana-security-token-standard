//! Program entrypoint

#![allow(unexpected_cfgs)]

use crate::processor::Processor;
use pinocchio::{
    account_info::AccountInfo, default_panic_handler, no_allocator, program_entrypoint,
    pubkey::Pubkey, ProgramResult,
};

program_entrypoint!(process_instruction);
default_panic_handler!();
no_allocator!();

/// The entrypoint to the Security Token program
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if let Err(error) = Processor::process(program_id, accounts, instruction_data) {
        Err(error)
    } else {
        Ok(())
    }
}

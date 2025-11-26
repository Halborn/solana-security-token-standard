//! Program entrypoint

#![allow(unexpected_cfgs)]

use crate::processor::Processor;
use pinocchio::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};
use pinocchio::entrypoint;

entrypoint!(process_instruction);

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

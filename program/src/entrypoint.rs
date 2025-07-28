//! Program entrypoint

use crate::{error::SecurityTokenError, processor::Processor};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, msg, pubkey::Pubkey};

solana_program::entrypoint!(process_instruction);

/// The entrypoint to the Security Token program
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if let Err(error) = Processor::process(program_id, accounts, instruction_data) {
        // log the error to the program logs
        msg!("Security Token Program error: {}", error);
        Err(error)
    } else {
        Ok(())
    }
}

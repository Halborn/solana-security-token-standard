//! Security Token transfer hook placeholder implementation
#![allow(unexpected_cfgs)]
use pinocchio::{
    account_info::AccountInfo, entrypoint, pubkey::Pubkey, ProgramResult,
};
use pinocchio_log::log;
use pinocchio_pubkey::declare_id;

// TODO: replace with the finalized program ID generated for the transfer hook deployment.
declare_id!("DTUuEirVJFg53cKgyTPKtVgvi5SV5DCDQpvbmdwBtYdd");

entrypoint!(process_instruction);

/// Placeholder processor for the transfer hook program. Currently it only logs the
/// invocation and returns success so integration work can proceed.
fn process_instruction(
    program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    log!("Transfer hook invoked (placeholder)");
    log!("Program ID: {}", program_id);
    log!("Instruction data ({} bytes)", instruction_data.len());

    // Future implementation will validate accounts, execute verification CPIs, and
    // forward control back to the Security Token program.
    Ok(())
}

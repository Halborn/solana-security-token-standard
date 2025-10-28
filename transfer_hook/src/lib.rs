//! Security Token transfer hook placeholder implementation
#![allow(unexpected_cfgs)]
use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
};
use pinocchio_log::log;
use pinocchio_pubkey::{declare_id, pubkey};

// NOTE: Spl token array discriminator length
// https://github.com/solana-program/libraries/blob/main/discriminator/src/discriminator.rs
pub const ARRAY_DISCRIMINATOR_LENGTH: usize = 8;
pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH");
pub static PERMANENT_DELEGATE_SEED: &[u8] = b"mint.permanent_delegate";
pub const TRANSFER_HOOK_EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];

// NOTE: Replace with the finalized program ID generated for the transfer hook deployment.
declare_id!("DTUuEirVJFg53cKgyTPKtVgvi5SV5DCDQpvbmdwBtYdd");

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    log!("Transfer hook invoked (placeholder)");
    log!("Program ID: {}", program_id);
    if instruction_data.len() < ARRAY_DISCRIMINATOR_LENGTH {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (discriminator, rest) = instruction_data.split_at(ARRAY_DISCRIMINATOR_LENGTH);

    if discriminator != TRANSFER_HOOK_EXECUTE_DISCRIMINATOR {
        return Err(ProgramError::InvalidInstructionData);
    }

    let [_from, mint, _to, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let (expected_pda, _bump) = find_program_address(
        &[b"mint.permanent_delegate", mint.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    if authority.key() != &expected_pda {
        return Err(ProgramError::IllegalOwner);
    }

    let amount = rest
        .get(..8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ProgramError::InvalidInstructionData)?;
    log!("Transfer amount: {}", amount);

    Ok(())
}

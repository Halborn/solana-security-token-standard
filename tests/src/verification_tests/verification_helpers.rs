use solana_pubkey::Pubkey;
use solana_sdk::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
};

// Constants for verification program behavior
pub const VERIFICATION_PASS: u8 = 0x01;
pub const VERIFICATION_FAIL: u8 = 0x02;

// Simple dummy program processor that can succeed or fail based on instruction data
pub fn dummy_program_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // The first byte determines instruction id
    // The second byte determines success (VERIFICATION_PASS) or failure (VERIFICATION_FAIL or 0)
    msg!("Dummy program called with {} bytes", instruction_data.len());

    // If instruction data is empty or has less than 2 bytes, pass by default (for CPI mode)
    if instruction_data.len() < 2 {
        msg!("Dummy program: default success (no verification byte)");
        return Ok(());
    }

    // Check second byte for explicit pass/fail
    if instruction_data[1] == VERIFICATION_FAIL || instruction_data[1] == 0 {
        msg!("Dummy program: intentional failure");
        return Err(ProgramError::Custom(9999));
    }

    msg!("Dummy program: success");
    Ok(())
}

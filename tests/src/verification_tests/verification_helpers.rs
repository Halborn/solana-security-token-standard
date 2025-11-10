use solana_pubkey::Pubkey;
use solana_sdk::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
};

// Simple dummy program processor
pub fn dummy_program_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Dummy program called with {} bytes", instruction_data.len());
    msg!("Dummy program: success");
    Ok(())
}

pub fn failing_dummy_program_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Failing dummy program called");
    Err(ProgramError::Custom(0x1111))
}

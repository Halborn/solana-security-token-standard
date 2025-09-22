use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError, pubkey::Pubkey,
};

// Dummy program entry point
entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Dummy verification program called");
    
    if instruction_data.is_empty() {
        msg!("No instruction data provided - returning success");
        return Ok(());
    }
    
    // First byte determines behavior:
    // 0 = success
    // anything else = failure
    let behavior = instruction_data[0];
    
    if behavior == 0 {
        msg!("Dummy verification program: SUCCESS");
        Ok(())
    } else {
        msg!("Dummy verification program: FAILURE (code: {})", behavior);
        Err(ProgramError::Custom(behavior as u32))
    }
}
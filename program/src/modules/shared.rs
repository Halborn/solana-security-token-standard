use crate::acc_info_as_str;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use pinocchio_log::log;

/// Verify account as a signer, returning an error if it is not or if it is not writable while
/// expected to be.
///
/// # Arguments
/// * `info` - The account to verify.
/// * `expect_writable` - Whether the account should be writable
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_signer(info: &AccountInfo, expect_writable: bool) -> Result<(), ProgramError> {
    if !info.is_signer() {
        log!("Account {} is not a signer", acc_info_as_str!(info));
        return Err(ProgramError::MissingRequiredSignature);
    }
    if expect_writable && !info.is_writable() {
        log!("Signer {} is not writable", acc_info_as_str!(info));
        return Err(ProgramError::Immutable);
    }

    Ok(())
}

/// Verify account's owner.
///
/// # Arguments
/// * `info` - The account to verify.
/// * `owner` - The expected owner of the account.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_owner(info: &AccountInfo, owner: &Pubkey) -> Result<(), ProgramError> {
    if !info.is_owned_by(owner) {
        log!(
            "Owner of {} does not match expected owner",
            acc_info_as_str!(info),
        );
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// Verify account as system program, returning an error if it is not.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_system_program(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.key().ne(&pinocchio_system::ID) {
        log!(
            "Account {} is not the system program",
            acc_info_as_str!(info)
        );
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}

/// Verify account as Token 2022 program, returning an error if it is not.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_token22_program(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.key().ne(&pinocchio_token_2022::ID) {
        log!(
            "Account {} is not the Token 2022 program",
            acc_info_as_str!(info),
        );
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}

/// Verify account as instructions sysvar, returning an error if it is not.
pub fn verify_instructions_sysvar(info: &AccountInfo) -> Result<(), ProgramError> {
    if info
        .key()
        .ne(&pinocchio::sysvars::instructions::INSTRUCTIONS_ID)
    {
        log!(
            "Account {} is not the instructions sysvar",
            acc_info_as_str!(info)
        );
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}

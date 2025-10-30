use crate::acc_info_as_str;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use pinocchio_log::log;

/// Verify account as writable
/// expected to be.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_writable(info: &AccountInfo) -> Result<(), ProgramError> {
    if !info.is_writable() {
        log!("Account {} is not writable", acc_info_as_str!(info));
        return Err(ProgramError::Immutable);
    }
    Ok(())
}

/// Verify account as a signer
/// expected to be.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_signer(info: &AccountInfo) -> Result<(), ProgramError> {
    if !info.is_signer() {
        log!("Account {} is not a signer", acc_info_as_str!(info));
        return Err(ProgramError::MissingRequiredSignature);
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
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
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

/// Verify account as rent sysvar, returning an error if it is not.
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_rent_sysvar(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.key().ne(&pinocchio::sysvars::rent::RENT_ID) {
        log!("Account {} is not the rent sysvar", acc_info_as_str!(info));
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}

/// Verify mint info in the operation. It must match the verified mint info.
///
/// # Arguments
/// * `verified_mint_info` - The initial verified Mint account.
/// * `operation_mint_info` - The Mint account from instruction operation.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_operation_mint_info(
    verified_mint_info: &AccountInfo,
    operation_mint_info: &&AccountInfo,
) -> Result<(), ProgramError> {
    if operation_mint_info.key().ne(verified_mint_info.key()) {
        log!(
            "Mint {} in the operation does not match verified Mint",
            acc_info_as_str!(operation_mint_info),
        );
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// Verify account is not initialized.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_account_not_initialized(info: &AccountInfo) -> Result<(), ProgramError> {
    if !info.data_is_empty() || info.lamports() > 0 || !info.is_owned_by(&pinocchio_system::id()) {
        log!("Account {} already exists", acc_info_as_str!(info));
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    Ok(())
}

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use pinocchio_log::log;

use crate::acc_info_as_str;

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
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

/// Verify account's owner and account mutability.
///
/// # Arguments
/// * `info` - The account to verify.
/// * `owner` - The expected owner of the account.
/// * `expect_writable` - Whether the account is expected to be writable.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
pub fn verify_owner_mutability(
    info: &AccountInfo,
    owner: &Pubkey,
    expect_writable: bool,
) -> Result<(), ProgramError> {
    if unsafe { info.owner() } != owner {
        log!(
            "Owner of {} does not match expected owner",
            acc_info_as_str!(info),
        );
        return Err(ProgramError::InvalidAccountOwner);
    }
    if expect_writable && !info.is_writable() {
        log!(
            "{} does not have the right write access",
            acc_info_as_str!(info),
        );
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

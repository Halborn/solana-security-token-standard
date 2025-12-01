#[cfg(feature = "debug-logs")]
use crate::acc_info_as_str;
use crate::{constants::TRANSFER_HOOK_PROGRAM_ID, debug_log};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// Verify account as writable
/// expected to be.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
#[inline(always)]
pub fn verify_writable(info: &AccountInfo) -> Result<(), ProgramError> {
    if !info.is_writable() {
        debug_log!("Account {} is not writable", acc_info_as_str!(info));
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
#[inline(always)]
pub fn verify_signer(info: &AccountInfo) -> Result<(), ProgramError> {
    if !info.is_signer() {
        debug_log!("Account {} is not a signer", acc_info_as_str!(info));
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
#[inline(always)]
pub fn verify_owner(info: &AccountInfo, owner: &Pubkey) -> Result<(), ProgramError> {
    if !info.is_owned_by(owner) {
        debug_log!(
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
#[inline(always)]
pub fn verify_system_program(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.key().ne(&pinocchio_system::ID) {
        debug_log!(
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
#[inline(always)]
pub fn verify_token22_program(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.key().ne(&pinocchio_token_2022::ID) {
        debug_log!(
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
#[inline(always)]
pub fn verify_instructions_sysvar(info: &AccountInfo) -> Result<(), ProgramError> {
    if info
        .key()
        .ne(&pinocchio::sysvars::instructions::INSTRUCTIONS_ID)
    {
        debug_log!(
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
#[inline(always)]
pub fn verify_rent_sysvar(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.key().ne(&pinocchio::sysvars::rent::RENT_ID) {
        debug_log!("Account {} is not the rent sysvar", acc_info_as_str!(info));
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}

/// Verify that two mint account keys match to prevent mint substitution attacks.
///
/// This security check ensures that operations authorized for one mint cannot be
/// executed on a different mint account.
///
/// # Arguments
/// * `verified_mint_info` - The initial verified Mint account.
/// * `operation_mint_info` - The Mint account from instruction operation.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
#[inline(always)]
pub fn verify_mint_keys_match(
    verified_mint_info: &AccountInfo,
    operation_mint_info: &&AccountInfo,
) -> Result<(), ProgramError> {
    if operation_mint_info.key().ne(verified_mint_info.key()) {
        debug_log!(
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
#[inline(always)]
pub fn verify_account_not_initialized(info: &AccountInfo) -> Result<(), ProgramError> {
    if !info.data_is_empty() || info.lamports() > 0 {
        debug_log!("Account {} already exists", acc_info_as_str!(info));
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    Ok(())
}

/// Verify account is initialized.
///
/// # Arguments
/// * `info` - The account to verify.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
#[inline(always)]
pub fn verify_account_initialized(info: &AccountInfo) -> Result<(), ProgramError> {
    if info.data_is_empty() || info.lamports() == 0 {
        debug_log!("Account {} is not initialized", acc_info_as_str!(info));
        return Err(ProgramError::UninitializedAccount);
    }
    Ok(())
}

/// Verify that provided and expected PDA keys match.
///
/// This check ensures that the PDA account provided in the instruction matches
/// the PDA derived by the program, preventing account substitution attacks.
///
/// # Arguments
/// * `provided_pda` - The account provided in the instruction.
/// * `expected_pda` - The account derived and expected by the program.
///
/// # Returns
/// * `Result<(), ProgramError>` - The result of the operation
#[inline(always)]
pub fn verify_pda_keys_match(
    provided_pda: &Pubkey,
    expected_pda: &Pubkey,
) -> Result<(), ProgramError> {
    if provided_pda.ne(expected_pda) {
        debug_log!(
            "Invalid PDA account. Expected: {}, Provided: {}",
            expected_pda,
            provided_pda
        );
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

#[inline(always)]
pub fn verify_transfer_hook_program(transfer_hook_pda: &AccountInfo) -> Result<(), ProgramError> {
    if transfer_hook_pda.key().ne(&TRANSFER_HOOK_PROGRAM_ID) {
        debug_log!(
            "Account {} is not the STP transfer hook",
            acc_info_as_str!(transfer_hook_pda)
        );
        return Err(ProgramError::IncorrectProgramId);
    }

    Ok(())
}

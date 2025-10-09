use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use pinocchio_log::log;

use crate::{acc_info_as_str, state::MintAuthority, utils};

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

/// Verify that the provided signer corresponds to the original mint authority PDA.
///
/// This routine performs the following checks:
/// * The candidate authority is a signer (and optionally writable when required).
/// * The mint authority PDA is owned by the current program and writable when required.
/// * The PDA matches the derivation using the candidate signer and mint address.
/// * The serialized `MintAuthority` state stored in the PDA matches the mint, creator, and bump.
///
/// # Arguments
/// * `program_id` - Current program id (used for PDA derivation and owner checks).
/// * `mint_info` - SPL mint account associated with the security token.
/// * `mint_authority` - PDA account storing `MintAuthority` state.
/// * `candidate_authority` - Account claiming to be the original mint authority (must sign).
/// * `expect_authority_writable` - Whether the mint authority PDA is expected to be writable.
pub fn verify_mint_authority(
    program_id: &Pubkey,
    mint_info: &AccountInfo,
    mint_authority: &AccountInfo,
    candidate_authority: &AccountInfo,
    expect_authority_writable: bool,
) -> Result<(), ProgramError> {
    verify_signer(candidate_authority, false)?;
    verify_owner(mint_authority, program_id)?;

    if expect_authority_writable && !mint_authority.is_writable() {
        log!(
            "Mint authority account {} is not writable",
            acc_info_as_str!(mint_authority)
        );
        return Err(ProgramError::Immutable);
    }

    let (expected_pda, expected_bump) =
        utils::find_mint_authority_pda(mint_info.key(), candidate_authority.key(), program_id);

    if mint_authority.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let data = mint_authority.try_borrow_data()?;
    if data.len() < MintAuthority::LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    let mint_authority_state = MintAuthority::try_from_bytes(&data)?;

    if mint_authority_state.mint != *mint_info.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    if mint_authority_state.mint_creator != *candidate_authority.key() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if mint_authority_state.bump != expected_bump {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

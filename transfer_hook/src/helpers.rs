use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::find_program_address,
    ProgramResult,
};

use super::SECURITY_TOKEN_PROGRAM_ID;

// Security Token PDA seeds.
const PERMANENT_DELEGATE_SEED: &[u8] = b"mint.permanent_delegate";

// Token-2022 account layout and extension identifiers.
const TOKEN_ACCOUNT_BASE_LEN: usize = 165;
const TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;
const TOKEN_ACCOUNT_STATE_INITIALIZED: u8 = 1;
const TOKEN_ACCOUNT_TYPE_OFFSET: usize = TOKEN_ACCOUNT_BASE_LEN;
const TOKEN_ACCOUNT_TLV_OFFSET: usize = TOKEN_ACCOUNT_TYPE_OFFSET + 1;
const TOKEN_ACCOUNT_TYPE: u8 = 2;
const TRANSFER_HOOK_ACCOUNT_EXTENSION_TYPE: u16 = 15;

/// Detects a forced transfer already authorized by Security Token Core.
pub(super) fn is_permanent_delegate_transfer(
    mint: &AccountInfo,
    authority: &AccountInfo,
    extra_accounts: &[AccountInfo],
) -> Result<bool, ProgramError> {
    let (permanent_delegate_pda, _bump) = find_program_address(
        &[PERMANENT_DELEGATE_SEED, mint.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );
    // NOTE: Permanent delegate with no extra accounts means security token program call
    Ok(authority.key() == &permanent_delegate_pda && extra_accounts.is_empty())
}

/// Validates that a token account belongs to the active Token-2022 transfer.
pub(super) fn validate_transferring_token_account(
    token_account: &AccountInfo,
    mint: &AccountInfo,
) -> ProgramResult {
    // A direct caller can manufacture the hook account list, so require Token-2022 ownership,
    // the expected mint, an initialized state, and the transient transferring marker.
    if !token_account.is_owned_by(&pinocchio_token_2022::ID) {
        return Err(ProgramError::IllegalOwner);
    }
    let data = token_account.try_borrow_data()?;
    if data.len() <= TOKEN_ACCOUNT_TLV_OFFSET
        || data.get(..32) != Some(mint.key().as_ref())
        || data.get(TOKEN_ACCOUNT_STATE_OFFSET) != Some(&TOKEN_ACCOUNT_STATE_INITIALIZED)
        || data.get(TOKEN_ACCOUNT_TYPE_OFFSET) != Some(&TOKEN_ACCOUNT_TYPE)
    {
        return Err(ProgramError::InvalidAccountData);
    }

    validate_transferring_marker(&data)
}

/// Finds and validates the transient Transfer Hook marker in account TLV data.
fn validate_transferring_marker(data: &[u8]) -> ProgramResult {
    // Token-2022 sets this marker only while invoking the hook for a transfer. A direct caller
    // cannot forge it because Token-2022 owns the source and destination account data.
    let mut offset = TOKEN_ACCOUNT_TLV_OFFSET;
    while offset < data.len() {
        let header_end = offset
            .checked_add(4)
            .ok_or(ProgramError::InvalidAccountData)?;
        let header = data
            .get(offset..header_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        let extension_type = u16::from_le_bytes(
            header[..2]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let extension_len = u16::from_le_bytes(
            header[2..]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;
        if extension_type == 0 && extension_len == 0 {
            break;
        }
        let value_end = header_end
            .checked_add(extension_len)
            .ok_or(ProgramError::InvalidAccountData)?;
        let value = data
            .get(header_end..value_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        if extension_type == TRANSFER_HOOK_ACCOUNT_EXTENSION_TYPE {
            return if value == [1] {
                Ok(())
            } else {
                Err(ProgramError::InvalidAccountData)
            };
        }
        offset = value_end;
    }
    Err(ProgramError::InvalidAccountData)
}

/// Reads a little-endian `u32` and advances the input offset.
pub(super) fn read_u32(data: &[u8], offset: &mut usize) -> Result<usize, ProgramError> {
    let end = offset
        .checked_add(4)
        .ok_or(ProgramError::InvalidAccountData)?;
    let value = u32::from_le_bytes(
        data.get(*offset..end)
            .ok_or(ProgramError::InvalidAccountData)?
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    ) as usize;
    *offset = end;
    Ok(value)
}

/// Reads a canonical boolean and advances the input offset.
pub(super) fn read_bool(data: &[u8], offset: &mut usize) -> Result<bool, ProgramError> {
    let value = *data.get(*offset).ok_or(ProgramError::InvalidAccountData)?;
    *offset = offset
        .checked_add(1)
        .ok_or(ProgramError::InvalidAccountData)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProgramError::InvalidAccountData),
    }
}

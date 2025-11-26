//! Utility functions for PDA derivation and common operations

use crate::token22_extensions::{
    metadata_pointer::MetadataPointer, pausable::Pausable, permanent_delegate::PermanentDelegate,
    scaled_ui_amount::ScaledUiAmountConfig, transfer_hook::TransferHook, Extension, ExtensionType,
    EXTENSIONS_PADDING, EXTENSION_LENGTH_LEN, EXTENSION_START_OFFSET, EXTENSION_TYPE_LEN,
};
use pinocchio::{
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
};
use pinocchio_token_2022::state::Mint;

use crate::{
    constants::{seeds, ACTION_ID_LEN, TRANSFER_HOOK_PROGRAM_ID},
    instructions::TokenMetadataArgs,
};

pub fn find_extra_account_metas_pda(mint: &Pubkey) -> (Pubkey, u8) {
    find_program_address(
        &[seeds::EXTRA_ACCOUNT_METAS, mint.as_ref()],
        &TRANSFER_HOOK_PROGRAM_ID,
    )
}

/// Find PDA for verification config
pub fn find_verification_config_pda(
    mint: &Pubkey,
    instruction_discriminator: u8,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    find_program_address(
        &[
            seeds::VERIFICATION_CONFIG,
            mint.as_ref(),
            &[instruction_discriminator],
        ],
        program_id,
    )
}

/// Derive mint authority PDA
/// Seeds: ["mint.authority", mint_pubkey, creator_pubkey]
pub fn find_mint_authority_pda(
    mint: &Pubkey,
    creator: &Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    find_program_address(
        &[seeds::MINT_AUTHORITY, mint.as_ref(), creator.as_ref()],
        program_id,
    )
}

/// Derive pause authority PDA
/// Seeds: ["mint.pause_authority", mint_pubkey]
pub fn find_pause_authority_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[seeds::PAUSE_AUTHORITY, mint.as_ref()], program_id)
}

/// Derive freeze authority PDA
/// Seeds: ["mint.freeze_authority", mint_pubkey]
pub fn find_freeze_authority_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[seeds::FREEZE_AUTHORITY, mint.as_ref()], program_id)
}

/// Derive transfer hook PDA
/// Seeds: ["mint.transfer_hook", mint_pubkey]
pub fn find_transfer_hook_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[seeds::TRANSFER_HOOK, mint.as_ref()], program_id)
}

/// Derive permanent delegate PDA
/// Seeds: ["mint.permanent_delegate", mint_pubkey]
pub fn find_permanent_delegate_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[seeds::PERMANENT_DELEGATE, mint.as_ref()], program_id)
}

/// Derive account delegate PDA
/// Seeds: ["account.delegate", account_pubkey]
pub fn find_account_delegate_pda(account: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[seeds::ACCOUNT_DELEGATE, account.as_ref()], program_id)
}

/// Derive rate PDA
/// Seeds: ["security_token.accounts.rate", action_id, mint_from, mint_to]
pub fn find_rate_pda(
    action_id: u64,
    mint_from: &Pubkey,
    mint_to: &Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    find_program_address(
        &[
            seeds::RATE_ACCOUNT,
            action_id.to_le_bytes().as_ref(),
            mint_from.as_ref(),
            mint_to.as_ref(),
        ],
        program_id,
    )
}
/// Derive receipt PDA
/// Seeds: ["receipt", mint, action_id]
pub fn find_receipt_pda(mint: &Pubkey, action_id: u64, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(
        &[
            seeds::RECEIPT_ACCOUNT,
            mint.as_ref(),
            action_id.to_le_bytes().as_ref(),
        ],
        program_id,
    )
}

/// Parse additional metadata from raw bytes in TLV format
/// Calls the provided callback for each key-value pair found
pub fn parse_additional_metadata<F>(data: &[u8], mut callback: F) -> Result<(), ProgramError>
where
    F: FnMut(&str, &str) -> Result<(), ProgramError>,
{
    let mut offset = 0;

    while offset < data.len() {
        // Read key length (4 bytes)
        if offset + 4 > data.len() {
            break;
        }
        let key_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        // Validate key length
        if key_len > 256 {
            // Reasonable limit for metadata keys
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read key
        if offset + key_len > data.len() {
            break;
        }
        let key_bytes = &data[offset..offset + key_len];
        let key =
            core::str::from_utf8(key_bytes).map_err(|_| ProgramError::InvalidInstructionData)?;
        offset += key_len;

        // Read value length (4 bytes)
        if offset + 4 > data.len() {
            break;
        }
        let value_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        // Validate value length
        if value_len > 1024 {
            // Reasonable limit for metadata values
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read value
        if offset + value_len > data.len() {
            break;
        }
        let value_bytes = &data[offset..offset + value_len];
        let value =
            core::str::from_utf8(value_bytes).map_err(|_| ProgramError::InvalidInstructionData)?;
        offset += value_len;

        // Call the callback with the parsed key-value pair
        callback(key, value)?;
    }

    Ok(())
}

/// Calculate mint account size with extensions using pinocchio constants
pub fn calculate_mint_size_with_extensions(extensions: &[ExtensionType]) -> usize {
    // Base mint size
    let base_size = Mint::BASE_LEN;

    // Extensions padding
    let padding_size = EXTENSIONS_PADDING;

    // Account type byte
    let account_type_size = EXTENSION_START_OFFSET;

    // Calculate extensions size
    let extensions_size: usize = extensions
        .iter()
        .map(|ext_type| {
            // Each extension has: type (2 bytes) + length (2 bytes) + data
            let extension_data_size = match ext_type {
                ExtensionType::PermanentDelegate => PermanentDelegate::LEN,
                ExtensionType::TransferHook => TransferHook::LEN,
                ExtensionType::Pausable => Pausable::LEN,
                ExtensionType::MetadataPointer => MetadataPointer::LEN,
                ExtensionType::ScaledUiAmount => ScaledUiAmountConfig::LEN,
                _ => unreachable!(),
            };
            EXTENSION_TYPE_LEN + EXTENSION_LENGTH_LEN + extension_data_size
        })
        .sum();

    base_size + padding_size + account_type_size + extensions_size
}

/// Calculate TLV size for TokenMetadata (equivalent to TokenMetadata::tlv_size_of)
pub fn calculate_metadata_tlv_size(metadata: &TokenMetadataArgs) -> Result<usize, ProgramError> {
    // TLV header (type + length)
    let tlv_header_size = EXTENSION_TYPE_LEN + EXTENSION_LENGTH_LEN;

    // Calculate additional metadata size using callback
    let mut additional_metadata_size: usize = 0;
    parse_additional_metadata(metadata.additional_metadata.as_slice(), |key, value| {
        additional_metadata_size += 4 + key.len() + 4 + value.len(); // key_len + key + value_len + value
        Ok(())
    })?;

    // TokenMetadata data size: fixed fields + variable strings + additional metadata
    let metadata_data_size = 32 + // update_authority (Pubkey)
        32 + // mint (Pubkey)  
        4 + metadata.name.len() + // name_len + name
        4 + metadata.symbol.len() + // symbol_len + symbol
        4 + metadata.uri.len() + // uri_len + uri
        4 +  additional_metadata_size; // parsed additional metadata

    Ok(tlv_header_size + metadata_data_size)
}

/// Parse action_id from bytes
pub fn parse_action_id_bytes(data: &[u8]) -> Option<u64> {
    data.get(..ACTION_ID_LEN)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
}

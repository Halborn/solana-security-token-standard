//! Utility functions for PDA derivation and common operations

use solana_program::pubkey::Pubkey;

/// Seeds for different PDA types
pub mod seeds {
    /// Seed for mint authority PDA
    pub const MINT_AUTHORITY: &[u8] = b"mint.authority";
    /// Seed for pause authority PDA
    pub const PAUSE_AUTHORITY: &[u8] = b"mint.pause_authority";
    /// Seed for freeze authority PDA
    pub const FREEZE_AUTHORITY: &[u8] = b"mint.freeze_authority";
    /// Seed for transfer hook PDA
    pub const TRANSFER_HOOK: &[u8] = b"mint.transfer_hook";
    /// Seed for permanent delegate PDA
    pub const PERMANENT_DELEGATE: &[u8] = b"mint.permanent_delegate";
    /// Seed for account delegate PDA
    pub const ACCOUNT_DELEGATE: &[u8] = b"account.delegate";
}

/// Derive mint authority PDA
/// Seeds: ["mint.authority", mint_pubkey, creator_pubkey]
pub fn find_mint_authority_pda(
    mint: &Pubkey,
    creator: &Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::MINT_AUTHORITY, mint.as_ref(), creator.as_ref()],
        program_id,
    )
}

/// Derive pause authority PDA
/// Seeds: ["mint.pause_authority", mint_pubkey]
pub fn find_pause_authority_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::PAUSE_AUTHORITY, mint.as_ref()], program_id)
}

/// Derive freeze authority PDA
/// Seeds: ["mint.freeze_authority", mint_pubkey]
pub fn find_freeze_authority_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::FREEZE_AUTHORITY, mint.as_ref()], program_id)
}

/// Derive transfer hook PDA
/// Seeds: ["mint.transfer_hook", mint_pubkey]
pub fn find_transfer_hook_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::TRANSFER_HOOK, mint.as_ref()], program_id)
}

/// Derive permanent delegate PDA
/// Seeds: ["mint.permanent_delegate", mint_pubkey]
pub fn find_permanent_delegate_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::PERMANENT_DELEGATE, mint.as_ref()], program_id)
}

/// Derive account delegate PDA
/// Seeds: ["account.delegate", account_pubkey]
pub fn find_account_delegate_pda(account: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::ACCOUNT_DELEGATE, account.as_ref()], program_id)
}

/// Get seeds for mint authority PDA signing
pub fn get_mint_authority_seeds<'a>(
    mint: &'a Pubkey,
    creator: &'a Pubkey,
    bump: &'a u8,
) -> [&'a [u8]; 4] {
    [
        seeds::MINT_AUTHORITY,
        mint.as_ref(),
        creator.as_ref(),
        std::slice::from_ref(bump),
    ]
}

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
    /// Seed for verification config
    pub const VERIFICATION_CONFIG: &[u8] = b"verification_config";
}

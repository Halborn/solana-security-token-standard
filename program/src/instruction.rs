use num_derive::FromPrimitive;

/// Arguments for initializing a security token mint
#[derive(Clone, Debug, PartialEq)]
pub struct InitializeMintArgs {
    /// Number of decimal places for the token
    pub decimals: u8,
    /// Token name (for metadata)
    pub name: String,
    /// Token symbol (for metadata)
    pub symbol: String,
    /// Token URI (for additional metadata)
    pub uri: String,
}

/// Instructions supported by the Security Token program
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum SecurityTokenInstruction {
    /// Initialize a security token mint with Token-2022 extensions
    ///
    /// Accounts expected:
    /// 0. `[writeable]` Mint account (must be uninitialized)
    /// 1. `[signer]` Creator/issuer account
    /// 2. `[]` SPL Token 2022 program
    /// 3. `[]` System program
    /// 4. `[]` Rent sysvar
    InitializeMint = 0,
    /// Update verification configuration
    UpdateVerificationConfig = 1,
    /// Set verification status for an account
    SetVerificationStatus = 2,
    /// Update whitelist status
    UpdateWhitelist = 3,
}

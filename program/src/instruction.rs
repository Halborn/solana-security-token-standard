use num_derive::FromPrimitive;

/// Instructions supported by the Security Token program
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum SecurityTokenInstruction {
    /// Initialize a security token mint
    InitializeMint = 0,
    /// Update verification configuration
    UpdateVerificationConfig = 1,
    /// Set verification status for an account
    SetVerificationStatus = 2,
    /// Update whitelist status
    UpdateWhitelist = 3,
}

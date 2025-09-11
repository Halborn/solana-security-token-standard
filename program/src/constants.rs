/// Maximum number of program addresses in verification config
pub const MAX_PROGRAM_ADDRESSES: usize = 16;

/// Instruction discriminators (first 8 bytes of SHA256 of instruction name)z
pub mod discriminators {
    /// InitializeMint discriminator
    pub const INITIALIZE_MINT: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0]; // Simple discriminator for now
    /// UpdateMetadata discriminator  
    pub const UPDATE_METADATA: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    /// MintTokens discriminator (for future use)
    pub const MINT_TOKENS: [u8; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
    /// BurnTokens discriminator (for future use)
    pub const BURN_TOKENS: [u8; 8] = [3, 0, 0, 0, 0, 0, 0, 0];
    /// TransferTokens discriminator (for future use)
    pub const TRANSFER_TOKENS: [u8; 8] = [4, 0, 0, 0, 0, 0, 0, 0];
    /// InitializeVerificationConfig discriminator
    pub const INITIALIZE_VERIFICATION_CONFIG: [u8; 8] = [5, 0, 0, 0, 0, 0, 0, 0];
    /// UpdateVerificationConfig discriminator
    pub const UPDATE_VERIFICATION_CONFIG: [u8; 8] = [6, 0, 0, 0, 0, 0, 0, 0];
}

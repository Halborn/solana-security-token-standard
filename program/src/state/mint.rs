//! Mint-related state structures

use bytemuck::{Pod, Zeroable};
use spl_pod::optional_keys::OptionalNonZeroPubkey;

/// Main security token mint configuration
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct SecurityTokenMint {
    /// The authority that can update security settings
    pub security_authority: OptionalNonZeroPubkey,
    /// The authority that can manage the whitelist  
    pub whitelist_authority: OptionalNonZeroPubkey,
    /// Verification requirements
    pub verification_config: super::VerificationConfig,
    /// Reserved for future use
    pub _reserved: [u8; 128],
}

impl Default for SecurityTokenMint {
    fn default() -> Self {
        Self {
            security_authority: OptionalNonZeroPubkey::default(),
            whitelist_authority: OptionalNonZeroPubkey::default(),
            verification_config: super::VerificationConfig::default(),
            _reserved: [0; 128],
        }
    }
}

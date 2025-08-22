//! Mint-related state structures

use bytemuck::{Pod, Zeroable};
use pinocchio::pubkey::Pubkey;

/// Main security token mint configuration
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct SecurityTokenMint {
    /// The authority that can update security settings
    pub security_authority: Pubkey,
    /// The authority that can manage the whitelist  
    pub whitelist_authority: Pubkey,
    /// Verification requirements
    pub verification_config: super::VerificationConfig,
    /// Reserved for future use
    pub _reserved: [u8; 128],
}

impl Default for SecurityTokenMint {
    fn default() -> Self {
        Self {
            security_authority: Pubkey::default(),
            whitelist_authority: Pubkey::default(),
            verification_config: super::VerificationConfig::default(),
            _reserved: [0; 128],
        }
    }
}

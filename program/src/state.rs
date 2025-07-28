//! State structures for Security Token Standard

use bytemuck::{Pod, Zeroable};
use spl_pod::optional_keys::OptionalNonZeroPubkey;

/// Configuration for verification requirements
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct VerificationConfig {
    /// KYC requirement level (0 = none, 1 = basic, 2 = full)
    pub kyc_level: u8,
    /// Whether AML checks are required (0 = false, 1 = true)
    pub aml_required: u8,
    /// Accreditation requirement (0 = none, 1 = accredited only)
    pub accreditation_level: u8,
    /// Reserved for future use
    pub _reserved: [u8; 5],
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            kyc_level: 0,
            aml_required: 0,
            accreditation_level: 0,
            _reserved: [0; 5],
        }
    }
}

/// Security token mint configuration
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct SecurityTokenMint {
    /// The authority that can update security settings
    pub security_authority: OptionalNonZeroPubkey,
    /// The authority that can manage the whitelist
    pub whitelist_authority: OptionalNonZeroPubkey,
    /// Verification requirements
    pub verification_config: VerificationConfig,
    /// Reserved for future use
    pub _reserved: [u8; 128],
}

impl Default for SecurityTokenMint {
    fn default() -> Self {
        Self {
            security_authority: OptionalNonZeroPubkey::default(),
            whitelist_authority: OptionalNonZeroPubkey::default(),
            verification_config: VerificationConfig::default(),
            _reserved: [0; 128],
        }
    }
}

/// Verification status for an account
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct VerificationStatus {
    /// KYC completion timestamp (0 if not completed)
    pub kyc_timestamp: u64,
    /// AML check timestamp (0 if not completed)
    pub aml_timestamp: u64,
    /// Account whitelist status (0 = false, 1 = true)
    pub is_whitelisted: u8,
    /// Reserved for future use
    pub _reserved: [u8; 32],
}

impl Default for VerificationStatus {
    fn default() -> Self {
        Self {
            kyc_timestamp: 0,
            aml_timestamp: 0,
            is_whitelisted: 0,
            _reserved: [0; 32],
        }
    }
}

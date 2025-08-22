//! Verification-related state structures

use bytemuck::{Pod, Zeroable};
use pinocchio::pubkey::Pubkey;

/// Verification configuration for instructions
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
pub struct VerificationConfig {
    /// Required verification programs (up to 4 for Phase 1)
    pub verification_programs: [Pubkey; 4],
    /// Instruction discriminator this config applies to
    pub instruction_discriminator: [u8; 8],
    /// Configuration flags
    pub flags: u64,
    /// Reserved for future use
    pub _reserved: [u8; 24],
}

/// Individual account verification status
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
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

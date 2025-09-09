//! Security Token account structures
//! 
//! Contains main account types used by the Security Token program

use bytemuck::{Pod, Zeroable};
use pinocchio::pubkey::Pubkey;

/// Security Token Mint configuration
/// Stored as part of SPL Token 2022 mint account extensions
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
pub struct SecurityTokenMint {
    /// Token creator (used for PDA generation)
    pub creator: Pubkey,
    /// Verification requirements
    pub verification_config: super::VerificationConfig,
    /// Reserved for future extensions
    pub _reserved: [u8; 32],
}

impl SecurityTokenMint {
    /// Create new SecurityTokenMint configuration
    pub fn new(creator: Pubkey) -> Self {
        Self {
            creator,
            verification_config: super::VerificationConfig::default(),
            _reserved: [0; 32],
        }
    }
}

/// Verification Config Account
/// PDA derived from instruction ID, mint address, and static string
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
pub struct InstructionVerificationConfig {
    /// Instruction discriminator this config applies to
    pub instruction_discriminator: [u8; 8],
    /// Number of verification programs configured
    pub program_count: u8,
    /// Reserved for alignment
    pub _reserved: [u8; 7],
    // Note: Verification program addresses stored as variable-length data
    // Access via get_programs() method
}

/// Receipt Account for corporate actions
/// Prevents double-execution of corporate actions
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
pub struct ReceiptAccount {
    /// Corporate action ID
    pub action_id: u64,
    /// Account that executed the action
    pub account: Pubkey,
    /// Amount processed
    pub amount: u64,
    /// Timestamp of execution
    pub timestamp: i64,
    /// Reserved for future use
    pub _reserved: [u8; 32],
}

/// Proof Account for merkle proofs
/// Used for large merkle proofs that don't fit in instruction data
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
pub struct ProofAccount {
    /// Corporate action ID this proof relates to
    pub action_id: u64,
    /// Length of proof data
    pub proof_length: u32,
    /// Reserved for alignment
    pub _reserved: [u8; 4],
    // Note: Proof data stored as variable-length data after this header
}

/// Rate Account for corporate actions
/// Stores conversion and split ratios
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable, Default)]
pub struct RateAccount {
    /// Corporate action ID
    pub action_id: u64,
    /// Rate information
    // pub rate: super::Rate,
    /// Reserved for future use
    pub _reserved: [u8; 32],
}

//! Verification-related state structures

use bytemuck::{Pod, Zeroable};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{find_program_address, Pubkey};

/// Verification configuration for instructions
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct VerificationConfig {
    /// Instruction discriminator this config applies to
    pub instruction_discriminator: [u8; 8],
    /// Number of valid verification programs (0-16)
    pub program_count: u8,
    /// Required verification programs (up to 16)
    pub verification_programs: [[u8; 32]; 16],
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            instruction_discriminator: [0; 8],
            program_count: 0,
            verification_programs: [[0u8; 32]; 16],
        }
    }
}

impl VerificationConfig {
    /// Size of the VerificationConfig account
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create new VerificationConfig
    pub fn new(
        instruction_discriminator: [u8; 8],
        verification_program_addresses: &[[u8; 32]],
    ) -> Result<Self, ProgramError> {
        if verification_program_addresses.len() > 16 {
            return Err(ProgramError::InvalidArgument);
        }

        let mut programs = [[0u8; 32]; 16];
        for (i, program_bytes) in verification_program_addresses.iter().enumerate() {
            programs[i] = *program_bytes;
        }

        Ok(Self {
            instruction_discriminator,
            program_count: verification_program_addresses.len() as u8,
            verification_programs: programs,
        })
    }

    /// Get active verification programs
    pub fn get_active_programs(&self) -> &[[u8; 32]] {
        &self.verification_programs[..self.program_count as usize]
    }

    /// Find PDA for verification config
    pub fn find_pda(
        mint: &Pubkey,
        instruction_discriminator: &[u8; 8],
        program_id: &Pubkey,
    ) -> (Pubkey, u8) {
        find_program_address(
            &[
                b"verification_config",
                mint.as_ref(),
                instruction_discriminator,
            ],
            program_id,
        )
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ProgramError> {
        // Validate program count
        if self.program_count > 16 {
            return Err(ProgramError::InvalidAccountData);
        }

        // Validate that all active programs are non-zero
        for i in 0..self.program_count as usize {
            if self.verification_programs[i] == [0u8; 32] {
                return Err(ProgramError::InvalidAccountData);
            }
        }

        Ok(())
    }
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

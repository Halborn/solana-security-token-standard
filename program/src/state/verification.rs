//! Verification-related state structures

use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

/// Verification configuration for instructions
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct VerificationConfig {
    /// Instruction discriminator this config applies to
    pub instruction_discriminator: [u8; 8],
    /// Required verification programs
    pub verification_programs: Vec<Pubkey>,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            instruction_discriminator: [0; 8],
            verification_programs: Vec::new(),
        }
    }
}

impl VerificationConfig {
    /// Create new VerificationConfig
    pub fn new(
        instruction_discriminator: [u8; 8],
        verification_program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            verification_programs: verification_program_addresses.to_vec(),
        })
    }

    /// Get active verification programs
    pub fn get_active_programs(&self) -> &[Pubkey] {
        &self.verification_programs
    }

    /// Get program count
    pub fn program_count(&self) -> usize {
        self.verification_programs.len()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ProgramError> {
        use pinocchio_log::log;

        // Create zero pubkey for comparison (actual zeros, not Pubkey::default)
        let zero_pubkey = [0u8; 32];

        // Validate that all programs are non-zero (valid pubkeys)
        log!(
            "Validating {} verification programs",
            self.verification_programs.len()
        );
        for (i, program) in self.verification_programs.iter().enumerate() {
            if *program == zero_pubkey {
                log!("Found invalid (zero) pubkey at index {}", i);
                return Err(ProgramError::InvalidAccountData);
            }
        }
        log!("All programs validated successfully");

        Ok(())
    }

    /// Calculate the actual size needed for serialization
    pub fn serialized_size(&self) -> usize {
        8 + 4 + (self.verification_programs.len() * 32) // discriminator + vec_len + programs
    }
}

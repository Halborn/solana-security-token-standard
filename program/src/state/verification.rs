//! Verification-related state structures

use crate::state::{
    AccountDeserialize, AccountSerialize, Discriminator, SecurityTokenDiscriminators,
};
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use shank::ShankAccount;

/// Verification configuration for instructions
#[repr(C)]
#[derive(ShankAccount)]
pub struct VerificationConfig {
    /// Instruction discriminator this config applies to
    pub instruction_discriminator: u8,
    /// Required verification programs
    pub verification_programs: Vec<Pubkey>,
}

impl Discriminator for VerificationConfig {
    const DISCRIMINATOR: u8 = SecurityTokenDiscriminators::VerificationConfigDiscriminator as u8;
}

impl AccountSerialize for VerificationConfig {
    fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Write instruction discriminator (1 byte)
        data.push(self.instruction_discriminator);

        // Write program count (4 bytes)
        data.extend(&(self.verification_programs.len() as u32).to_le_bytes());

        // Write each program address (32 bytes each)
        for program in &self.verification_programs {
            data.extend_from_slice(program.as_ref());
        }

        data
    }
}

impl AccountDeserialize for VerificationConfig {
    fn try_from_bytes_inner(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 5 {
            // Minimum: 1 byte discriminator + 4 bytes count
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = 0;

        // Read instruction discriminator (1 byte)
        let instruction_discriminator = data[offset];
        offset += 1;

        // Read program count (4 bytes)
        let program_count = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;
        offset += 4;

        // Validate we have enough data for all programs
        if data.len() < offset + (program_count * 32) {
            return Err(ProgramError::InvalidAccountData);
        }

        // Read program addresses (32 bytes each)
        let mut verification_programs = Vec::with_capacity(program_count);
        for _ in 0..program_count {
            let program_bytes: [u8; 32] = data[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            verification_programs.push(Pubkey::from(program_bytes));
            offset += 32;
        }

        let config = Self {
            instruction_discriminator,
            verification_programs,
        };

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }
}

impl VerificationConfig {
    /// Create new VerificationConfig
    pub fn new(
        instruction_discriminator: u8,
        verification_program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            verification_programs: verification_program_addresses.to_vec(),
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ProgramError> {
        // Create zero pubkey for comparison (actual zeros, not Pubkey::default)
        let zero_pubkey = [0u8; PUBKEY_BYTES];

        // Validate that all programs are non-zero (valid pubkeys)
        for program in self.verification_programs.iter() {
            if *program == zero_pubkey {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        Ok(())
    }

    /// Calculate the actual size needed for serialization
    pub fn serialized_size(&self) -> usize {
        1 // account discriminator
            + 1 // instruction discriminator
            + 4 // vector length prefix
            + (self.verification_programs.len() * PUBKEY_BYTES)
    }

    pub fn from_account_info(account: &AccountInfo) -> Result<Self, ProgramError> {
        let data = account.try_borrow_data()?;
        let config = VerificationConfig::try_from_bytes(&data)?;
        drop(data);
        Ok(config)
    }
}

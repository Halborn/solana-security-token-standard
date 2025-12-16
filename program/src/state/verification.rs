//! Verification-related state structures

use crate::constants::seeds::VERIFICATION_CONFIG;
use crate::state::{
    AccountDeserialize, AccountSerialize, Discriminator, SecurityTokenDiscriminators,
};
use pinocchio::pubkey::{checked_create_program_address, Pubkey, PUBKEY_BYTES};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use shank::ShankAccount;

/// Verification configuration for instructions
#[repr(C)]
#[derive(ShankAccount)]
pub struct VerificationConfig {
    /// Instruction discriminator this config applies to
    pub instruction_discriminator: u8,
    /// Indicates if this config is for CPI mode
    pub cpi_mode: bool,
    /// PDA bump seed used for address derivation
    pub bump: u8,
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

        // Write cpi_mode (1 byte)
        data.push(self.cpi_mode as u8);

        // Write bump (1 byte)
        data.push(self.bump);

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
        if data.len() < Self::MIN_LEN - 1 {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = 0;

        // Read instruction discriminator (1 byte)
        let instruction_discriminator = data[offset];
        offset += 1;

        let cpi_mode = data[offset] != 0;
        offset += 1;

        let bump = data[offset];
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
            let program_bytes: [u8; PUBKEY_BYTES] = data[offset..offset + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            verification_programs.push(Pubkey::from(program_bytes));
            offset += PUBKEY_BYTES;
        }

        let config = Self {
            instruction_discriminator,
            cpi_mode,
            bump,
            verification_programs,
        };

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }
}

impl VerificationConfig {
    /// Minimum size: discriminator (1) + instruction_discriminator (1) + cpi_mode (1) + bump (1) + vector length (4) = 8 bytes
    pub const MIN_LEN: usize = 1 + 1 + 1 + 1 + 4;

    /// Create new VerificationConfig
    pub fn new(
        instruction_discriminator: u8,
        cpi_mode: bool,
        bump: u8,
        verification_program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            bump,
            verification_programs: verification_program_addresses.to_vec(),
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ProgramError> {
        // Validate that all programs are non-zero (valid pubkeys)
        for program in self.verification_programs.iter() {
            // The Pubkey::default() actually represents a zeroed pubkey
            if *program == Pubkey::default() {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        Ok(())
    }

    /// Calculate the actual size needed for serialization
    pub fn serialized_size(&self) -> usize {
        1 // account discriminator
            + 1 // instruction discriminator
            + 1 // cpi_mode
            + 1 // bump
            + 4 // vector length prefix
            + (self.verification_programs.len() * PUBKEY_BYTES)
    }

    pub fn from_account_info(account: &AccountInfo) -> Result<Self, ProgramError> {
        let data = account.try_borrow_data()?;
        let config = VerificationConfig::try_from_bytes(&data)?;
        drop(data);
        Ok(config)
    }

    /// Derive the PDA address for this VerificationConfig using stored bump seed
    ///
    /// # Arguments
    /// * `mint` - The mint address this config is associated with
    ///
    /// # Returns
    /// The derived PDA address or an error if derivation fails
    pub fn derive_pda(&self, mint: &Pubkey) -> Result<Pubkey, ProgramError> {
        let seeds = [
            VERIFICATION_CONFIG,
            mint.as_ref(),
            &[self.instruction_discriminator],
            &[self.bump],
        ];
        checked_create_program_address(&seeds, &crate::id())
    }
}

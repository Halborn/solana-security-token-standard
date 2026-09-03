//! Verification-related state structures

use crate::constants::seeds::VERIFICATION_CONFIG;
use crate::instructions::verification_config::{
    parse_programs, read_bool, serialize_programs, validate_programs, VerificationAccountMeta,
    VerificationProgramConfig,
};
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
    /// Required verification programs and their private extra-account declarations
    pub programs: Vec<VerificationProgramConfig>,
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

        // Write programs and their extra account declarations
        serialize_programs(&self.programs, &mut data);

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

        let cpi_mode =
            read_bool(data, &mut offset).map_err(|_| ProgramError::InvalidAccountData)?;

        let bump = data[offset];
        offset += 1;

        // Read programs and their extra account declarations
        let programs =
            parse_programs(data, &mut offset).map_err(|_| ProgramError::InvalidAccountData)?;
        if offset != data.len() {
            return Err(ProgramError::InvalidAccountData);
        }

        let config = Self {
            instruction_discriminator,
            cpi_mode,
            bump,
            programs,
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
        programs: &[VerificationProgramConfig],
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            bump,
            programs: programs.to_vec(),
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ProgramError> {
        validate_programs(self.instruction_discriminator, &self.programs)
            .map_err(|_| ProgramError::InvalidAccountData)
    }

    /// Calculate the actual size needed for serialization
    pub fn serialized_size(&self) -> usize {
        let extra_account_count = self
            .programs
            .iter()
            .map(|program| program.extra_accounts.len())
            .sum::<usize>();

        1 // account discriminator
            + 1 // instruction discriminator
            + 1 // cpi_mode
            + 1 // bump
            + 4 // vector length prefix
            + (self.programs.len() * (PUBKEY_BYTES + 4))
            + (extra_account_count * VerificationAccountMeta::LEN)
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

impl crate::state::ProgramAccount for VerificationConfig {
    fn space(&self) -> u64 {
        self.serialized_size() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::SecurityTokenInstruction;
    use crate::instructions::verification_config::VerificationAccountMeta;

    #[test]
    fn nested_config_golden_size_and_roundtrip() {
        let config = VerificationConfig::new(
            SecurityTokenInstruction::Mint.discriminant(),
            true,
            7,
            &[
                VerificationProgramConfig {
                    program_id: [1; 32],
                    extra_accounts: vec![VerificationAccountMeta {
                        discriminator: 0,
                        address_config: [2; 32],
                        is_signer: false,
                        is_writable: true,
                    }],
                },
                VerificationProgramConfig {
                    program_id: [3; 32],
                    extra_accounts: vec![],
                },
            ],
        )
        .unwrap();

        let bytes = config.to_bytes();
        assert_eq!(config.serialized_size(), 8 + 36 * 2 + 35);
        assert_eq!(bytes.len(), config.serialized_size());
        let decoded = VerificationConfig::try_from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.instruction_discriminator,
            config.instruction_discriminator
        );
        assert_eq!(decoded.cpi_mode, config.cpi_mode);
        assert_eq!(decoded.bump, config.bump);
        assert_eq!(decoded.programs, config.programs);
    }

    #[test]
    fn nested_config_rejects_noncanonical_bool_and_trailing_bytes() {
        let config = VerificationConfig::new(
            SecurityTokenInstruction::Mint.discriminant(),
            true,
            7,
            &[VerificationProgramConfig {
                program_id: [1; 32],
                extra_accounts: vec![],
            }],
        )
        .unwrap();

        let mut invalid_bool = config.to_bytes();
        invalid_bool[2] = 2;
        assert!(VerificationConfig::try_from_bytes(&invalid_bool).is_err());

        let mut trailing = config.to_bytes();
        trailing.push(0);
        assert!(VerificationConfig::try_from_bytes(&trailing).is_err());
    }
}

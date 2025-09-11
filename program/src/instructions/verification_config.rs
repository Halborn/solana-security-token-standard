//! Verification configuration instruction arguments and utilities
//!
//! This module contains structures and functions for managing verification
//! configuration instructions in the security token program.

use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

/// Arguments for InitializeVerificationConfig instruction
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct InitializeVerificationConfigArgs {
    /// 8-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: [u8; 8],
    /// Number of valid program addresses (0-16)
    pub program_count: u8,
    /// Array of verification program addresses (up to 16)
    pub program_addresses: [[u8; 32]; 16], // Static array for SBF compatibility
}

/// Wrapper struct that matches what codama generates
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct InitializeVerificationConfigInstructionArgs {
    /// The verification config arguments
    pub args: InitializeVerificationConfigArgs,
}

impl InitializeVerificationConfigArgs {
    /// Create new InitializeVerificationConfigArgs
    pub fn new(
        instruction_discriminator: [u8; 8],
        program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        if program_addresses.len() > 16 {
            return Err(ProgramError::InvalidArgument);
        }

        let mut addresses = [[0u8; 32]; 16];
        for (i, pubkey) in program_addresses.iter().enumerate() {
            addresses[i] = *pubkey;
        }

        Ok(Self {
            instruction_discriminator,
            program_count: program_addresses.len() as u8,
            program_addresses: addresses,
        })
    }

    /// Pack the arguments into bytes using Borsh serialization
    pub fn pack(&self) -> Vec<u8> {
        self.try_to_vec().unwrap_or_default()
    }

    /// Unpack arguments from bytes using Borsh deserialization
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)
    }

    /// Get program addresses as iterator for SBF compatibility
    pub fn program_addresses_iter(&self) -> impl Iterator<Item = Pubkey> + '_ {
        (0..self.program_count as usize).map(move |i| Pubkey::from(self.program_addresses[i]))
    }

    /// Get specific program address by index
    pub fn get_program_address(&self, index: usize) -> Option<Pubkey> {
        if index < self.program_count as usize {
            Some(Pubkey::from(self.program_addresses[index]))
        } else {
            None
        }
    }
}

#[cfg(test)]
fn random_pubkey() -> Pubkey {
    use pinocchio::pubkey::PUBKEY_BYTES;
    rand::random::<[u8; PUBKEY_BYTES]>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::discriminators;

    #[test]
    fn test_initialize_verification_config_args_pack_unpack() {
        // Create test program addresses
        let program1 = random_pubkey();
        let program2 = random_pubkey();
        let program_addresses = vec![program1, program2];

        // Test with MINT_TOKENS discriminator
        let original =
            InitializeVerificationConfigArgs::new(discriminators::MINT_TOKENS, &program_addresses)
                .unwrap();

        let packed = original.pack();
        let unpacked = InitializeVerificationConfigArgs::unpack(&packed).unwrap();

        assert_eq!(
            original.instruction_discriminator,
            unpacked.instruction_discriminator
        );
        assert_eq!(original.program_count, unpacked.program_count);

        let original_addresses: Vec<Pubkey> = original.program_addresses_iter().collect();
        let unpacked_addresses: Vec<Pubkey> = unpacked.program_addresses_iter().collect();
        assert_eq!(original_addresses, unpacked_addresses);
        assert_eq!(program_addresses, unpacked_addresses);
    }

    #[test]
    fn test_initialize_verification_config_args_limits() {
        // Test with maximum allowed programs (16)
        let max_programs: Vec<Pubkey> = (0..16).map(|_| random_pubkey()).collect();
        let max_args =
            InitializeVerificationConfigArgs::new(discriminators::BURN_TOKENS, &max_programs)
                .unwrap();
        assert_eq!(max_args.program_count, 16);

        // Test with too many programs (should fail)
        let too_many_programs: Vec<Pubkey> = (0..17).map(|_| random_pubkey()).collect();
        let result = InitializeVerificationConfigArgs::new(
            discriminators::TRANSFER_TOKENS,
            &too_many_programs,
        );
        assert!(result.is_err());

        // Test with empty programs list
        let empty_args = InitializeVerificationConfigArgs::new(
            discriminators::INITIALIZE_VERIFICATION_CONFIG,
            &[],
        )
        .unwrap();
        assert_eq!(empty_args.program_count, 0);
    }
}

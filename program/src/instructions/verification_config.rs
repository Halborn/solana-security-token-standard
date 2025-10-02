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
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// Vector of verification program addresses
    pub program_addresses: Vec<Pubkey>,
}

/// Wrapper struct that matches what codama generates
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct InitializeVerificationConfigInstructionArgs {
    /// The verification config arguments
    pub args: InitializeVerificationConfigArgs,
}

/// Arguments for UpdateVerificationConfig instruction
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct UpdateVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// Vector of new verification program addresses to add/replace
    pub program_addresses: Vec<Pubkey>,
    /// Offset at which to start replacement/insertion (0-based index)
    pub offset: u8,
}

/// Wrapper struct that matches what codama generates for UpdateVerificationConfig
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct UpdateVerificationConfigInstructionArgs {
    /// The verification config update arguments
    pub args: UpdateVerificationConfigArgs,
}

impl InitializeVerificationConfigArgs {
    /// Create new InitializeVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        if program_addresses.len() > 16 {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(Self {
            instruction_discriminator,
            program_addresses: program_addresses.to_vec(),
        })
    }

    /// Pack the arguments into bytes using Borsh serialization
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        self.try_to_vec().unwrap_or_default()
    }

    /// Unto_bytes_inner arguments from bytes using Borsh deserialization
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)
    }

    /// Get program count
    pub fn program_count(&self) -> u8 {
        self.program_addresses.len() as u8
    }

    /// Get program addresses as slice
    pub fn program_addresses(&self) -> &[Pubkey] {
        &self.program_addresses
    }

    /// Get specific program address by index
    pub fn get_program_address(&self, index: usize) -> Option<Pubkey> {
        self.program_addresses.get(index).copied()
    }
}

impl UpdateVerificationConfigArgs {
    /// Create new UpdateVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        program_addresses: &[Pubkey],
        offset: u8,
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            program_addresses: program_addresses.to_vec(),
            offset,
        })
    }

    /// Pack the arguments into bytes using Borsh serialization
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        self.try_to_vec().unwrap_or_default()
    }

    /// Unto_bytes_inner arguments from bytes using Borsh deserialization
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)
    }

    /// Get program count
    pub fn program_count(&self) -> u8 {
        self.program_addresses.len() as u8
    }

    /// Get program addresses as slice
    pub fn program_addresses(&self) -> &[Pubkey] {
        &self.program_addresses
    }

    /// Get specific program address by index
    pub fn get_program_address(&self, index: usize) -> Option<Pubkey> {
        self.program_addresses.get(index).copied()
    }

    /// Get offset
    pub fn offset(&self) -> u8 {
        self.offset
    }
}

/// Arguments for TrimVerificationConfig instruction
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct TrimVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// New size of the program array (number of Pubkeys to keep)
    pub size: u8,
    /// Whether to close the account completely
    pub close: bool,
}

/// Wrapper struct that matches what codama generates for TrimVerificationConfig
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct TrimVerificationConfigInstructionArgs {
    /// The trim verification config arguments
    pub args: TrimVerificationConfigArgs,
}

impl TrimVerificationConfigArgs {
    /// Creates a new `TrimVerificationConfigArgs` instance.
    ///
    /// # Arguments
    ///
    /// * `instruction_discriminator` - 1-byte instruction discriminator.
    /// * `size` - New size of the program array (number of Pubkeys to keep).
    /// * `close` - Whether to close the account completely.
    pub fn new(instruction_discriminator: u8, size: u8, close: bool) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            size,
            close,
        })
    }

    /// Pack the arguments into bytes using Borsh serialization
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        self.try_to_vec().unwrap_or_default()
    }

    /// Unto_bytes_inner arguments from bytes using Borsh deserialization
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)
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
    use crate::instruction::SecurityTokenInstruction;

    #[test]
    fn test_initialize_verification_config_args_to_bytes_inner_try_from_bytes() {
        // Create test program addresses
        let program1 = random_pubkey();
        let program2 = random_pubkey();
        let program_addresses = vec![program1, program2];

        // Test with UpdateMetadata discriminator
        let original = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::UpdateMetadata.discriminant(),
            &program_addresses,
        )
        .unwrap();

        let to_bytes_innered = original.to_bytes_inner();
        let try_from_bytesed = InitializeVerificationConfigArgs::try_from_bytes(&to_bytes_innered).unwrap();

        assert_eq!(
            original.instruction_discriminator,
            try_from_bytesed.instruction_discriminator
        );
        assert_eq!(original.program_count(), try_from_bytesed.program_count());

        let original_addresses = original.program_addresses();
        let try_from_bytesed_addresses = try_from_bytesed.program_addresses();
        assert_eq!(original_addresses, try_from_bytesed_addresses);
        assert_eq!(program_addresses, try_from_bytesed_addresses);
    }

    #[test]
    fn test_initialize_verification_config_args_limits() {
        // Test with maximum allowed programs (16)
        let max_programs: Vec<Pubkey> = (0..16).map(|_| random_pubkey()).collect();
        let max_args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::InitializeMint.discriminant(),
            &max_programs,
        )
        .unwrap();
        assert_eq!(max_args.program_count(), 16);

        // Test with too many programs (should fail)
        let too_many_programs: Vec<Pubkey> = (0..17).map(|_| random_pubkey()).collect();
        let result = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::UpdateMetadata.discriminant(),
            &too_many_programs,
        );
        assert!(result.is_err());

        // Test with empty programs list
        let empty_args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::InitializeVerificationConfig.discriminant(),
            &[],
        )
        .unwrap();
        assert_eq!(empty_args.program_count(), 0);
    }
}

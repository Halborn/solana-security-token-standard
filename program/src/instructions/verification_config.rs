//! Verification configuration instruction arguments and utilities
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};
use shank::ShankType;

use crate::constants::MAX_VERIFICATION_PROGRAMS;

/// Arguments for InitializeVerificationConfig instruction
#[repr(C)]
#[derive(ShankType)]
pub struct InitializeVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// 1-byte CPI mode
    pub cpi_mode: bool,
    /// Vector of verification program addresses
    pub program_addresses: Vec<Pubkey>,
}

/// Arguments for UpdateVerificationConfig instruction
#[repr(C)]
#[derive(ShankType)]
pub struct UpdateVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// 1-byte CPI mode
    pub cpi_mode: bool,
    /// Offset at which to start replacement/insertion (0-based index)
    pub offset: u8,
    /// Vector of new verification program addresses to add/replace
    pub program_addresses: Vec<Pubkey>,
}

impl InitializeVerificationConfigArgs {
    /// Minimum size: instruction_discriminator (1) + cpi_mode (1) + vector length (4) = 6 bytes
    pub const MIN_LEN: usize = 6;

    /// Create new InitializeVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        cpi_mode: bool,
        program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            program_addresses: program_addresses.to_vec(),
        })
    }

    /// Serialize to bytes using manual serialization (following SAS pattern)
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Write instruction discriminator (1 byte)
        data.push(self.instruction_discriminator);
        // Write cpi_mode (1 byte)
        data.push(self.cpi_mode as u8);

        // Write program count (4 bytes)
        data.extend(&(self.program_addresses.len() as u32).to_le_bytes());

        // Write each program address (32 bytes each)
        for program in &self.program_addresses {
            data.extend_from_slice(program.as_ref());
        }

        data
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read instruction discriminator (1 byte)
        let instruction_discriminator = data[offset];
        offset += 1;

        // Read cpi_mode (1 byte)
        let cpi_mode = data[offset];
        offset += 1;

        // Read program count (4 bytes)
        let program_count = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset += 4;

        // Validate we have enough data for all programs
        if data.len() < offset + (program_count * PUBKEY_BYTES) {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read program addresses (32 bytes each)
        let mut program_addresses = Vec::with_capacity(program_count);
        for _ in 0..program_count {
            let program_bytes: [u8; PUBKEY_BYTES] = data[offset..offset + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let program_pubkey = Pubkey::from(program_bytes);
            program_addresses.push(program_pubkey);
            offset += PUBKEY_BYTES;
        }

        Ok(Self {
            instruction_discriminator,
            cpi_mode: cpi_mode != 0,
            program_addresses,
        })
    }

    pub fn validate(&self) -> Result<(), ProgramError> {
        // Validate program count doesn't exceed maximum
        if self.program_addresses.len() > MAX_VERIFICATION_PROGRAMS {
            return Err(ProgramError::InvalidArgument);
        }

        // Validate no default pubkeys
        for program in &self.program_addresses {
            if *program == Pubkey::default() {
                return Err(ProgramError::InvalidArgument);
            }
        }

        Ok(())
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
    /// Minimum size: instruction_discriminator (1) + cpi_mode (1) + offset (1) + vector length (4) = 7 bytes
    pub const MIN_LEN: usize = 7;

    /// Create new UpdateVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        cpi_mode: bool,
        program_addresses: &[Pubkey],
        offset: u8,
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            program_addresses: program_addresses.to_vec(),
            offset,
        })
    }

    /// Serialize to bytes using manual serialization (following SAS pattern)
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Write instruction discriminator (1 byte)
        data.push(self.instruction_discriminator);

        // Write cpi_mode (1 byte)
        data.push(self.cpi_mode as u8);

        // Write offset (1 byte)
        data.push(self.offset);

        // Write program count (4 bytes)
        data.extend(&(self.program_addresses.len() as u32).to_le_bytes());

        // Write each program address (32 bytes each)
        for program in &self.program_addresses {
            data.extend_from_slice(program.as_ref());
        }

        data
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset_pos = 0;

        // Read instruction discriminator (1 byte)
        let instruction_discriminator = data[offset_pos];
        offset_pos += 1;

        // Read cpi_mode (1 byte)
        let cpi_mode = data[offset_pos];
        offset_pos += 1;

        // Read offset (1 byte)
        let offset = data[offset_pos];
        offset_pos += 1;

        // Read program count (4 bytes)
        let program_count = u32::from_le_bytes(
            data[offset_pos..offset_pos + 4]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset_pos += 4;

        // Validate we have enough data for all programs
        if data.len() < offset_pos + (program_count * PUBKEY_BYTES) {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read program addresses (32 bytes each)
        let mut program_addresses = Vec::with_capacity(program_count);
        for _ in 0..program_count {
            let program_bytes: [u8; PUBKEY_BYTES] = data[offset_pos..offset_pos + PUBKEY_BYTES]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let program_pubkey = Pubkey::from(program_bytes);
            program_addresses.push(program_pubkey);
            offset_pos += PUBKEY_BYTES;
        }

        Ok(Self {
            instruction_discriminator,
            cpi_mode: cpi_mode != 0,
            program_addresses,
            offset,
        })
    }

    pub fn validate(&self) -> Result<(), ProgramError> {
        // Validate offset is within bounds (0-based index, so offset < MAX)
        if self.offset >= MAX_VERIFICATION_PROGRAMS as u8 {
            return Err(ProgramError::InvalidArgument);
        }

        // Validate that offset + program count doesn't exceed maximum
        let total_programs = self.offset as usize + self.program_addresses.len();
        if total_programs > MAX_VERIFICATION_PROGRAMS {
            return Err(ProgramError::InvalidArgument);
        }

        // Validate no default pubkeys
        for program in &self.program_addresses {
            if *program == Pubkey::default() {
                return Err(ProgramError::InvalidArgument);
            }
        }

        Ok(())
    }

    /// Get program addresses as slice
    pub fn program_addresses(&self) -> &[Pubkey] {
        &self.program_addresses
    }

    /// Get offset
    pub fn offset(&self) -> u8 {
        self.offset
    }
}

/// Arguments for TrimVerificationConfig instruction
#[derive(ShankType)]
#[repr(C)]
pub struct TrimVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// New size of the program array (number of Pubkeys to keep)
    pub size: u8,
    /// Whether to close the account completely
    pub close: bool,
}

impl TrimVerificationConfigArgs {
    /// Fixed size: instruction_discriminator (1) + size (1) + close (1) = 3 bytes
    pub const LEN: usize = 3;

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

    /// Serialize to bytes using manual serialization (following SAS pattern)
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        vec![self.instruction_discriminator, self.size, self.close as u8]
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read instruction_discriminator (1 byte)
        let instruction_discriminator = data[offset];
        offset += 1;

        // Read size (1 byte)
        let size = data[offset];
        offset += 1;

        // Read close (1 byte)
        let close = data[offset] != 0; // Non-zero is true

        Ok(Self {
            instruction_discriminator,
            size,
            close,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::SecurityTokenInstruction;
    use crate::test_utils::random_pubkey;
    use rstest::rstest;

    #[test]
    fn test_initialize_verification_config_args_to_bytes_inner_try_from_bytes() {
        let program1 = random_pubkey();
        let program2 = random_pubkey();
        let program_addresses = vec![program1, program2];
        let original = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::UpdateMetadata.discriminant(),
            false,
            &program_addresses,
        )
        .unwrap();

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeVerificationConfigArgs::try_from_bytes(&inner_bytes).unwrap();

        assert_eq!(
            original.instruction_discriminator,
            deserialized.instruction_discriminator
        );
        assert_eq!(original.cpi_mode, deserialized.cpi_mode);
        assert_eq!(original.program_count(), deserialized.program_count());

        let original_addresses = original.program_addresses();
        let deserialized_addresses = deserialized.program_addresses();
        assert_eq!(original_addresses, deserialized_addresses);
        assert_eq!(program_addresses, deserialized_addresses);
    }

    #[rstest]
    #[case(10, true)]
    #[case(9, true)]
    #[case(11, false)]
    fn test_initialize_verification_config_programs_limit(
        #[case] num_programs: usize,
        #[case] should_succeed: bool,
    ) {
        let programs: Vec<Pubkey> = (0..num_programs).map(|_| random_pubkey()).collect();
        let args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            false,
            &programs,
        )
        .unwrap();

        let result = args.validate();

        if should_succeed {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case(11, 10, false)]
    #[case(10, 1, false)]
    #[case(9, 1, true)]
    #[case(8, 2, true)]
    #[case(9, 2, false)]
    fn test_update_verification_config_programs_limit(
        #[case] offset: u8,
        #[case] num_programs: usize,
        #[case] should_succeed: bool,
    ) {
        let programs: Vec<Pubkey> = (0..num_programs).map(|_| random_pubkey()).collect();

        let args = UpdateVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            false,
            &programs,
            offset,
        )
        .unwrap();

        let result = args.validate();

        if should_succeed {
            assert!(
                result.is_ok(),
                "Expected success for offset={} with {} programs",
                offset,
                num_programs
            );
        } else {
            assert!(
                result.is_err(),
                "Expected failure for offset={} with {} programs",
                offset,
                num_programs
            );
        }
    }

    #[test]
    fn test_initialize_verification_config_rejects_default_pubkey() {
        let program1 = random_pubkey();
        let default_pubkey = Pubkey::default();
        let program2 = random_pubkey();

        let program_addresses = vec![program1, default_pubkey, program2];

        let args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            false,
            &program_addresses,
        )
        .unwrap();

        let result = args.validate();

        assert!(matches!(result, Err(ProgramError::InvalidArgument)));
    }

    #[test]
    fn test_update_verification_config_rejects_default_pubkey() {
        let program1 = random_pubkey();
        let default_pubkey = Pubkey::default();

        let program_addresses = vec![program1, default_pubkey];

        let args = UpdateVerificationConfigArgs::new(
            SecurityTokenInstruction::Transfer.discriminant(),
            false,
            &program_addresses,
            0,
        )
        .unwrap();

        let result = args.validate();

        assert!(matches!(result, Err(ProgramError::InvalidArgument)));
    }
}

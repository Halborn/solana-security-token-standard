//! Verification configuration instruction arguments and utilities
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use shank::ShankType;

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
    /// Create new InitializeVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        cpi_mode: bool,
        program_addresses: &[Pubkey],
    ) -> Result<Self, ProgramError> {
        if program_addresses.len() > 16 {
            return Err(ProgramError::InvalidArgument);
        }

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
        if data.len() < 5 {
            // Minimum: 1 byte discriminator + 4 bytes count
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
        if data.len() < offset + (program_count * 32) {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read program addresses (32 bytes each)
        let mut program_addresses = Vec::with_capacity(program_count);
        for _ in 0..program_count {
            let program_bytes: [u8; 32] = data[offset..offset + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            program_addresses.push(Pubkey::from(program_bytes));
            offset += 32;
        }

        Ok(Self {
            instruction_discriminator,
            cpi_mode: cpi_mode != 0,
            program_addresses,
        })
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
        if data.len() < 7 {
            // Minimum: 1 byte discriminator + 1 byte cpi_mode + 1 byte offset + 4 bytes count
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
        if data.len() < offset_pos + (program_count * 32) {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Read program addresses (32 bytes each)
        let mut program_addresses = Vec::with_capacity(program_count);
        for _ in 0..program_count {
            let program_bytes: [u8; 32] = data[offset_pos..offset_pos + 32]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            program_addresses.push(Pubkey::from(program_bytes));
            offset_pos += 32;
        }

        Ok(Self {
            instruction_discriminator,
            cpi_mode: cpi_mode != 0,
            program_addresses,
            offset,
        })
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
        let mut data = Vec::new();

        // Write instruction discriminator (1 byte)
        data.push(self.instruction_discriminator);

        // Write size (1 byte)
        data.push(self.size);

        // Write close flag (1 byte: 1 for true, 0 for false)
        data.push(if self.close { 1 } else { 0 });

        data
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 3 {
            // Minimum: 1 byte discriminator + 1 byte size + 1 byte close
            return Err(ProgramError::InvalidInstructionData);
        }

        let instruction_discriminator = data[0];
        let size = data[1];
        let close = data[2] != 0; // Non-zero is true

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

    #[test]
    fn test_initialize_verification_config_args_to_bytes_inner_try_from_bytes() {
        // Create test program addresses
        let program1 = random_pubkey();
        let program2 = random_pubkey();
        let program_addresses = vec![program1, program2];

        // Test with UpdateMetadata discriminator
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

    #[test]
    fn test_initialize_verification_config_args_limits() {
        // Test with maximum allowed programs (16)
        let max_programs: Vec<Pubkey> = (0..16).map(|_| random_pubkey()).collect();
        let max_args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::InitializeMint.discriminant(),
            false,
            &max_programs,
        )
        .unwrap();
        assert_eq!(max_args.program_count(), 16);

        // Test with too many programs (should fail)
        let too_many_programs: Vec<Pubkey> = (0..17).map(|_| random_pubkey()).collect();
        let result = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::UpdateMetadata.discriminant(),
            false,
            &too_many_programs,
        );
        assert!(result.is_err());

        // Test with empty programs list
        let empty_args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::InitializeVerificationConfig.discriminant(),
            false,
            &[],
        )
        .unwrap();
        assert_eq!(empty_args.program_count(), 0);
    }
}

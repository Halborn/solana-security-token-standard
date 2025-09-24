use num_derive::FromPrimitive;
use pinocchio::program_error::ProgramError;

/// Security Token Program instructions
#[derive(Clone, Debug, PartialEq, FromPrimitive)]
pub enum SecurityTokenInstruction {
    /// Initialize a new security token mint with metadata and compliance features
    /// Accounts expected:
    /// 0. `[writable, signer]` The mint account (must be a signer when creating new account)
    /// 1. `[signer]` The creator/payer account
    /// 2. `[]` The SPL Token 2022 program ID
    /// 3. `[]` The system program ID
    /// 4. `[]` The rent sysvar
    InitializeMint = 0,
    /// Update the metadata of an existing security token mint
    /// Accounts expected:
    /// 0. `[writable]` The mint account
    /// 1. `[signer]` The mint authority account
    /// 2. `[]` The SPL Token 2022 program ID
    /// 3. `[]` The system program ID - NOTE: Add lamports if needed
    UpdateMetadata = 1,
    /// Initialize verification configuration for an instruction
    /// Accounts expected:
    /// 0. `[writable]` The VerificationConfig PDA account
    /// 1. `[writable, signer]` The payer account  
    /// 2. `[]` The mint account
    /// 3. `[signer]` The authority account (mint authority)
    /// 4. `[]` The system program ID
    InitializeVerificationConfig = 2,
    /// Update verification configuration for an instruction
    /// Accounts expected:
    /// 0. `[writable]` The VerificationConfig PDA account
    /// 1. `[]` The mint account
    /// 2. `[signer]` The authority account (mint authority)
    /// 3. `[]` The system program ID
    UpdateVerificationConfig = 3,
    /// Trim verification configuration to recover rent
    /// Accounts expected:
    /// 0. `[writable]` The VerificationConfig PDA account
    /// 1. `[]` The mint account
    /// 2. `[signer]` The authority account (mint authority)
    /// 3. `[writable]` The rent recipient account (to receive recovered lamports)
    /// 4. `[]` The system program ID (optional for closing account)
    TrimVerificationConfig = 4,
}

impl TryFrom<u8> for SecurityTokenInstruction {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SecurityTokenInstruction::InitializeMint),
            1 => Ok(SecurityTokenInstruction::UpdateMetadata),
            2 => Ok(SecurityTokenInstruction::InitializeVerificationConfig),
            3 => Ok(SecurityTokenInstruction::UpdateVerificationConfig),
            4 => Ok(SecurityTokenInstruction::TrimVerificationConfig),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

impl SecurityTokenInstruction {
    /// Parse instruction from instruction data
    pub fn parse_instruction(instruction_data: &[u8]) -> Result<(Self, &[u8]), ProgramError> {
        if instruction_data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let (discriminant, args_data) = instruction_data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        let instruction = Self::try_from(*discriminant)?;
        Ok((instruction, args_data))
    }

    /// Get the discriminant byte for this instruction
    pub fn discriminant(&self) -> u8 {
        match self {
            SecurityTokenInstruction::InitializeMint => 0,
            SecurityTokenInstruction::UpdateMetadata => 1,
            SecurityTokenInstruction::InitializeVerificationConfig => 2,
            SecurityTokenInstruction::UpdateVerificationConfig => 3,
            SecurityTokenInstruction::TrimVerificationConfig => 4,
        }
    }
}

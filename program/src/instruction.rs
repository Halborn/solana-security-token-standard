use pinocchio::program_error::ProgramError;

/// Security Token Program instructions
#[repr(u8)]
#[derive(Clone)]
pub enum SecurityTokenInstruction {
    InitializeMint = 0,
    UpdateMetadata = 1,
    InitializeVerificationConfig = 2,
    UpdateVerificationConfig = 3,
    TrimVerificationConfig = 4,
    Verify = 5,
    Mint = 6,
    Burn = 7,
    Pause = 8,
    Resume = 9,
    Freeze = 10,
    Thaw = 11,
    CreateRateAccount = 12,
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
            5 => Ok(SecurityTokenInstruction::Verify),
            6 => Ok(SecurityTokenInstruction::Mint),
            7 => Ok(SecurityTokenInstruction::Burn),
            8 => Ok(SecurityTokenInstruction::Pause),
            9 => Ok(SecurityTokenInstruction::Resume),
            10 => Ok(SecurityTokenInstruction::Freeze),
            11 => Ok(SecurityTokenInstruction::Thaw),
            12 => Ok(SecurityTokenInstruction::CreateRateAccount),
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
        self.clone() as u8
    }

    /// Create instruction from discriminant byte
    pub fn from_discriminant(discriminant: u8) -> Option<Self> {
        Self::try_from(discriminant).ok()
    }
}

mod idl_gen {

    use crate::instructions::{
        CreateRateArgs, InitializeMintArgs, InitializeVerificationConfigArgs,
        TrimVerificationConfigArgs, UpdateMetadataArgs, UpdateVerificationConfigArgs, VerifyArgs,
    };

    #[derive(shank::ShankInstruction)]
    #[repr(u8)]
    enum _SecurityTokenInstruction {
        #[account(0, writable, signer, name = "mint")]
        #[account(1, writable, signer, name = "payer")]
        #[account(2, writable, name = "authority")]
        #[account(3, name = "token_program")]
        #[account(4, name = "system_program")]
        #[account(5, name = "rent_sysvar")]
        InitializeMint(InitializeMintArgs) = 0,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        #[account(3, writable, name = "mint_account")]
        #[account(4, name = "mint_authority")]
        #[account(5, writable, signer, name = "payer")] // Pays for potential rent-exempt top-up, must sign
        #[account(6, name = "token_program")]
        #[account(7, name = "system_program")]
        UpdateMetadata(UpdateMetadataArgs) = 1,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        #[account(3, name = "mint_account")]
        #[account(4, writable, name = "config_account")]
        #[account(5, writable, signer, name = "payer")]
        #[account(6, name = "system_program")]
        InitializeVerificationConfig(InitializeVerificationConfigArgs) = 2,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        #[account(3, name = "mint_account")]
        #[account(4, writable, name = "config_account")]
        #[account(5, writable, signer, name = "payer")]
        #[account(6, name = "system_program")]
        UpdateVerificationConfig(UpdateVerificationConfigArgs) = 3,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        #[account(3, writable, name = "mint_account")]
        #[account(4, writable, name = "config_account")]
        #[account(5, writable, name = "recipient")]
        #[account(6, name = "system_program")]
        TrimVerificationConfig(TrimVerificationConfigArgs) = 4,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        Verify(VerifyArgs) = 5,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        #[account(3, writable, name = "mint_account")]
        #[account(4, writable, name = "mint_authority")]
        #[account(5, writable, name = "destination")]
        #[account(6, name = "token_program")]
        Mint { amount: u64 } = 6,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        #[account(3, writable, name = "mint_account")]
        #[account(4, name = "permanent_delegate")]
        #[account(5, writable, name = "token_account")]
        #[account(6, name = "token_program")]
        Burn { amount: u64 } = 7,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        #[account(3, writable, name = "mint_account")]
        #[account(4, name = "pause_authority")]
        #[account(5, name = "token_program")]
        Pause = 8,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        #[account(3, writable, name = "mint_account")]
        #[account(4, name = "pause_authority")]
        #[account(5, name = "token_program")]
        Resume = 9,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        #[account(3, name = "mint_account")]
        #[account(4, name = "freeze_authority")]
        #[account(5, writable, name = "token_account")]
        #[account(6, name = "token_program")]
        Freeze = 10,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        #[account(3, name = "mint_account")]
        #[account(4, name = "freeze_authority")]
        #[account(5, writable, name = "token_account")]
        #[account(6, name = "token_program")]
        Thaw = 11,

        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        #[account(3, writable, name = "rate_account")]
        #[account(4, name = "mint_from")]
        #[account(5, name = "mint_to")]
        #[account(6, writable, signer, name = "payer")]
        #[account(7, name = "system_program")]
        CreateRateAccount(CreateRateArgs) = 12,
    }
}

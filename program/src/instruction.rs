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
    Transfer = 12,
    CreateRateAccount = 13,
    UpdateRateAccount = 14,
    CloseRateAccount = 15,
    Split = 16,
    Convert = 17,
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
            12 => Ok(SecurityTokenInstruction::Transfer),
            13 => Ok(SecurityTokenInstruction::CreateRateAccount),
            14 => Ok(SecurityTokenInstruction::UpdateRateAccount),
            15 => Ok(SecurityTokenInstruction::CloseRateAccount),
            16 => Ok(SecurityTokenInstruction::Split),
            17 => Ok(SecurityTokenInstruction::Convert),
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
        close_rate_account::CloseRateArgs, convert::ConvertArgs, split::SplitArgs,
        update_rate_account::UpdateRateArgs, CreateRateArgs, InitializeMintArgs,
        InitializeVerificationConfigArgs, TrimVerificationConfigArgs, UpdateMetadataArgs,
        UpdateVerificationConfigArgs, VerifyArgs,
    };

    #[derive(shank::ShankInstruction)]
    #[repr(u8)]
    enum _SecurityTokenInstruction {
        // No verification overhead
        // Instruction accounts
        #[account(0, writable, signer, name = "mint")]
        #[account(1, writable, name = "authority")]
        #[account(2, writable, signer, name = "payer")]
        #[account(3, name = "token_program")]
        #[account(4, name = "system_program")]
        #[account(5, name = "rent_sysvar")]
        InitializeMint(InitializeMintArgs) = 0,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, name = "mint_authority")]
        #[account(4, writable, signer, name = "payer")]
        #[account(5, writable, name = "mint_account")]
        #[account(6, name = "token_program")]
        #[account(7, name = "system_program")]
        UpdateMetadata(UpdateMetadataArgs) = 1,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, writable, signer, name = "payer")]
        #[account(4, name = "mint_account")]
        #[account(5, writable, name = "config_account")]
        #[account(6, name = "system_program")]
        // Optional accounts, required by accounts meta management
        #[account(7, writable, optional, name = "account_metas_pda")]
        #[account(8, optional, name = "transfer_hook_pda")]
        #[account(9, optional, name = "transfer_hook_program")]
        InitializeVerificationConfig(InitializeVerificationConfigArgs) = 2,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, writable, signer, name = "payer")]
        #[account(4, name = "mint_account")]
        #[account(5, writable, name = "config_account")]
        #[account(6, name = "system_program")]
        // Optional accounts, required by accounts meta management
        #[account(7, writable, optional, name = "account_metas_pda")]
        #[account(8, optional, name = "transfer_hook_pda")]
        #[account(9, optional, name = "transfer_hook_program")]
        UpdateVerificationConfig(UpdateVerificationConfigArgs) = 3,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, name = "mint_account")]
        #[account(4, writable, name = "config_account")]
        #[account(5, writable, name = "recipient")]
        #[account(6, name = "system_program")]
        // Optional accounts, required by accounts meta management
        #[account(7, writable, optional, name = "account_metas_pda")]
        #[account(8, optional, name = "transfer_hook_pda")]
        #[account(9, optional, name = "transfer_hook_program")]
        TrimVerificationConfig(TrimVerificationConfigArgs) = 4,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        Verify(VerifyArgs) = 5,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "mint_authority")]
        #[account(4, writable, name = "mint_account")]
        #[account(5, writable, name = "destination")]
        #[account(6, name = "token_program")]
        Mint { amount: u64 } = 6,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "permanent_delegate")]
        #[account(4, writable, name = "mint_account")]
        #[account(5, writable, name = "token_account")]
        #[account(6, name = "token_program")]
        Burn { amount: u64 } = 7,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "pause_authority")]
        #[account(4, writable, name = "mint_account")]
        #[account(5, name = "token_program")]
        Pause = 8,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "pause_authority")]
        #[account(4, writable, name = "mint_account")]
        #[account(5, name = "token_program")]
        Resume = 9,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "freeze_authority")]
        #[account(4, name = "mint_account")]
        #[account(5, writable, name = "token_account")]
        #[account(6, name = "token_program")]
        Freeze = 10,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "freeze_authority")]
        #[account(4, name = "mint_account")]
        #[account(5, writable, name = "token_account")]
        #[account(6, name = "token_program")]
        Thaw = 11,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "permanent_delegate_authority")]
        #[account(4, name = "mint_account")]
        #[account(5, writable, name = "from_token_account")]
        #[account(6, writable, name = "to_token_account")]
        #[account(7, name = "transfer_hook_program")]
        #[account(8, name = "token_program")]
        Transfer { amount: u64 } = 12,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, writable, signer, name = "payer")]
        #[account(4, writable, name = "rate_account")]
        #[account(5, name = "mint_from")]
        #[account(6, name = "mint_to")]
        #[account(7, name = "system_program")]
        CreateRateAccount(CreateRateArgs) = 13,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, writable, name = "rate_account")]
        #[account(4, name = "mint_from")]
        #[account(5, name = "mint_to")]
        UpdateRateAccount(UpdateRateArgs) = 14,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config_or_mint_authority")]
        #[account(2, name = "instructions_sysvar_or_creator")]
        // Instruction accounts
        #[account(3, writable, name = "rate_account")]
        #[account(4, writable, name = "destination")]
        #[account(5, name = "mint_from")]
        #[account(6, name = "mint_to")]
        CloseRateAccount(CloseRateArgs) = 15,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "mint_authority")]
        #[account(4, name = "permanent_delegate")]
        #[account(5, writable, signer, name = "payer")]
        #[account(6, writable, name = "mint_account")]
        #[account(7, writable, name = "token_account")]
        #[account(8, name = "rate_account")]
        #[account(9, writable, name = "receipt_account")]
        #[account(10, name = "token_program")]
        #[account(11, name = "system_program")]
        Split(SplitArgs) = 16,

        // Verification overhead
        #[account(0, name = "mint")]
        #[account(1, name = "verification_config")]
        #[account(2, name = "instructions_sysvar")]
        // Instruction accounts
        #[account(3, name = "mint_authority")]
        #[account(4, name = "permanent_delegate")]
        #[account(5, writable, signer, name = "payer")]
        #[account(6, writable, name = "mint_from")]
        #[account(7, writable, name = "mint_to")]
        #[account(8, writable, name = "token_account_from")]
        #[account(9, writable, name = "token_account_to")]
        #[account(10, name = "rate_account")]
        #[account(11, writable, name = "receipt_account")]
        #[account(12, name = "token_program")]
        #[account(13, name = "system_program")]
        Convert(ConvertArgs) = 17,
    }
}

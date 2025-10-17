use pinocchio::program_error::ProgramError;
use shank::ShankInstruction;

/// Security Token Program instructions
#[repr(u8)]
#[derive(Clone)]
pub enum SecurityTokenInstruction {
    /// Initialize a new security token mint with metadata and compliance features
    // #[account(0, writable, signer, name = "mint")]
    // #[account(1, signer, name = "payer")]
    // #[account(2, signer, name = "authority")]
    // #[account(3, name = "SPL Token 2022 Program")]
    // #[account(4, name = "System Program")]
    // #[account(5, name = "Rent Sysvar")]
    InitializeMint = 0,
    /// Update the metadata of an existing security token mint
    /// 0. `[]` The mint account
    /// 1. `[]` The verification config PDA account
    /// 2. `[]` Instructions sysvar (for introspection mode)
    ///
    /// * Authorization through mint authority
    /// 0. `[]` The mint account
    /// 1. `[]` The mint authority PDA account
    /// 2. `[signer]` The mint creator account
    ///
    /// 3. `[writable]` The mint account
    /// 4. `[signer]` The mint authority account
    /// 5. `[]` The SPL Token 2022 program ID
    /// 6. `[]` The system program ID - NOTE: Add lamports if needed
    /// 7. `[]` the remaining accounts for the verification purposes
    UpdateMetadata = 1,
    InitializeVerificationConfig = 2,
    /// Update verification configuration for an instruction
    /// Accounts expected:
    /// * Authorization through verification programs
    /// 0. `[]` The mint account
    /// 1. `[]` The verification config PDA account
    /// 2. `[]` Instructions sysvar (for introspection mode)
    ///
    /// * Authorization through mint authority
    /// 0. `[]` The mint account
    /// 1. `[]` The mint authority PDA account
    /// 2. `[signer]` The mint creator account
    ///
    /// * Instruction accounts:
    /// 3. `[writable]` The VerificationConfig PDA account
    /// 4. `[writable, signer]` The payer account  
    /// 5. `[]` The mint account
    /// 6. `[signer]` The authority account (mint authority)
    /// 7. `[]` The system program ID
    UpdateVerificationConfig = 3,
    /// Trim verification configuration for an instruction
    /// Accounts expected:
    /// * Authorization through verification programs
    /// 0. `[]` The mint account
    /// 1. `[]` The verification config PDA account
    /// 2. `[]` Instructions sysvar (for introspection mode)
    ///
    /// * Authorization through mint authority
    /// 0. `[]` The mint account
    /// 1. `[]` The mint authority PDA account
    /// 2. `[signer]` The mint creator account
    ///
    /// * Instruction accounts:
    /// 3. `[writable]` The VerificationConfig PDA account
    /// 4. `[writable]` The recipient account  
    /// 5. `[]` The mint account
    /// 6. `[signer]` The authority account (mint authority)
    /// 7. `[]` The system program ID
    TrimVerificationConfig = 4,
    /// Verify a security token instruction using configured verification programs
    /// Accounts expected:
    /// 0. `[]` The mint account
    /// 1. `[]` The verification config PDA account
    /// 2. `[]` Instructions sysvar (for introspection mode)
    /// 3. Remaining accounts depend on the instruction being verified and CPI mode requirements
    Verify = 5,
    /// Mint new tokens after verification succeeds
    /// Accounts expected:
    /// 0. `[]` The mint account (used for verification config PDA derivation)
    /// 1. `[]` The VerificationConfig PDA (optional; may be uninitialized when verification is disabled)
    /// 2. `[]` Instructions sysvar for introspection-based verification
    /// 3. `[signer]` Original mint creator account that matches the mint authority PDA seeds
    /// 4. `[writable]` SPL Token mint account
    /// 5. `[writable]` Mint authority PDA account (owned by this program)
    /// 6. `[writable]` Destination token account to receive newly minted tokens
    /// 7. `[]` System program account
    /// 8. `[]` SPL Token 2022 program account
    Mint = 6,
    /// Burn tokens from a holder account after verification succeeds
    /// Accounts expected:
    /// 0. `[]` The mint account (used for verification config PDA derivation)
    /// 1. `[]` The VerificationConfig PDA (optional; may be uninitialized when verification is disabled)
    /// 2. `[]` Instructions sysvar for introspection-based verification
    /// 3. `[writable]` SPL Token mint account
    /// 4. `[]` Permanent delegate PDA account derived for the mint (signs via PDA seeds)
    /// 5. `[writable]` Token account holding the balance to burn
    /// 6. `[]` SPL Token 2022 program account
    Burn = 7,
    /// Pause all token activity after verification succeeds
    /// Accounts expected:
    /// 0. `[]` The mint account (used for verification config PDA derivation)
    /// 1. `[]` The VerificationConfig PDA (optional; may be uninitialized when verification is disabled)
    /// 2. `[]` Instructions sysvar for introspection-based verification
    /// 3. `[writable]` SPL Token mint account (the mint to pause)
    /// 4. `[]` Pause authority PDA account derived for the mint
    /// 5. `[]` SPL Token 2022 program account
    Pause = 8,
    /// Resume all token activity after verification succeeds
    /// Accounts expected:
    /// 0. `[]` The mint account (used for verification config PDA derivation)
    /// 1. `[]` The VerificationConfig PDA (optional; may be uninitialized when verification is disabled)
    /// 2. `[]` Instructions sysvar for introspection-based verification
    /// 3. `[writable]` SPL Token mint account (the mint to resume)
    /// 4. `[]` Pause authority PDA account derived for the mint
    /// 5. `[]` SPL Token 2022 program account
    Resume = 9,
    /// Freeze a token account after verification succeeds
    /// Accounts expected:
    /// 0. `[]` The mint account (used for verification config PDA derivation)
    /// 1. `[]` The VerificationConfig PDA (optional; may be uninitialized when verification is disabled)
    /// 2. `[]` Instructions sysvar for introspection-based verification
    /// 3. `[]` SPL Token mint account
    /// 4. `[]` Freeze authority PDA account derived for the mint (signs via PDA seeds)
    /// 5. `[writable]` Token account that will be frozen
    /// 6. `[]` SPL Token 2022 program account
    Freeze = 10,
    /// Thaw a frozen token account after verification succeeds
    /// Accounts expected:
    /// 0. `[]` The mint account (used for verification config PDA derivation)
    /// 1. `[]` The VerificationConfig PDA (optional; may be uninitialized when verification is disabled)
    /// 2. `[]` Instructions sysvar for introspection-based verification
    /// 3. `[]` SPL Token mint account
    /// 4. `[]` Freeze authority PDA account derived for the mint (signs via PDA seeds)
    /// 5. `[writable]` Token account that will be thawed
    /// 6. `[]` SPL Token 2022 program account
    Thaw = 11,
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
        InitializeVerificationConfigArgs, TrimVerificationConfigArgs, UpdateVerificationConfigArgs,
    };

    #[derive(shank::ShankInstruction)]
    #[repr(u8)]
    enum _SecurityTokenInstruction {
        #[account(0, name = "mint", desc = "Mint used when deriving verification PDAs")]
        #[account(
            1,
            name = "verification_config_or_mint_authority",
            desc = "VerificationConfig PDA when using program verification, or MintAuthority PDA when using mint-authority fallback"
        )]
        #[account(
            2,
            name = "instructions_sysvar_or_creator",
            desc = "Instructions sysvar for CPI introspection (non-signer) or mint creator signer when using mint-authority fallback"
        )]
        #[account(
            3,
            writable,
            name = "config_account",
            desc = "VerificationConfig PDA being created"
        )]
        #[account(
            4,
            writable,
            signer,
            name = "payer",
            desc = "Payer funding the new VerificationConfig account"
        )]
        #[account(
            5,
            name = "mint_account",
            desc = "SPL Token 2022 mint the configuration applies to"
        )]
        #[account(
            6,
            name = "system_program",
            desc = "System program used for account creation"
        )]
        InitializeVerificationConfig(InitializeVerificationConfigArgs) = 2,

        #[account(0, name = "mint", desc = "Mint used when deriving verification PDAs")]
        #[account(
            1,
            name = "verification_config_or_mint_authority",
            desc = "VerificationConfig PDA when using program verification, or MintAuthority PDA when using mint-authority fallback"
        )]
        #[account(
            2,
            name = "instructions_sysvar_or_creator",
            desc = "Instructions sysvar for CPI introspection (non-signer) or mint creator signer when using mint-authority fallback"
        )]
        #[account(
            3,
            writable,
            name = "config_account",
            desc = "VerificationConfig PDA account to update"
        )]
        #[account(
            4,
            name = "mint_account",
            desc = "SPL Token 2022 mint the configuration applies to"
        )]
        #[account(
            5,
            writable,
            signer,
            name = "payer",
            desc = "Payer covering any additional rent during update"
        )]
        #[account(6, name = "system_program", desc = "System program for reallocations")]
        UpdateVerificationConfig(UpdateVerificationConfigArgs) = 3,

        #[account(0, name = "mint", desc = "Mint used when deriving verification PDAs")]
        #[account(
            1,
            name = "verification_config_or_mint_authority",
            desc = "VerificationConfig PDA when using program verification, or MintAuthority PDA when using mint-authority fallback"
        )]
        #[account(
            2,
            name = "instructions_sysvar_or_creator",
            desc = "Instructions sysvar for CPI introspection (non-signer) or mint creator signer when using mint-authority fallback"
        )]
        #[account(
            3,
            writable,
            name = "config_account",
            desc = "VerificationConfig PDA account to trim"
        )]
        #[account(
            4,
            name = "mint_account",
            desc = "SPL Token 2022 mint the configuration applies to"
        )]
        #[account(
            5,
            writable,
            name = "recipient",
            desc = "Recipient account that receives reclaimed lamports"
        )]
        #[account(
            6,
            name = "system_program",
            desc = "System program for closing or reallocating accounts"
        )]
        TrimVerificationConfig(TrimVerificationConfigArgs) = 4,
        
    }
}

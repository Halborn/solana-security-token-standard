//! ScaledUIAmount extension

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    pubkey::Pubkey,
    sysvars::clock::UnixTimestamp,
    ProgramResult,
};

use crate::token22_extensions::{write_bytes, BaseState, Extension, ExtensionType, UNINIT_BYTE};

pub const SCALED_UI_AMOUNT_CONFIG_LEN: usize = core::mem::size_of::<ScaledUiAmountConfig>();

/// ScaledUIAmount extension data
/// Multiplier for displaying token amounts
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScaledUiAmountConfig {
    /// Authority that can set the scaling amount and authority
    pub authority: Pubkey,
    /// Amount to multiply raw amounts by, outside of the decimal
    pub multiplier: [u8; 8],
    /// Unix timestamp at which `new_multiplier` comes into effective
    pub new_multiplier_effective_timestamp: UnixTimestamp,
    /// Next multiplier, once `new_multiplier_effective_timestamp` is reached
    pub new_multiplier: [u8; 8],
}

impl Extension for ScaledUiAmountConfig {
    const TYPE: ExtensionType = ExtensionType::ScaledUiAmount;
    const LEN: usize = SCALED_UI_AMOUNT_CONFIG_LEN;
    const BASE_STATE: BaseState = BaseState::Mint;
}

impl ScaledUiAmountConfig {
    /// Return a `ScaledUiAmountConfig` from the given account info.
    ///
    /// This method performs owner and length validation on `AccountInfo`, safe borrowing
    /// the account data.
    #[inline(always)]
    pub fn from_account_info_unchecked(
        account_info: &pinocchio::account_info::AccountInfo,
    ) -> Result<&ScaledUiAmountConfig, pinocchio::program_error::ProgramError> {
        super::get_extension_from_bytes(unsafe { account_info.borrow_data_unchecked() })
            .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)
    }
}

pub struct InitializeScaledUiAmount<'a> {
    /// The mint to initialize
    pub mint: &'a AccountInfo,
    /// The public key for the account that can update the multiplier
    pub authority: Option<Pubkey>,
    /// The initial multiplier
    pub multiplier: f64,
}

impl InitializeScaledUiAmount<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas = [AccountMeta::writable(self.mint.key())];

        // Instruction Layout
        // - [0] u8: instruction discriminator
        // - [1] u8: extension instruction discriminator
        // - [2..34] Pubkey: authority (32 bytes)
        // - [34..42] f64: multiplier (8 bytes)

        let mut instruction_data = [UNINIT_BYTE; 42];

        // Set discriminator as u8 at offset [0] & Set extension discriminator as u8 at offset [1]
        write_bytes(&mut instruction_data[0..2], &[43, 0]);
        // Set authority as Pubkey at offset [2..34]
        if let Some(authority) = self.authority {
            write_bytes(&mut instruction_data[2..34], authority.as_ref());
        } else {
            write_bytes(&mut instruction_data[2..34], &Pubkey::default());
        }
        // Set multiplier as f64 at offset [34..42]
        write_bytes(
            &mut instruction_data[34..42],
            &self.multiplier.to_le_bytes(),
        );
        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 42) },
        };

        invoke_signed(&instruction, &[self.mint], signers)?;

        Ok(())
    }
}

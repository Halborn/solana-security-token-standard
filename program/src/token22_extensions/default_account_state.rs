//! DefaultAccountState extension

const INSTRUCTION_DISCRIMINATOR: u8 = 28;
const SUBCOMMAND_INITIALIZE: u8 = 0;
const SUBCOMMAND_UPDATE: u8 = 1;

use crate::token22_extensions::{write_bytes, BaseState, Extension, ExtensionType, UNINIT_BYTE};
use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    program_error::ProgramError,
    ProgramResult,
};
pub use pinocchio_token_2022::state::AccountState;

/// DefaultAccountState extension data
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DefaultAccountStateExtension {
    pub state: u8,
}

impl Extension for DefaultAccountStateExtension {
    const TYPE: ExtensionType = ExtensionType::DefaultAccountState;
    const LEN: usize = 1;
    const BASE_STATE: BaseState = BaseState::Mint;
}

impl DefaultAccountStateExtension {
    #[inline(always)]
    pub fn from_account_info_unchecked(
        account_info: &AccountInfo,
    ) -> Result<&DefaultAccountStateExtension, ProgramError> {
        super::get_extension_from_bytes(unsafe { account_info.borrow_data_unchecked() })
            .ok_or(ProgramError::InvalidAccountData)
    }
}

/// Wrapper for InitializeDefaultAccountState.
///
/// Must be called before `InitializeMint`.
///
/// Instruction data: `[28, 0, state]`
/// where `28` = Token-2022 instruction discriminator for DefaultAccountState, `0` = Initialize sub-command.
pub struct InitializeDefaultAccountState<'a> {
    pub mint: &'a AccountInfo,
    pub state: AccountState,
}

impl InitializeDefaultAccountState<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas = [AccountMeta::writable(self.mint.key())];

        let mut instruction_data = [UNINIT_BYTE; 3];
        write_bytes(
            &mut instruction_data,
            &[
                INSTRUCTION_DISCRIMINATOR,
                SUBCOMMAND_INITIALIZE,
                self.state as u8,
            ],
        );

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 3) },
        };

        invoke_signed(&instruction, &[self.mint], signers)
    }
}

/// Wrapper for UpdateDefaultAccountState.
///
/// Instruction data: `[28, 1, state]`
/// where `28` = Token-2022 instruction discriminator for DefaultAccountState, `1` = Update sub-command.
///
/// Accounts: writable mint, signer freeze_authority.
pub struct UpdateDefaultAccountState<'a> {
    pub mint: &'a AccountInfo,
    pub freeze_authority: &'a AccountInfo,
    pub state: AccountState,
}

impl UpdateDefaultAccountState<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let instruction_data = [
            INSTRUCTION_DISCRIMINATOR,
            SUBCOMMAND_UPDATE,
            self.state as u8,
        ];
        let account_metas = [
            AccountMeta::writable(self.mint.key()),
            AccountMeta::readonly_signer(self.freeze_authority.key()),
        ];
        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };
        invoke_signed(&instruction, &[self.mint, self.freeze_authority], signers)
    }
}

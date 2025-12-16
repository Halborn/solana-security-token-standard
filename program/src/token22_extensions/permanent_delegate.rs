//! PermanentDelegate extension

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    pubkey::Pubkey,
    ProgramResult,
};

use crate::token22_extensions::{write_bytes, BaseState, Extension, ExtensionType, UNINIT_BYTE};

/// PermanentDelegate extension data
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PermanentDelegate {
    /// Permanent delegate authority
    pub delegate: [u8; 32],
}

impl Extension for PermanentDelegate {
    const TYPE: ExtensionType = ExtensionType::PermanentDelegate;
    const LEN: usize = 32;
    const BASE_STATE: BaseState = BaseState::Mint;
}

pub struct InitializePermanentDelegate<'a> {
    /// The mint to initialize the permanent delegate
    pub mint: &'a AccountInfo,
    /// The public key for the account that can close the mint
    pub delegate: Pubkey,
}

impl InitializePermanentDelegate<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas = [AccountMeta::writable(self.mint.key())];

        // Instruction data Layout:
        // -  [0]: instruction discriminator (1 byte, u8)
        // -  [1..33]: permanent delegate (32 bytes, Pubkey)
        let mut instruction_data = [UNINIT_BYTE; 33];
        // Set discriminator as u8 at offset [0]
        write_bytes(&mut instruction_data[0..1], &[35]);
        // Set permanent delegate as Pubkey at offset [1..33]
        write_bytes(&mut instruction_data[1..33], &self.delegate);

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 33) },
        };

        invoke_signed(&instruction, &[self.mint], signers)?;

        Ok(())
    }
}

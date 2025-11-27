//! Pausable extension

use crate::token22_extensions::{write_bytes, BaseState, Extension, ExtensionType, UNINIT_BYTE};
use pinocchio::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction, Signer},
    program::invoke_signed,
    pubkey::Pubkey,
    ProgramResult,
};

/// Pausable extension data
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pausable {
    /// Authority that can pause/resume the mint
    pub authority: [u8; 32],
    /// Whether minting / transferring / burning tokens is paused
    pub paused: u8,
}

impl Extension for Pausable {
    const TYPE: ExtensionType = ExtensionType::Pausable;
    const LEN: usize = 33;
    const BASE_STATE: BaseState = BaseState::Mint;
}

pub struct InitializePausable<'a> {
    /// The mint to initialize the pausable config
    pub mint: &'a AccountInfo,
    /// The public key for the account that can pause or resume activity on the mint
    pub authority: Pubkey,
}

impl InitializePausable<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas = [AccountMeta::writable(self.mint.key())];

        // Instruction data Layout:
        //[0] u8: instruction discriminator
        //[1] u8: extension instruction discriminator
        //[2..34] Pubkey: authority

        let mut instruction_data = [UNINIT_BYTE; 34];

        // Set the instruction discriminator
        write_bytes(&mut instruction_data[0..1], &[44]);
        // Set the extension ix discriminator
        write_bytes(&mut instruction_data[1..2], &[0]);
        // Set the authority
        write_bytes(&mut instruction_data[2..34], &self.authority);

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 34) },
        };

        invoke_signed(&instruction, &[self.mint], signers)?;

        Ok(())
    }
}

/// Wrapper for Pause instruction
pub struct Pause<'a> {
    /// The mint to pause
    pub mint: &'a AccountInfo,
    /// The mint's pause authority
    pub pause_authority: &'a AccountInfo,
}

impl Pause<'_> {
    /// Invoke the Pause instruction
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the Pause instruction with signers
    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.mint.key()),
            AccountMeta::readonly_signer(self.pause_authority.key()),
        ];

        // Instruction data Layout:
        // -  [0]: token instruction discriminator (PausableExtension = 44)
        // -  [1]: pausable extension sub-instruction (Pause = 1)
        let instruction_data = [44u8, 1u8];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(&instruction, &[self.mint, self.pause_authority], signers)?;

        Ok(())
    }
}

/// Wrapper for Resume instruction
pub struct Resume<'a> {
    /// The mint to resume
    pub mint: &'a AccountInfo,
    /// The mint's pause authority
    pub pause_authority: &'a AccountInfo,
}

impl Resume<'_> {
    /// Invoke the Resume instruction
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the Resume instruction with signers
    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.mint.key()),
            AccountMeta::readonly_signer(self.pause_authority.key()),
        ];

        // Instruction data Layout:
        // -  [0]: token instruction discriminator (PausableExtension = 44)
        // -  [1]: pausable extension sub-instruction (Resume = 2)
        let instruction_data = [44u8, 2u8];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(&instruction, &[self.mint, self.pause_authority], signers)?;

        Ok(())
    }
}

//! TransferHook extension

use crate::token22_extensions::{write_bytes, BaseState, Extension, ExtensionType, UNINIT_BYTE};
use pinocchio::{
    account_info::AccountInfo,
    cpi::{invoke_signed, slice_invoke_signed},
    instruction::{AccountMeta, Instruction, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use spl_tlv_account_resolution::account::ExtraAccountMeta;

/// Discriminator for "spl-transfer-hook-interface:initialize-extra-account-metas"
/// Calculated via: sha256("spl-transfer-hook-interface:initialize-extra-account-metas")[..8]
const INITIALIZE_EXTRA_ACCOUNT_META_LIST_DISCRIMINATOR: [u8; 8] =
    [0x2b, 0x22, 0x0d, 0x31, 0xa7, 0x58, 0xeb, 0xeb];

/// Discriminator for "spl-transfer-hook-interface:update-extra-account-metas"
/// Calculated via: sha256("spl-transfer-hook-interface:update-extra-account-metas")[..8]
const UPDATE_EXTRA_ACCOUNT_META_LIST_DISCRIMINATOR: [u8; 8] =
    [0x9d, 0x69, 0x2a, 0x92, 0x66, 0x55, 0xf1, 0xae];

/// TransferHook extension data
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransferHook {
    /// Authority that can update the program ID
    pub authority: [u8; 32],
    /// Program ID to call on transfer
    pub program_id: [u8; 32],
}

impl Extension for TransferHook {
    const TYPE: ExtensionType = ExtensionType::TransferHook;
    const LEN: usize = 64;
    const BASE_STATE: BaseState = BaseState::Mint;
}

pub struct InitializeTransferHook<'a> {
    /// Mint of the transfer hook
    pub mint: &'a AccountInfo,
    /// The public key for the account that can update the transfer hook program id
    pub authority: Option<Pubkey>,
    /// The program id that authorizes the transfer
    pub program_id: Option<Pubkey>,
}

impl InitializeTransferHook<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> Result<(), ProgramError> {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> Result<(), ProgramError> {
        // account metas
        let account_metas = [AccountMeta::writable(self.mint.key())];

        // Instruction data layout:
        // [0] : instruction discriminator (1 byte, u8)
        // [1] : extension instruction discriminator (1 byte, u8)
        // [2..34] : authority (32 bytes, Pubkey)
        // [34..66] : program_id (32 bytes, Pubkey)
        let mut instruction_data = [UNINIT_BYTE; 66];

        // Set discriminator as u8 at offset [0] & Set extension discriminator as u8 at offset [1]
        write_bytes(&mut instruction_data[0..2], &[36, 0]);
        // Set authority at offset [2..34]
        if let Some(authority) = self.authority {
            write_bytes(&mut instruction_data[2..34], &authority);
        } else {
            write_bytes(&mut instruction_data[2..34], &Pubkey::default());
        }
        // Set program_id at offset [34..66]
        if let Some(program_id) = self.program_id {
            write_bytes(&mut instruction_data[34..66], &program_id);
        } else {
            write_bytes(&mut instruction_data[34..66], &Pubkey::default());
        }
        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 66) },
        };

        invoke_signed(&instruction, &[self.mint], signers)?;

        Ok(())
    }
}

/// Wrapper for InitializeExtraAccountMetaList instruction
///
/// This instruction creates the extra_account_metas PDA and initializes it.
/// The Transfer Hook program will create the PDA via CPI to System Program.
pub struct InitializeExtraAccountMetaList<'a> {
    /// The transfer hook program ID
    pub program_id: &'a Pubkey,
    /// PDA address for extra account metas (will be created by Transfer Hook program)
    pub extra_account_metas_pda: &'a AccountInfo,
    /// Mint pubkey
    pub mint: &'a AccountInfo,
    /// Mint authority AccountInfo (needs to sign)
    pub authority: &'a AccountInfo,
    /// System program pubkey
    pub system_program: &'a AccountInfo,
    /// List of extra account metas to initialize
    pub metas: &'a [ExtraAccountMeta],
}

impl<'a> InitializeExtraAccountMetaList<'a> {
    /// Create a new InitializeExtraAccountMetaList instruction wrapper
    /// Invoke the instruction
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the instruction with signers
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Calculate instruction data size
        // 8 byte discriminator + 4 bytes vec length + (35 bytes per ExtraAccountMeta)
        let data_len = 8 + 4 + (self.metas.len() * 35);
        let mut instruction_data = Vec::with_capacity(data_len);

        // 8-byte discriminator for initialize-extra-account-metas
        instruction_data.extend(&INITIALIZE_EXTRA_ACCOUNT_META_LIST_DISCRIMINATOR);

        instruction_data.extend(&(self.metas.len() as u32).to_le_bytes());
        for meta in self.metas {
            instruction_data.extend(bytemuck::bytes_of(meta));
        }

        let account_metas: [AccountMeta; 4] = [
            AccountMeta::writable(self.extra_account_metas_pda.key()),
            AccountMeta::readonly(self.mint.key()),
            AccountMeta::readonly_signer(self.authority.key()),
            AccountMeta::readonly(self.system_program.key()),
        ];

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: &account_metas,
            data: &instruction_data,
        };
        invoke_signed(
            &instruction,
            &[
                self.extra_account_metas_pda,
                self.mint,
                self.authority,
                self.system_program,
            ],
            signers,
        )
    }
}

/// Wrapper for UpdateExtraAccountMetaList instruction
///
/// This instruction updates existing extra account metas in the PDA.
pub struct UpdateExtraAccountMetaList<'a> {
    /// The transfer hook program ID
    pub program_id: &'a Pubkey,
    /// PDA address for extra account metas (must already exist)
    pub extra_account_metas_pda: &'a AccountInfo,
    /// Mint pubkey
    pub mint: &'a AccountInfo,
    /// Mint authority AccountInfo (needs to sign)
    pub authority: &'a AccountInfo,
    /// System program pubkey
    pub system_program: &'a AccountInfo,
    /// Optional recipient pubkey
    pub recipient: Option<&'a AccountInfo>,
    /// List of extra account metas to update
    pub metas: &'a [ExtraAccountMeta],
}

impl<'a> UpdateExtraAccountMetaList<'a> {
    /// Create a new UpdateExtraAccountMetaList instruction wrapper
    /// Invoke the instruction
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the instruction with signers
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Calculate instruction data size
        // 8 byte discriminator + 4 bytes vec length + (35 bytes per ExtraAccountMeta)
        let data_len = 8 + 4 + (self.metas.len() * 35);
        let mut instruction_data = Vec::with_capacity(data_len);

        // 8-byte discriminator for update-extra-account-metas
        instruction_data.extend(&UPDATE_EXTRA_ACCOUNT_META_LIST_DISCRIMINATOR);

        // Vec length (u32 little-endian)
        instruction_data.extend(&(self.metas.len() as u32).to_le_bytes());

        // Serialize each ExtraAccountMeta
        for meta in self.metas {
            instruction_data.extend(bytemuck::bytes_of(meta));
        }

        let mut account_metas = vec![
            AccountMeta::writable(self.extra_account_metas_pda.key()),
            AccountMeta::readonly(self.mint.key()),
            AccountMeta::readonly_signer(self.authority.key()),
            AccountMeta::readonly(self.system_program.key()),
        ];

        let mut account_infos = vec![
            self.extra_account_metas_pda,
            self.mint,
            self.authority,
            self.system_program,
        ];

        if let Some(recipient) = self.recipient {
            account_metas.push(AccountMeta::writable(recipient.key()));
            account_infos.push(recipient);
        }

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: &account_metas,
            data: &instruction_data,
        };
        slice_invoke_signed(&instruction, &account_infos, signers)
    }
}

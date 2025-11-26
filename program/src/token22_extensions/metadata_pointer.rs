//! MetadataPointer extension

use crate::token22_extensions::{write_bytes, BaseState, Extension, ExtensionType, UNINIT_BYTE};
use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    pubkey::Pubkey,
    ProgramResult,
};

/// MetadataPointer extension data
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetadataPointer {
    /// Authority that can set the metadata address
    pub authority: [u8; 32],
    /// Account address that holds the metadata
    pub metadata_address: [u8; 32],
}

impl Extension for MetadataPointer {
    const TYPE: ExtensionType = ExtensionType::MetadataPointer;
    const LEN: usize = 64;
    const BASE_STATE: BaseState = BaseState::Mint;
}

pub struct InitializeMetadataPointer<'a> {
    /// The mint that this metadata pointer is associated with
    pub mint: &'a AccountInfo,
    /// The public key for the account that can update the metadata address
    pub authority: Option<Pubkey>,
    /// The account address that holds the metadata
    pub metadata_address: Option<Pubkey>,
}

impl InitializeMetadataPointer<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Instruction data layout:
        // -  [0] u8: instruction discriminator
        // -  [1] u8: extension instruction discriminator
        // -  [2..34] Pubkey: authority (32 bytes)
        // -  [34..66] Pubkey: metadata_address (32 bytes)
        let mut instruction_data = [UNINIT_BYTE; 66];
        // Set discriminator as u8 at offset [0] & Set extension discriminator as u8 at offset [1]
        write_bytes(&mut instruction_data[0..2], &[39, 0]);
        // Set authority at offset [2..34]
        if let Some(authority) = self.authority {
            write_bytes(&mut instruction_data[2..34], &authority);
        } else {
            write_bytes(&mut instruction_data[2..34], &Pubkey::default());
        }
        // Set metadata_address at offset [34..66]
        if let Some(metadata_address) = self.metadata_address {
            write_bytes(&mut instruction_data[34..66], &metadata_address);
        } else {
            write_bytes(&mut instruction_data[34..66], &Pubkey::default());
        }

        let account_metas: [AccountMeta; 1] = [AccountMeta::writable(self.mint.key())];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 66) },
        };

        invoke_signed(&instruction, &[self.mint], signers)
    }
}

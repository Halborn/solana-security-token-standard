//! SBF-compatible Token 2022 wrappers
//! 
//! Custom wrappers for SPL Token 2022 operations that work within SBF constraints:
//! - No Vec allocation (use static arrays)  
//! - No heap allocation (stack only)
//! - Optimized buffer sizes

use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use pinocchio::ProgramResult;
use pinocchio_token_2022::extensions::metadata::{
    Field, InitializeTokenMetadata, TokenMetadata, UpdateField,
};

/// SBF-compatible wrapper for RemoveKey instruction
pub struct CustomRemoveKey<'a> {
    /// The metadata account to update.
    pub metadata: &'a AccountInfo,
    /// The account authorized to update the metadata.
    pub update_authority: &'a AccountInfo,
    /// The key to remove from the metadata.
    pub key: &'a str,
    /// Whether the operation should be idempotent.
    pub idempotent: bool,
}

impl<'a> CustomRemoveKey<'a> {
    /// Create new SBF-compatible wrapper for RemoveKey
    pub fn new(
        metadata: &'a AccountInfo,
        update_authority: &'a AccountInfo,
        key: &'a str,
        idempotent: bool,
    ) -> Self {
        Self {
            metadata,
            update_authority,
            key,
            idempotent,
        }
    }

    /// Custom invoke implementation using static arrays for SBF compatibility
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Custom invoke_signed implementation using static arrays for SBF compatibility
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Calculate instruction length for RemoveKey
        let ix_len = 8 // instruction discriminator
            + 1 // idempotent flag
            + 4 // key length
            + self.key.len(); // key data

        // Conservative limit based on typical metadata key sizes (most keys are < 100 bytes)
        const MAX_INSTRUCTION_SIZE: usize = 256; 
        if ix_len > MAX_INSTRUCTION_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut ix_data = [0u8; MAX_INSTRUCTION_SIZE];
        let mut offset = 0;

        // Set 8-byte discriminator for RemoveKey
        // Based on spl_token_metadata_interface:remove_key_ix hash
        let discriminator: [u8; 8] = [234, 18, 32, 56, 89, 141, 37, 181];
        ix_data[offset..offset + 8].copy_from_slice(&discriminator);
        offset += 8;

        // Set idempotent flag
        ix_data[offset] = if self.idempotent { 1 } else { 0 };
        offset += 1;

        // Set serialized key data
        let key_len = self.key.len() as u32;
        let key_len_bytes = key_len.to_le_bytes();
        ix_data[offset..offset + 4].copy_from_slice(&key_len_bytes);
        offset += 4;

        let key_bytes = self.key.as_bytes();
        ix_data[offset..offset + key_bytes.len()].copy_from_slice(key_bytes);

        // Create account metas
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.metadata.key()),
            AccountMeta::readonly_signer(self.update_authority.key()),
        ];

        // Get token program from metadata account owner
        // SAFETY: The metadata account is owned by the token program
        let token_program_id = unsafe { *self.metadata.owner() };

        let instruction = Instruction {
            program_id: &token_program_id,
            accounts: &account_metas,
            data: &ix_data[..ix_len],
        };

        use pinocchio::cpi::invoke_signed;
        invoke_signed(
            &instruction,
            &[self.metadata, self.update_authority],
            signers,
        )
    }
}

/// SBF-compatible wrapper for UpdateField that uses static arrays instead of Vec
pub struct CustomUpdateField<'a> {
    inner: UpdateField<'a>,
}

impl<'a> CustomUpdateField<'a> {
    /// Create new SBF-compatible wrapper for UpdateField
    pub fn new(
        metadata: &'a AccountInfo,
        update_authority: &'a AccountInfo,
        field: Field<'a>,
        value: &'a str,
    ) -> Self {
        Self {
            inner: UpdateField {
                metadata,
                update_authority,
                field,
                value,
            },
        }
    }

    /// Custom invoke implementation using static arrays for SBF compatibility
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Custom invoke_signed implementation using static arrays for SBF compatibility
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Calculate instruction length based on field type
        let ix_len = 8 // instruction discriminator
            + 1 // field type
            + if let Field::Key(key) = self.inner.field {
                4 + key.len() // key length + key data
            } else {
                0
            }
            + 4 // value length
            + self.inner.value.len(); // value data

        // More realistic limit for metadata updates (key + value usually < 500 bytes)
        const MAX_INSTRUCTION_SIZE: usize = 512;
        if ix_len > MAX_INSTRUCTION_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut ix_data = [0u8; MAX_INSTRUCTION_SIZE];
        let mut offset = 0;

        // Set 8-byte discriminator for UpdateField
        let discriminator: [u8; 8] = [221, 233, 49, 45, 181, 202, 220, 200];
        ix_data[offset..offset + 8].copy_from_slice(&discriminator);
        offset += 8;

        // Set field type
        ix_data[offset] = self.inner.field.to_u8();
        offset += 1;

        // Set serialized key data if Field is Key type
        if let Field::Key(key) = self.inner.field {
            let key_len = key.len() as u32;
            let key_len_bytes = key_len.to_le_bytes();
            ix_data[offset..offset + 4].copy_from_slice(&key_len_bytes);
            offset += 4;

            let key_bytes = key.as_bytes();
            ix_data[offset..offset + key_bytes.len()].copy_from_slice(key_bytes);
            offset += key_bytes.len();
        }

        // Set serialized value data
        let value_len = self.inner.value.len() as u32;
        let value_len_bytes = value_len.to_le_bytes();
        ix_data[offset..offset + 4].copy_from_slice(&value_len_bytes);
        offset += 4;

        let value_bytes = self.inner.value.as_bytes();
        ix_data[offset..offset + value_bytes.len()].copy_from_slice(value_bytes);

        // Create account metas
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.inner.metadata.key()),
            AccountMeta::readonly_signer(self.inner.update_authority.key()),
        ];

        // Get token program from metadata account owner
        // SAFETY: The metadata account is owned by the token program
        let token_program_id = unsafe { *self.inner.metadata.owner() };

        let instruction = Instruction {
            program_id: &token_program_id,
            accounts: &account_metas,
            data: &ix_data[..ix_len],
        };

        use pinocchio::cpi::invoke_signed;
        invoke_signed(
            &instruction,
            &[self.inner.metadata, self.inner.update_authority],
            signers,
        )
    }
}

/// SBF-compatible wrapper for InitializeTokenMetadata
pub struct CustomInitializeTokenMetadata<'a> {
    inner: InitializeTokenMetadata<'a>,
}

impl<'a> CustomInitializeTokenMetadata<'a> {
    /// Create new SBF-compatible wrapper
    pub fn new(
        metadata: &'a AccountInfo,
        update_authority: &'a AccountInfo,
        mint: &'a AccountInfo,
        mint_authority: &'a AccountInfo,
        name: &'a str,
        symbol: &'a str,
        uri: &'a str,
    ) -> Self {
        Self {
            inner: InitializeTokenMetadata {
                metadata,
                update_authority,
                mint,
                mint_authority,
                name,
                symbol,
                uri,
            },
        }
    }

    /// Custom invoke implementation using static arrays for SBF compatibility
    pub fn invoke(&self) -> ProgramResult {
        // Calculate instruction length
        let ix_len = 8 // instruction discriminator
            + 4 // name length
            + self.inner.name.len()
            + 4 // symbol length
            + self.inner.symbol.len()
            + 4 // uri length
            + self.inner.uri.len();

        // Realistic limit for token metadata (name + symbol + URI typically < 400 bytes)
        const MAX_INSTRUCTION_SIZE: usize = 512;
        if ix_len > MAX_INSTRUCTION_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut ix_data = [0u8; MAX_INSTRUCTION_SIZE];
        let mut offset = 0;

        // Set 8-byte discriminator for InitializeTokenMetadata
        let discriminator: [u8; 8] = [210, 225, 30, 162, 88, 184, 77, 141];
        ix_data[offset..offset + 8].copy_from_slice(&discriminator);
        offset += 8;

        // Set name length and name data bytes
        let name_len = self.inner.name.len() as u32;
        let name_len_bytes = name_len.to_le_bytes();
        ix_data[offset..offset + 4].copy_from_slice(&name_len_bytes);
        offset += 4;
        let name_bytes = self.inner.name.as_bytes();
        ix_data[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
        offset += name_bytes.len();

        // Set symbol length and symbol data bytes
        let symbol_len = self.inner.symbol.len() as u32;
        let symbol_len_bytes = symbol_len.to_le_bytes();
        ix_data[offset..offset + 4].copy_from_slice(&symbol_len_bytes);
        offset += 4;
        let symbol_bytes = self.inner.symbol.as_bytes();
        ix_data[offset..offset + symbol_bytes.len()].copy_from_slice(symbol_bytes);
        offset += symbol_bytes.len();

        // Set uri length and uri data bytes
        let uri_len = self.inner.uri.len() as u32;
        let uri_len_bytes = uri_len.to_le_bytes();
        ix_data[offset..offset + 4].copy_from_slice(&uri_len_bytes);
        offset += 4;
        let uri_bytes = self.inner.uri.as_bytes();
        ix_data[offset..offset + uri_bytes.len()].copy_from_slice(uri_bytes);

        // Create account metas
        let account_metas: [AccountMeta; 4] = [
            AccountMeta::writable(self.inner.metadata.key()),
            AccountMeta::readonly(self.inner.update_authority.key()),
            AccountMeta::readonly(self.inner.mint.key()),
            AccountMeta::readonly_signer(self.inner.mint_authority.key()),
        ];

        // Get token program from metadata account owner
        // SAFETY: The metadata account is owned by the token program
        let token_program_id = unsafe { *self.inner.metadata.owner() };

        let instruction = Instruction {
            program_id: &token_program_id,
            accounts: &account_metas,
            data: &ix_data[..ix_len],
        };

        use pinocchio::cpi::invoke_signed;
        invoke_signed(
            &instruction,
            &[
                self.inner.metadata,
                self.inner.update_authority,
                self.inner.mint,
                self.inner.mint_authority,
            ],
            &[],
        )
    }
}

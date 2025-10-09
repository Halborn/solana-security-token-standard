//! Token extension wrappers

use pinocchio::account_info::AccountInfo;
use pinocchio::cpi::invoke_signed;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::ProgramResult;
use pinocchio_token_2022::extensions::metadata::InitializeTokenMetadata;

/// Wrapper for RemoveKey instruction
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
    /// Create new for RemoveKey
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

    /// Custom invoke implementation
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Custom invoke_signed implementation
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Calculate instruction length for RemoveKey
        let ix_len = 8 // instruction discriminator
            + 1 // idempotent flag
            + 4 // key length
            + self.key.len(); // key data

        let mut ix_data: Vec<u8> = Vec::with_capacity(ix_len);

        // Set 8-byte discriminator for RemoveKey
        // Based on spl_token_metadata_interface:remove_key_ix hash
        let discriminator: [u8; 8] = [234, 18, 32, 56, 89, 141, 37, 181];
        ix_data.extend(discriminator);

        // Set idempotent flag
        ix_data.push(if self.idempotent { 1 } else { 0 });

        // Set serialized key data
        let key_len = self.key.len() as u32;
        ix_data.extend(&key_len.to_le_bytes());
        ix_data.extend(self.key.as_bytes());

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
            data: &ix_data,
        };

        use pinocchio::cpi::invoke_signed;
        invoke_signed(
            &instruction,
            &[self.metadata, self.update_authority],
            signers,
        )
    }
}

/// Wrapper for InitializeTokenMetadata
pub struct CustomInitializeTokenMetadata<'a> {
    inner: InitializeTokenMetadata<'a>,
}

impl<'a> CustomInitializeTokenMetadata<'a> {
    /// Create new wrapper
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

    /// Invoke the InitializeTokenMetadata instruction
    pub fn invoke(&self) -> ProgramResult {
        let ix_len = 8 // instruction discriminator
                + 4 // name length
                + self.inner.name.len()
                + 4 // symbol length
                + self.inner.symbol.len()
                + 4 // uri length
                + self.inner.uri.len();
        let mut ix_data: Vec<u8> = Vec::with_capacity(ix_len);
        // Set 8-byte discriminator.
        let discriminator: [u8; 8] = [210, 225, 30, 162, 88, 184, 77, 141];
        ix_data.extend(discriminator);

        // Set name length and name data bytes.
        let name_len = self.inner.name.len() as u32;
        ix_data.extend(&name_len.to_le_bytes());
        ix_data.extend(self.inner.name.as_bytes());

        // Set symbol length and symbol data bytes.
        let symbol_len = self.inner.symbol.len() as u32;
        ix_data.extend(&symbol_len.to_le_bytes());
        ix_data.extend(self.inner.symbol.as_bytes());

        // Set uri length and uri data bytes.
        let uri_len = self.inner.uri.len() as u32;
        ix_data.extend(&uri_len.to_le_bytes());
        ix_data.extend(self.inner.uri.as_bytes());

        let account_metas: [AccountMeta; 4] = [
            AccountMeta::writable(self.inner.metadata.key()),
            AccountMeta::readonly(self.inner.update_authority.key()),
            AccountMeta::readonly(self.inner.mint.key()),
            AccountMeta::readonly_signer(self.inner.mint_authority.key()),
        ];

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

/// Wrapper for the Pause instruction.
pub struct CustomPause<'a> {
    /// The mint to pause
    pub mint: &'a AccountInfo,
    /// The mint's pause authority
    pub pause_authority: &'a AccountInfo,
}

impl CustomPause<'_> {
    /// Invoke the Pause instruction.
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the Pause instruction with signers.
    /// NOTE: The implementation from the third party repository has wrong data bytes and account metas.
    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.mint.key()),
            AccountMeta::readonly_signer(self.pause_authority.key()),
        ];
        // Instruction data Layout:
        // -  [0]: token instruction discriminator (PausableExtension)
        // -  [1]: pausable extension sub-instruction (Pause)
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

/// Wrapper for the Resume instruction.
pub struct CustomResume<'a> {
    /// The mint to pause
    pub mint: &'a AccountInfo,
    /// The mint's pause authority
    pub pause_authority: &'a AccountInfo,
}

impl CustomResume<'_> {
    /// Invoke the Resume instruction.
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the Resume instruction with signers.
    /// NOTE: The implementation from the third party repository has wrong data bytes and account metas.
    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.mint.key()),
            AccountMeta::readonly_signer(self.pause_authority.key()),
        ];
        // Instruction data Layout:
        // -  [0]: token instruction discriminator (PausableExtension)
        // -  [1]: pausable extension sub-instruction (Resume)
        let instruction_data = [44u8, 2];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(&instruction, &[self.mint, self.pause_authority], signers)?;

        Ok(())
    }
}

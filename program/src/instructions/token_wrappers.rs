//! Token extension wrappers

use bytemuck;
use pinocchio::account_info::AccountInfo;
use pinocchio::cpi::{invoke_signed, slice_invoke_signed};
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::pubkey::Pubkey;
use pinocchio::ProgramResult;
use pinocchio_token_2022::extensions::metadata::InitializeTokenMetadata;
use spl_tlv_account_resolution::account::ExtraAccountMeta;

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
        self.invoke_signed(&[])
    }

    /// Invoke the InitializeTokenMetadata instruction with signers
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
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
            signers,
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

/// Wrapper for the TransferChecked instruction that supports passing remaining accounts.
pub struct CustomTransferChecked<'a> {
    /// The mint whose tokens are being transferred.
    pub mint: &'a AccountInfo,
    /// The source token account.
    pub from: &'a AccountInfo,
    /// The destination token account.
    pub to: &'a AccountInfo,
    /// Authority allowed to transfer tokens.
    pub authority: &'a AccountInfo,
    /// Amount of tokens to transfer (raw units).
    pub amount: u64,
    /// Mint decimals needed for checked transfer.
    pub decimals: u8,
    pub transfer_hook_program: &'a AccountInfo,
}

impl<'a> CustomTransferChecked<'a> {
    /// Construct a new wrapper instance.
    pub fn new(
        mint: &'a AccountInfo,
        from: &'a AccountInfo,
        to: &'a AccountInfo,
        authority: &'a AccountInfo,
        amount: u64,
        decimals: u8,
        transfer_hook_program: &'a AccountInfo,
    ) -> Self {
        Self {
            mint,
            from,
            to,
            authority,
            amount,
            decimals,
            transfer_hook_program,
        }
    }

    /// Invoke the TransferChecked instruction.
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the TransferChecked instruction with signer seeds.
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // account metadata
        let account_metas: [AccountMeta; 5] = [
            AccountMeta::writable(self.from.key()),
            AccountMeta::readonly(self.mint.key()),
            AccountMeta::writable(self.to.key()),
            AccountMeta::readonly_signer(self.authority.key()),
            AccountMeta::readonly(self.transfer_hook_program.key()),
        ];

        // Instruction data layout:
        // -  [0]: instruction discriminator (1 byte, u8)
        // -  [1..9]: amount (8 bytes, u64)
        // -  [9]: decimals (1 byte, u8)
        let mut instruction_data = [0u8; 10];

        // Set discriminator at offset [0]
        instruction_data[0] = 12;
        // Set amount at offset [1..9]
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());
        // Set decimals at offset [9]
        instruction_data[9] = self.decimals;

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(
            &instruction,
            &[
                self.from,
                self.mint,
                self.to,
                self.authority,
                self.transfer_hook_program,
            ],
            signers,
        )
    }
}

/// Wrapper for InitializeExtraAccountMetaList instruction
///
/// This instruction creates the extra_account_metas PDA and initializes it.
/// The Transfer Hook program will create the PDA via CPI to System Program.
pub struct CustomInitializeExtraAccountMetaList<'a> {
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

impl<'a> CustomInitializeExtraAccountMetaList<'a> {
    /// Create a new InitializeExtraAccountMetaList instruction wrapper
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program_id: &'a Pubkey,
        extra_account_metas_pda: &'a AccountInfo,
        mint: &'a AccountInfo,
        authority: &'a AccountInfo,
        system_program: &'a AccountInfo,
        metas: &'a [ExtraAccountMeta],
    ) -> Self {
        Self {
            program_id,
            extra_account_metas_pda,
            mint,
            authority,
            system_program,
            metas,
        }
    }

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

        // 8-byte ArrayDiscriminator for "spl-transfer-hook-interface:initialize-extra-account-metas"
        // Calculated via: sha256("spl-transfer-hook-interface:initialize-extra-account-metas")[..8]
        instruction_data.extend(&[0x2b, 0x22, 0x0d, 0x31, 0xa7, 0x58, 0xeb, 0xeb]);

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
pub struct CustomUpdateExtraAccountMetaList<'a> {
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

impl<'a> CustomUpdateExtraAccountMetaList<'a> {
    /// Create a new UpdateExtraAccountMetaList instruction wrapper
    pub fn new(
        program_id: &'a Pubkey,
        extra_account_metas_pda: &'a AccountInfo,
        mint: &'a AccountInfo,
        authority: &'a AccountInfo,
        system_program: &'a AccountInfo,
        recipient: Option<&'a AccountInfo>,
        metas: &'a [ExtraAccountMeta],
    ) -> Self {
        Self {
            program_id,
            extra_account_metas_pda,
            mint,
            authority,
            system_program,
            recipient,
            metas,
        }
    }

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

        // 8-byte ArrayDiscriminator for "spl-transfer-hook-interface:update-extra-account-metas"
        // Calculated via: sha256("spl-transfer-hook-interface:update-extra-account-metas")[..8]
        instruction_data.extend(&[0x9d, 0x69, 0x2a, 0x92, 0x66, 0x55, 0xf1, 0xae]);

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

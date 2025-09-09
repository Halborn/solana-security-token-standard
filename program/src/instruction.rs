use num_derive::FromPrimitive;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use pinocchio::ProgramResult;
use pinocchio_token_2022::extensions::metadata::{
    Field, InitializeTokenMetadata, TokenMetadata, UpdateField,
};
use pinocchio_token_2022::extensions::metadata_pointer::MetadataPointer;
use pinocchio_token_2022::extensions::scaled_ui_amount::ScaledUiAmountConfig;

/// SBF contradicts with the Vector in the original InitializeTokenMetadata
pub struct CustomInitializeTokenMetadata<'a> {
    inner: InitializeTokenMetadata<'a>,
}

/// SBF-compatible wrapper for UpdateField that uses static arrays instead of Vec
pub struct CustomUpdateField<'a> {
    inner: UpdateField<'a>,
}

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
                              // TODO: Review
        if ix_len > 512 {
            return Err(ProgramError::Custom(0xDEAD));
        }

        let mut ix_data = [0u8; 512];
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
                                      // TODO: Review
        if ix_len > 512 {
            return Err(ProgramError::Custom(0xDEAD));
        }

        let mut ix_data = [0u8; 512];
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
        // TODO: Review
        if ix_len > 512 {
            return Err(ProgramError::Custom(0xDEAD));
        }

        let mut ix_data = [0u8; 512];
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

/// Follows the pinocchio::instruction::TokenInstruction::InitializeMint
#[repr(C)]
#[derive(Clone, Debug)]
pub struct InitializeMintArgs {
    /// Number of decimals for the token
    pub decimals: u8,
    /// Mint authority public key
    pub mint_authority: Pubkey,
    /// Optional freeze authority public key
    pub freeze_authority: Option<Pubkey>,
}

impl InitializeMintArgs {
    /// Pack the mint arguments into bytes using the same format as SPL Token 2022
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Pack decimals (1 byte)
        buf.push(self.decimals);

        // Pack mint authority (32 bytes)
        buf.extend_from_slice(self.mint_authority.as_ref());

        // Pack freeze authority option (1 byte flag + 32 bytes if Some)
        if let Some(freeze_auth) = self.freeze_authority {
            buf.push(1); // has freeze authority
            buf.extend_from_slice(freeze_auth.as_ref());
        } else {
            buf.push(0); // no freeze authority
        }

        buf
    }

    /// Unpack mint arguments from bytes
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 34 {
            // minimum: 1 (decimals) + 32 (mint_authority) + 1 (freeze_authority flag)
            return Err(ProgramError::InvalidInstructionData);
        }

        let decimals = data[0];
        let mint_authority: Pubkey = data[1..33]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        let freeze_authority = if data[33] == 1 {
            if data.len() < 66 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Some(
                data[34..66]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            )
        } else {
            None
        };

        Ok(Self {
            decimals,
            mint_authority,
            freeze_authority,
        })
    }
}

/// Arguments for Initialize instruction that supports both mint and metadata
#[repr(C)]
#[derive(Clone)]
pub struct InitializeArgs<'a> {
    /// Basic mint arguments
    pub ix_mint: InitializeMintArgs,
    /// Optional metadata pointer configuration
    pub ix_metadata_pointer: Option<MetadataPointer>,
    /// Optional metadata
    pub ix_metadata: Option<TokenMetadata<'a>>,
    /// Optional scaled UI amount configuration
    pub ix_scaled_ui_amount: Option<ScaledUiAmountConfig>,
}

impl<'a> std::fmt::Debug for InitializeArgs<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitializeArgs")
            .field("ix_mint", &self.ix_mint)
            .field("ix_metadata_pointer", &self.ix_metadata_pointer)
            .field("ix_metadata", &self.ix_metadata)
            .field("ix_scaled_ui_amount", &self.ix_scaled_ui_amount)
            .finish()
    }
}

impl<'a> InitializeArgs<'a> {
    /// Internal parser that returns both TokenMetadata and number of bytes consumed
    fn parse_token_metadata(data: &'a [u8]) -> Result<(TokenMetadata<'a>, usize), ProgramError> {
        if data.len() < TokenMetadata::SIZE_METADATA_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        let mut offset: usize = 0;

        // Read update_authority (32 bytes)
        let update_authority = Pubkey::from(
            <[u8; 32]>::try_from(&data[offset..offset + 32])
                .map_err(|_| ProgramError::InvalidRealloc)?,
        );
        offset += 32;

        // Read mint (32 bytes)
        let mint = Pubkey::from(
            <[u8; 32]>::try_from(&data[offset..offset + 32])
                .map_err(|_| ProgramError::InvalidRealloc)?,
        );
        offset += 32;

        // Read name_len (4 bytes)
        let name_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidRealloc)?,
        );
        offset += 4;

        // Read name string
        if data.len() < offset + name_len as usize {
            return Err(ProgramError::InvalidRealloc);
        }
        let name = core::str::from_utf8(&data[offset..offset + name_len as usize])
            .map_err(|_| ProgramError::InvalidRealloc)?;
        offset += name_len as usize;

        // Read symbol_len (4 bytes)
        let symbol_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidRealloc)?,
        );
        offset += 4;

        // Read symbol string
        if data.len() < offset + symbol_len as usize {
            return Err(ProgramError::InvalidRealloc);
        }
        let symbol = core::str::from_utf8(&data[offset..offset + symbol_len as usize])
            .map_err(|_| ProgramError::InvalidRealloc)?;
        offset += symbol_len as usize;

        // Read uri_len (4 bytes)
        let uri_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidRealloc)?,
        );
        offset += 4;

        // Read uri string
        if data.len() < offset + uri_len as usize {
            return Err(ProgramError::InvalidRealloc);
        }
        let uri = core::str::from_utf8(&data[offset..offset + uri_len as usize])
            .map_err(|_| ProgramError::InvalidRealloc)?;
        offset += uri_len as usize;

        // Read additional_metadata_len (4 bytes)
        let additional_metadata_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidRealloc)?,
        );
        offset += 4;

        // Read additional_metadata
        let additional_metadata = if additional_metadata_len > 0 {
            if data.len() < offset + additional_metadata_len as usize {
                return Err(ProgramError::InvalidRealloc);
            }
            &data[offset..offset + additional_metadata_len as usize]
        } else {
            &[]
        };

        let meta = TokenMetadata {
            update_authority,
            mint,
            name_len,
            name,
            symbol_len,
            symbol,
            uri_len,
            uri,
            additional_metadata_len,
            additional_metadata,
        };

        Ok((meta, offset + additional_metadata_len as usize))
    }

    /// Deserialize TokenMetadata from bytes using the same format as pinocchio's from_bytes
    /// TODO: For some reason it is pub(crate) fn from_bytes<'a>(data: &[u8]) -> Result<TokenMetadata<'a>, ProgramError>
    fn deserialize_token_metadata(data: &'a [u8]) -> Result<TokenMetadata<'a>, ProgramError> {
        Self::parse_token_metadata(data).map(|(m, _)| m)
    }

    /// Serialize TokenMetadata to bytes using the same format as pinocchio's from_bytes expects
    fn serialize_token_metadata(metadata: &TokenMetadata) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write update_authority (32 bytes)
        buf.extend_from_slice(metadata.update_authority.as_ref());

        // Write mint (32 bytes)
        buf.extend_from_slice(metadata.mint.as_ref());

        // Write name_len and name
        buf.extend_from_slice(&metadata.name_len.to_le_bytes());
        buf.extend_from_slice(metadata.name.as_bytes());

        // Write symbol_len and symbol
        buf.extend_from_slice(&metadata.symbol_len.to_le_bytes());
        buf.extend_from_slice(metadata.symbol.as_bytes());

        // Write uri_len and uri
        buf.extend_from_slice(&metadata.uri_len.to_le_bytes());
        buf.extend_from_slice(metadata.uri.as_bytes());

        // Write additional_metadata_len and additional_metadata
        buf.extend_from_slice(&metadata.additional_metadata_len.to_le_bytes());
        buf.extend_from_slice(metadata.additional_metadata);

        buf
    }

    /// Create new InitializeArgs with optional metadata pointer and metadata
    pub fn new(
        decimals: u8,
        mint_authority: Pubkey,
        freeze_authority: Option<Pubkey>,
        metadata_pointer: Option<MetadataPointer>,
        metadata: Option<TokenMetadata<'a>>,
        scaled_ui_amount: Option<ScaledUiAmountConfig>,
    ) -> Self {
        Self {
            ix_mint: InitializeMintArgs {
                decimals,
                mint_authority,
                freeze_authority,
            },
            ix_metadata_pointer: metadata_pointer,
            ix_metadata: metadata,
            ix_scaled_ui_amount: scaled_ui_amount,
        }
    }

    /// Pack the arguments into bytes
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Pack basic mint arguments first
        buf.extend_from_slice(&self.ix_mint.pack());

        // Pack metadata pointer presence flag and data if present
        if let Some(metadata_pointer) = &self.ix_metadata_pointer {
            buf.push(1); // has metadata pointer
                         // Manually serialize MetadataPointer
            buf.extend_from_slice(metadata_pointer.authority.as_ref());
            buf.extend_from_slice(metadata_pointer.metadata_address.as_ref());
        } else {
            buf.push(0); // no metadata pointer
        }

        // Pack metadata presence flag and data if present
        if let Some(metadata) = &self.ix_metadata {
            buf.push(1); // has metadata
            let metadata_bytes = Self::serialize_token_metadata(metadata);
            // Directly append metadata fields without an extra length prefix (borsh-like layout)
            buf.extend_from_slice(&metadata_bytes);
        } else {
            buf.push(0); // no metadata
        }

        // Pack scaled UI amount presence flag and data if present
        if let Some(scaled_ui_amount) = &self.ix_scaled_ui_amount {
            buf.push(1); // has scaled UI amount
                         // Manually serialize ScaledUiAmountConfig
            buf.extend_from_slice(scaled_ui_amount.authority.as_ref());
            buf.extend_from_slice(&scaled_ui_amount.multiplier);
            buf.extend_from_slice(
                &scaled_ui_amount
                    .new_multiplier_effective_timestamp
                    .to_le_bytes(),
            );
            buf.extend_from_slice(&scaled_ui_amount.new_multiplier);
        } else {
            buf.push(0); // no scaled UI amount
        }

        buf
    }

    /// Unpack arguments from bytes
    pub fn unpack(data: &'a [u8]) -> Result<Self, ProgramError> {
        // First, unpack the mint arguments
        let ix_mint = InitializeMintArgs::unpack(data)?;

        // Determine the offset after mint args
        let mut offset = if ix_mint.freeze_authority.is_some() {
            66 // 1 + 32 + 1 + 32
        } else {
            34 // 1 + 32 + 1
        };

        if data.len() <= offset {
            // No extensions
            return Ok(Self {
                ix_mint,
                ix_metadata_pointer: None,
                ix_metadata: None,
                ix_scaled_ui_amount: None,
            });
        }

        // Check metadata pointer flag
        let has_metadata_pointer = data[offset];
        offset += 1;

        let ix_metadata_pointer = if has_metadata_pointer == 1 {
            if data.len() < offset + 64 {
                // 32 (authority) + 32 (metadata_address)
                return Err(ProgramError::InvalidInstructionData);
            }

            let authority = Pubkey::from(
                <[u8; 32]>::try_from(&data[offset..offset + 32])
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            offset += 32;

            let metadata_address = Pubkey::from(
                <[u8; 32]>::try_from(&data[offset..offset + 32])
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            offset += 32;

            Some(MetadataPointer {
                authority,
                metadata_address,
            })
        } else {
            None
        };

        if data.len() <= offset {
            // No metadata
            return Ok(Self {
                ix_mint,
                ix_metadata_pointer,
                ix_metadata: None,
                ix_scaled_ui_amount: None,
            });
        }

        // Check metadata flag
        let has_metadata = data[offset];
        offset += 1;

        let ix_metadata = if has_metadata == 1 {
            // Parse metadata directly from the remaining bytes and advance by consumed length
            let (meta, consumed) = Self::parse_token_metadata(&data[offset..])?;
            offset += consumed;
            Some(meta)
        } else {
            None
        };

        // Check scaled UI amount flag
        let has_scaled_ui_amount = if data.len() > offset { data[offset] } else { 0 };

        if has_scaled_ui_amount == 0 || data.len() <= offset + 1 {
            // No scaled UI amount or not enough data
            return Ok(Self {
                ix_mint,
                ix_metadata_pointer,
                ix_metadata,
                ix_scaled_ui_amount: None,
            });
        }

        offset += 1;

        let ix_scaled_ui_amount = if has_scaled_ui_amount == 1 {
            // ScaledUiAmountConfig structure:
            // 32 bytes authority + 8 bytes multiplier + 8 bytes timestamp + 8 bytes new_multiplier
            let expected_size = 32 + 8 + 8 + 8; // 56 bytes total
            if data.len() < offset + expected_size {
                return Err(ProgramError::InvalidInstructionData);
            }

            let authority = Pubkey::from(
                <[u8; 32]>::try_from(&data[offset..offset + 32])
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            offset += 32;

            let multiplier = <[u8; 8]>::try_from(&data[offset..offset + 8])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            offset += 8;

            let new_multiplier_effective_timestamp = i64::from_le_bytes(
                <[u8; 8]>::try_from(&data[offset..offset + 8])
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            );
            offset += 8;

            let new_multiplier = <[u8; 8]>::try_from(&data[offset..offset + 8])
                .map_err(|_| ProgramError::InvalidInstructionData)?;

            Some(ScaledUiAmountConfig {
                authority,
                multiplier,
                new_multiplier_effective_timestamp,
                new_multiplier,
            })
        } else {
            None
        };

        Ok(Self {
            ix_mint,
            ix_metadata_pointer,
            ix_metadata,
            ix_scaled_ui_amount,
        })
    }

    /// Validate the arguments
    pub fn validate(&self) -> Result<(), ProgramError> {
        // Validate decimals
        if self.ix_mint.decimals > 20 {
            return Err(ProgramError::InvalidArgument);
        }

        // Validate that if metadata exists, metadata pointer must also exist
        if self.ix_metadata.is_some() && self.ix_metadata_pointer.is_none() {
            return Err(ProgramError::InvalidArgument);
        }

        // Validate metadata if present
        if let Some(metadata) = &self.ix_metadata {
            if metadata.name.is_empty() {
                return Err(ProgramError::InvalidArgument);
            }
            if metadata.symbol.is_empty() {
                return Err(ProgramError::InvalidArgument);
            }
        }

        Ok(())
    }
}

/// Arguments for UpdateMetadata instruction
#[repr(C)]
#[derive(Clone, Debug)]
pub struct UpdateMetadataArgs<'a> {
    /// Metadata to update
    pub metadata: TokenMetadata<'a>,
}

impl<'a> UpdateMetadataArgs<'a> {
    /// Create new UpdateMetadataArgs
    pub fn new(metadata: TokenMetadata<'a>) -> Self {
        Self { metadata }
    }

    /// Pack the arguments into bytes
    pub fn pack(&self) -> Vec<u8> {
        InitializeArgs::serialize_token_metadata(&self.metadata)
    }

    /// Unpack arguments from bytes
    pub fn unpack(data: &'a [u8]) -> Result<Self, ProgramError> {
        let metadata = InitializeArgs::deserialize_token_metadata(data)?;
        Ok(Self { metadata })
    }

    /// Validate the arguments
    pub fn validate(&self) -> Result<(), ProgramError> {
        // Validate metadata
        if self.metadata.name.is_empty() {
            return Err(ProgramError::InvalidArgument);
        }
        if self.metadata.symbol.is_empty() {
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }
}

/// Security Token Program instructions
#[derive(Clone, Debug, PartialEq, FromPrimitive)]
pub enum SecurityTokenInstruction {
    /// Initialize a new security token mint with metadata and compliance features
    /// Accounts expected:
    /// 0. `[writable, signer]` The mint account (must be a signer when creating new account)
    /// 1. `[signer]` The creator/payer account
    /// 2. `[]` The SPL Token 2022 program ID
    /// 3. `[]` The system program ID
    /// 4. `[]` The rent sysvar
    InitializeMint = 0,
    /// Update the metadata of an existing security token mint
    /// Accounts expected:
    /// 0. `[writable]` The mint account
    /// 1. `[signer]` The mint authority account
    /// 2. `[]` The SPL Token 2022 program ID
    /// 3. `[]` The system program ID - NOTE: Add lamports if needed
    UpdateMetadata = 1,
}

impl TryFrom<u8> for SecurityTokenInstruction {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SecurityTokenInstruction::InitializeMint),
            1 => Ok(SecurityTokenInstruction::UpdateMetadata),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[cfg(test)]
fn random_pubkey() -> Pubkey {
    use pinocchio::pubkey::PUBKEY_BYTES;

    rand::random::<[u8; PUBKEY_BYTES]>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_mint_args_pack_unpack() {
        let mint_authority = random_pubkey();
        let freeze_authority = Some(random_pubkey());

        let original = InitializeMintArgs {
            decimals: 6,
            mint_authority,
            freeze_authority,
        };

        let packed = original.pack();
        let unpacked = InitializeMintArgs::unpack(&packed).unwrap();

        assert_eq!(original.decimals, unpacked.decimals);
        assert_eq!(original.mint_authority, unpacked.mint_authority);
        assert_eq!(original.freeze_authority, unpacked.freeze_authority);
    }

    #[test]
    fn test_initialize_args_with_metadata_and_scaled_ui_amount() {
        let mint_authority = random_pubkey();
        let freeze_authority = Some(random_pubkey());
        let update_authority = random_pubkey();
        let multiplier_authority = random_pubkey();
        let mint = random_pubkey();

        let name = "Security Token";
        let symbol = "SEC";
        let uri = "https://example.com/metadata.json";
        let additional_metadata = &[];

        let metadata = TokenMetadata {
            update_authority,
            mint,
            name_len: name.len() as u32,
            name,
            symbol_len: symbol.len() as u32,
            symbol,
            uri_len: uri.len() as u32,
            uri,
            additional_metadata_len: 0,
            additional_metadata,
        };

        let metadata_pointer = MetadataPointer {
            authority: update_authority,
            metadata_address: mint,
        };

        let scaled_ui_amount = ScaledUiAmountConfig {
            authority: multiplier_authority,
            multiplier: 2.0f64.to_le_bytes(),
            new_multiplier_effective_timestamp: 0,
            new_multiplier: 2.0f64.to_le_bytes(),
        };

        let original = InitializeArgs::new(
            6,
            mint_authority,
            freeze_authority,
            Some(metadata_pointer),
            Some(metadata.clone()),
            Some(scaled_ui_amount),
        );

        let packed = original.pack();
        let unpacked = InitializeArgs::unpack(&packed).unwrap();

        assert_eq!(original.ix_mint.decimals, unpacked.ix_mint.decimals);
        assert_eq!(
            original.ix_mint.mint_authority,
            unpacked.ix_mint.mint_authority
        );
        assert_eq!(
            original.ix_mint.freeze_authority,
            unpacked.ix_mint.freeze_authority
        );

        // Verify that MetadataPointer is correctly restored
        let unpacked_metadata_pointer = unpacked.ix_metadata_pointer.unwrap();
        assert_eq!(
            metadata_pointer.authority,
            unpacked_metadata_pointer.authority
        );
        assert_eq!(
            metadata_pointer.metadata_address,
            unpacked_metadata_pointer.metadata_address
        );

        // Verify Metadata
        let unpacked_metadata = unpacked.ix_metadata.unwrap();
        assert_eq!(metadata.name, unpacked_metadata.name);
        assert_eq!(metadata.symbol, unpacked_metadata.symbol);
        assert_eq!(metadata.uri, unpacked_metadata.uri);
        assert_eq!(
            metadata.additional_metadata,
            unpacked_metadata.additional_metadata
        );

        // Verify ScaledUiAmount
        let unpacked_scaled_ui_amount = unpacked.ix_scaled_ui_amount.unwrap();
        assert_eq!(
            scaled_ui_amount.authority,
            unpacked_scaled_ui_amount.authority
        );
        assert_eq!(
            scaled_ui_amount.multiplier,
            unpacked_scaled_ui_amount.multiplier
        );
    }

    #[test]
    fn test_initialize_args_with_metadata() {
        let mint_authority = random_pubkey();
        let freeze_authority = Some(random_pubkey());

        // Create a test with simple metadata (no scaled UI amount for simplicity)
        let original = InitializeArgs::new(
            6,
            mint_authority,
            freeze_authority,
            None, // no metadata pointer for this simpler test
            None, // no metadata for this simpler test
            None, // no scaled UI amount
        );

        let packed = original.pack();
        let unpacked = InitializeArgs::unpack(&packed).unwrap();

        assert_eq!(original.ix_mint.decimals, unpacked.ix_mint.decimals);
        assert_eq!(
            original.ix_mint.mint_authority,
            unpacked.ix_mint.mint_authority
        );
        assert_eq!(
            original.ix_mint.freeze_authority,
            unpacked.ix_mint.freeze_authority
        );

        assert!(unpacked.ix_metadata_pointer.is_none());
        assert!(unpacked.ix_metadata.is_none());
        assert!(unpacked.ix_scaled_ui_amount.is_none());
    }

    #[test]
    fn test_update_metadata_args_pack_unpack() {
        // For now, we'll test just the pack/unpack mechanism without full metadata construction
        // since TokenMetadata requires proper lifetime management with &str and &[u8] fields

        let original = UpdateMetadataArgs::new(TokenMetadata {
            update_authority: random_pubkey(),
            mint: random_pubkey(),
            name_len: 4,
            name: "Test",
            symbol_len: 3,
            symbol: "TST",
            uri_len: 0,
            uri: "",
            additional_metadata_len: 0,
            additional_metadata: &[],
        });

        // Test validation
        assert!(original.validate().is_ok());

        let packed = original.pack();
        let unpacked = UpdateMetadataArgs::unpack(&packed).unwrap();

        assert_eq!(
            original.metadata.update_authority,
            unpacked.metadata.update_authority
        );
        assert_eq!(original.metadata.mint, unpacked.metadata.mint);
        assert_eq!(original.metadata.name, unpacked.metadata.name);
        assert_eq!(original.metadata.symbol, unpacked.metadata.symbol);
        assert_eq!(original.metadata.uri, unpacked.metadata.uri);

        // Test validation failure with empty name
        let bad_metadata = TokenMetadata {
            update_authority: random_pubkey(),
            mint: random_pubkey(),
            name_len: 0,
            name: "",
            symbol_len: 3,
            symbol: "TST",
            uri_len: 0,
            uri: "",
            additional_metadata_len: 0,
            additional_metadata: &[],
        };
        let invalid_args = UpdateMetadataArgs::new(bad_metadata);
        assert!(invalid_args.validate().is_err());
    }

    #[test]
    fn test_validate() {
        let mint_authority = random_pubkey();

        // Valid args without metadata
        let valid_args = InitializeArgs::new(6, mint_authority, None, None, None, None);
        assert!(valid_args.validate().is_ok());

        // Invalid decimals
        let invalid_decimals = InitializeArgs::new(25, mint_authority, None, None, None, None);
        assert!(invalid_decimals.validate().is_err());

        // Test with a valid metadata pointer but no metadata (this should be valid)
        let metadata_pointer = MetadataPointer {
            authority: mint_authority,
            metadata_address: mint_authority,
        };
        let valid_with_metadata_pointer_only = InitializeArgs::new(
            6,
            mint_authority,
            None,
            Some(metadata_pointer),
            None, // no metadata
            None,
        );
        assert!(valid_with_metadata_pointer_only.validate().is_ok());

        // Test metadata validation with proper lifetime-bound data
        let name = "Test Token";
        let symbol = "TEST";
        let uri = "https://example.com";
        let additional_metadata = &[];

        let valid_metadata = TokenMetadata {
            update_authority: mint_authority,
            mint: mint_authority,
            name_len: name.len() as u32,
            name,
            symbol_len: symbol.len() as u32,
            symbol,
            uri_len: uri.len() as u32,
            uri,
            additional_metadata_len: 0,
            additional_metadata,
        };

        let valid_with_metadata = InitializeArgs::new(
            6,
            mint_authority,
            None,
            Some(metadata_pointer),
            Some(valid_metadata),
            None,
        );
        assert!(valid_with_metadata.validate().is_ok());

        // Invalid: metadata without metadata pointer (create a new metadata instance)
        let metadata_for_invalid_test = TokenMetadata {
            update_authority: mint_authority,
            mint: mint_authority,
            name_len: name.len() as u32,
            name,
            symbol_len: symbol.len() as u32,
            symbol,
            uri_len: uri.len() as u32,
            uri,
            additional_metadata_len: 0,
            additional_metadata,
        };
        let metadata_without_pointer = InitializeArgs::new(
            6,
            mint_authority,
            None,
            None,
            Some(metadata_for_invalid_test),
            None,
        );
        assert!(metadata_without_pointer.validate().is_err());

        // Invalid metadata - empty name
        let bad_metadata = TokenMetadata {
            update_authority: mint_authority,
            mint: mint_authority,
            name_len: 0,
            name: "",
            symbol_len: symbol.len() as u32,
            symbol,
            uri_len: uri.len() as u32,
            uri,
            additional_metadata_len: 0,
            additional_metadata,
        };
        let invalid_metadata = InitializeArgs::new(
            6,
            mint_authority,
            None,
            Some(metadata_pointer),
            Some(bad_metadata),
            None,
        );
        assert!(invalid_metadata.validate().is_err());
    }
}

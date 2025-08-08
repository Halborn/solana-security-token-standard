use borsh::BorshDeserialize;
use num_derive::FromPrimitive;
use solana_program::{program_error::ProgramError, pubkey::Pubkey};
use spl_token_2022::extension::metadata_pointer::MetadataPointer;
use spl_token_2022::extension::scaled_ui_amount::instruction::InitializeInstructionData as ScaledUiAmountInitialize;
use spl_token_metadata_interface::state::TokenMetadata;

/// Follows the spl_token_2022::instruction::TokenInstruction::InitializeMint
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
        let mint_authority = Pubkey::new_from_array(
            data[1..33]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );

        let freeze_authority = if data[33] == 1 {
            if data.len() < 66 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Some(Pubkey::new_from_array(
                data[34..66]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            ))
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
#[derive(Clone)]
pub struct InitializeArgs {
    /// Basic mint arguments
    pub ix_mint: InitializeMintArgs,
    /// Optional metadata pointer configuration
    pub ix_metadata_pointer: Option<MetadataPointer>,
    /// Optional metadata
    pub ix_metadata: Option<TokenMetadata>,
    /// Optional scaled UI amount configuration
    pub ix_scaled_ui_amount: Option<ScaledUiAmountInitialize>,
}

impl std::fmt::Debug for InitializeArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitializeArgs")
            .field("ix_mint", &self.ix_mint)
            .field("ix_metadata_pointer", &self.ix_metadata_pointer)
            .field("ix_metadata", &self.ix_metadata)
            .field("ix_scaled_ui_amount", &"<ScaledUiAmountInitialize>")
            .finish()
    }
}

impl InitializeArgs {
    /// Create new InitializeArgs with optional metadata pointer and metadata
    pub fn new(
        decimals: u8,
        mint_authority: Pubkey,
        freeze_authority: Option<Pubkey>,
        metadata_pointer: Option<MetadataPointer>,
        metadata: Option<TokenMetadata>,
        scaled_ui_amount: Option<ScaledUiAmountInitialize>,
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
        use bytemuck::bytes_of;
        let mut buf = Vec::new();

        // Pack basic mint arguments first
        buf.extend_from_slice(&self.ix_mint.pack());

        // Pack metadata pointer presence flag and data if present
        if let Some(metadata_pointer) = &self.ix_metadata_pointer {
            buf.push(1); // has metadata pointer
            buf.extend_from_slice(bytes_of(metadata_pointer));
        } else {
            buf.push(0); // no metadata pointer
        }

        // Pack metadata presence flag and data if present
        if let Some(metadata) = &self.ix_metadata {
            buf.push(1); // has metadata
            let metadata_bytes = borsh::to_vec(metadata).unwrap();
            // Pack the length first (4 bytes)
            buf.extend_from_slice(&(metadata_bytes.len() as u32).to_le_bytes());
            // Then pack the metadata itself
            buf.extend_from_slice(&metadata_bytes);
        } else {
            buf.push(0); // no metadata
        }

        // Pack scaled UI amount presence flag and data if present
        if let Some(scaled_ui_amount) = &self.ix_scaled_ui_amount {
            buf.push(1); // has scaled UI amount
            buf.extend_from_slice(bytes_of(scaled_ui_amount));
        } else {
            buf.push(0); // no scaled UI amount
        }

        buf
    }

    /// Unpack arguments from bytes
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        use bytemuck::try_from_bytes;

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
            if data.len() < offset + std::mem::size_of::<MetadataPointer>() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata_pointer_bytes =
                &data[offset..offset + std::mem::size_of::<MetadataPointer>()];
            offset += std::mem::size_of::<MetadataPointer>();
            Some(
                *try_from_bytes::<MetadataPointer>(metadata_pointer_bytes)
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            )
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
            // Read the length first (4 bytes)
            if data.len() < offset + 4 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            // Read the metadata data
            if data.len() < offset + metadata_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata_data = &data[offset..offset + metadata_len];
            offset += metadata_len;

            Some(
                TokenMetadata::try_from_slice(metadata_data)
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            )
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
            if data.len() < offset + std::mem::size_of::<ScaledUiAmountInitialize>() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let scaled_ui_amount_bytes =
                &data[offset..offset + std::mem::size_of::<ScaledUiAmountInitialize>()];
            Some(
                *try_from_bytes::<ScaledUiAmountInitialize>(scaled_ui_amount_bytes)
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            )
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
#[derive(Clone, Debug)]
pub struct UpdateMetadataArgs {
    /// Metadata to update
    pub metadata: TokenMetadata,
}

impl UpdateMetadataArgs {
    /// Create new UpdateMetadataArgs
    pub fn new(metadata: TokenMetadata) -> Self {
        Self { metadata }
    }

    /// Pack the arguments into bytes
    pub fn pack(&self) -> Vec<u8> {
        borsh::to_vec(&self.metadata).unwrap()
    }

    /// Unpack arguments from bytes
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let metadata = TokenMetadata::try_from_slice(data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::pubkey::Pubkey;
    use spl_pod::optional_keys::OptionalNonZeroPubkey;

    #[test]
    fn test_initialize_mint_args_pack_unpack() {
        let mint_authority = Pubkey::new_unique();
        let freeze_authority = Some(Pubkey::new_unique());

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
        let mint_authority = Pubkey::new_unique();
        let freeze_authority = Some(Pubkey::new_unique());
        let update_authority = Pubkey::new_unique();
        let multiplier_authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "Security Token".to_string(),
            symbol: "SEC".to_string(),
            uri: "https://example.com/metadata.json".to_string(),
            additional_metadata: vec![
                ("category".to_string(), "security".to_string()),
                ("issuer".to_string(), "Example Corp".to_string()),
                ("regulation".to_string(), "RegD".to_string()),
            ],
        };

        let metadata_pointer = MetadataPointer {
            authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            metadata_address: OptionalNonZeroPubkey::try_from(Some(mint)).unwrap(),
        };

        let scaled_ui_amount = ScaledUiAmountInitialize {
            authority: OptionalNonZeroPubkey::try_from(Some(multiplier_authority)).unwrap(),
            multiplier: 2.0f64.into(),
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
            f64::from(scaled_ui_amount.multiplier),
            f64::from(unpacked_scaled_ui_amount.multiplier)
        );
    }

    #[test]
    fn test_initialize_args_with_metadata() {
        let mint_authority = Pubkey::new_unique();
        let freeze_authority = Some(Pubkey::new_unique());
        let update_authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "Security Token".to_string(),
            symbol: "SEC".to_string(),
            uri: "https://example.com/metadata.json".to_string(),
            additional_metadata: vec![
                ("category".to_string(), "security".to_string()),
                ("issuer".to_string(), "Example Corp".to_string()),
                ("regulation".to_string(), "RegD".to_string()),
            ],
        };

        let metadata_pointer = MetadataPointer {
            authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            metadata_address: OptionalNonZeroPubkey::try_from(Some(mint)).unwrap(),
        };

        let original = InitializeArgs::new(
            6,
            mint_authority,
            freeze_authority,
            Some(metadata_pointer),
            Some(metadata.clone()),
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

        let unpacked_metadata_pointer = unpacked.ix_metadata_pointer.unwrap();
        assert_eq!(
            metadata_pointer.authority,
            unpacked_metadata_pointer.authority
        );
        assert_eq!(
            metadata_pointer.metadata_address,
            unpacked_metadata_pointer.metadata_address
        );

        let unpacked_metadata = unpacked.ix_metadata.unwrap();
        assert_eq!(metadata.name, unpacked_metadata.name);
        assert_eq!(metadata.symbol, unpacked_metadata.symbol);
        assert_eq!(metadata.uri, unpacked_metadata.uri);
        assert_eq!(
            metadata.additional_metadata,
            unpacked_metadata.additional_metadata
        );
    }

    #[test]
    fn test_update_metadata_args_pack_unpack() {
        let update_authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "Updated Token".to_string(),
            symbol: "UPD".to_string(),
            uri: "https://updated.example.com".to_string(),
            additional_metadata: vec![
                ("version".to_string(), "2.0".to_string()),
                ("updated".to_string(), "2024".to_string()),
            ],
        };

        let original = UpdateMetadataArgs::new(metadata.clone());

        // Test validation
        assert!(original.validate().is_ok());

        let packed = original.pack();
        let unpacked = UpdateMetadataArgs::unpack(&packed).unwrap();

        assert_eq!(original.metadata.name, unpacked.metadata.name);
        assert_eq!(original.metadata.symbol, unpacked.metadata.symbol);
        assert_eq!(original.metadata.uri, unpacked.metadata.uri);
        assert_eq!(
            original.metadata.additional_metadata,
            unpacked.metadata.additional_metadata
        );

        // Test validation failure with empty name
        let bad_metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "".to_string(),
            symbol: "UPD".to_string(),
            uri: "https://updated.example.com".to_string(),
            additional_metadata: Vec::new(),
        };
        let invalid_args = UpdateMetadataArgs::new(bad_metadata);
        assert!(invalid_args.validate().is_err());
    }

    #[test]
    fn test_validate() {
        let mint_authority = Pubkey::new_unique();
        let update_authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        // Valid args without metadata
        let valid_args = InitializeArgs::new(6, mint_authority, None, None, None, None);
        assert!(valid_args.validate().is_ok());

        // Valid args with metadata
        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            uri: "https://example.com".to_string(),
            additional_metadata: Vec::new(),
        };
        let metadata_pointer = MetadataPointer {
            authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            metadata_address: OptionalNonZeroPubkey::try_from(Some(mint)).unwrap(),
        };
        let valid_with_metadata = InitializeArgs::new(
            6,
            mint_authority,
            None,
            Some(metadata_pointer),
            Some(metadata),
            None, // no scaled UI amount
        );
        assert!(valid_with_metadata.validate().is_ok());

        // Invalid decimals
        let invalid_decimals = InitializeArgs::new(25, mint_authority, None, None, None, None);
        assert!(invalid_decimals.validate().is_err());

        // Invalid metadata - empty name
        let bad_metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "".to_string(),
            symbol: "TEST".to_string(),
            uri: "https://example.com".to_string(),
            additional_metadata: Vec::new(),
        };
        let invalid_metadata =
            InitializeArgs::new(6, mint_authority, None, None, Some(bad_metadata), None);
        assert!(invalid_metadata.validate().is_err());

        // Invalid: metadata without metadata pointer
        let valid_metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey::try_from(Some(update_authority)).unwrap(),
            mint,
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            uri: "https://example.com".to_string(),
            additional_metadata: Vec::new(),
        };
        let metadata_without_pointer =
            InitializeArgs::new(6, mint_authority, None, None, Some(valid_metadata), None);
        assert!(metadata_without_pointer.validate().is_err());
    }
}

use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use pinocchio_token_2022::extensions::metadata::TokenMetadata;
use pinocchio_token_2022::extensions::metadata_pointer::MetadataPointer;
use pinocchio_token_2022::extensions::scaled_ui_amount::ScaledUiAmountConfig;

/// Arguments to initialize mint
#[repr(C)]
#[derive(Clone, Debug)]
pub struct InitializeMintArgs {
    /// Number of decimals for the token
    pub decimals: u8,
    /// Mint authority public key
    pub mint_authority: Pubkey,
    /// Optional freeze authority public key
    pub freeze_authority: Pubkey,
}

impl InitializeMintArgs {
    /// Pack the mint arguments into bytes using the same format as SPL Token 2022
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Pack decimals (1 byte)
        buf.push(self.decimals);

        // Pack mint authority (32 bytes)
        buf.extend_from_slice(self.mint_authority.as_ref());

        // Freeze authority (32 bytes)
        buf.extend_from_slice(self.freeze_authority.as_ref());

        buf
    }

    /// Deserialize mint arguments from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 34 {
            // minimum: 1 (decimals) + 32 (mint_authority) + 1 (freeze_authority flag)
            return Err(ProgramError::InvalidInstructionData);
        }

        let decimals = data[0];
        let mint_authority: Pubkey = data[1..33]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        let freeze_authority = data[33..65]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

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
    pub fn deserialize_token_metadata(data: &'a [u8]) -> Result<TokenMetadata<'a>, ProgramError> {
        Self::parse_token_metadata(data).map(|(m, _)| m)
    }

    /// Serialize TokenMetadata to bytes using the same format as pinocchio's from_bytes expects
    pub fn serialize_token_metadata(metadata: &TokenMetadata) -> Vec<u8> {
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
        freeze_authority: Pubkey,
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
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Pack basic mint arguments first
        buf.extend_from_slice(&self.ix_mint.to_bytes_inner());

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

    /// Deserialize arguments from bytes
    pub fn try_from_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        // First, try_from_bytes the mint arguments
        let ix_mint = InitializeMintArgs::try_from_bytes(data)?;

        // Determine the offset after mint args
        let mut offset = 65;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn random_pubkey() -> Pubkey {
        use pinocchio::pubkey::PUBKEY_BYTES;
        rand::random::<[u8; PUBKEY_BYTES]>()
    }

    #[test]
    fn test_initialize_mint_args_to_bytes_inner_try_from_bytes() {
        let mint_authority = random_pubkey();
        let freeze_authority = random_pubkey();

        let original = InitializeMintArgs {
            decimals: 6,
            mint_authority,
            freeze_authority,
        };

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeMintArgs::try_from_bytes(&inner_bytes).unwrap();

        assert_eq!(original.decimals, deserialized.decimals);
        assert_eq!(original.mint_authority, deserialized.mint_authority);
        assert_eq!(original.freeze_authority, deserialized.freeze_authority);
    }

    #[test]
    fn test_initialize_args_with_metadata_and_scaled_ui_amount() {
        let mint_authority = random_pubkey();
        let freeze_authority = random_pubkey();
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

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeArgs::try_from_bytes(&inner_bytes).unwrap();

        assert_eq!(original.ix_mint.decimals, deserialized.ix_mint.decimals);
        assert_eq!(
            original.ix_mint.mint_authority,
            deserialized.ix_mint.mint_authority
        );
        assert_eq!(
            original.ix_mint.freeze_authority,
            deserialized.ix_mint.freeze_authority
        );

        // Verify that MetadataPointer is correctly restored
        let deserialized_metadata_pointer = deserialized.ix_metadata_pointer.unwrap();
        assert_eq!(
            metadata_pointer.authority,
            deserialized_metadata_pointer.authority
        );
        assert_eq!(
            metadata_pointer.metadata_address,
            deserialized_metadata_pointer.metadata_address
        );

        // Verify Metadata
        let deserialized_metadata = deserialized.ix_metadata.unwrap();
        assert_eq!(metadata.name, deserialized_metadata.name);
        assert_eq!(metadata.symbol, deserialized_metadata.symbol);
        assert_eq!(metadata.uri, deserialized_metadata.uri);
        assert_eq!(
            metadata.additional_metadata,
            deserialized_metadata.additional_metadata
        );

        // Verify ScaledUiAmount
        let deserialized_scaled_ui_amount = deserialized.ix_scaled_ui_amount.unwrap();
        assert_eq!(
            scaled_ui_amount.authority,
            deserialized_scaled_ui_amount.authority
        );
        assert_eq!(
            scaled_ui_amount.multiplier,
            deserialized_scaled_ui_amount.multiplier
        );
    }

    #[test]
    fn test_initialize_args_with_metadata() {
        let mint_authority = random_pubkey();
        let freeze_authority = random_pubkey();

        // Create a test with simple metadata (no scaled UI amount for simplicity)
        let original = InitializeArgs::new(
            6,
            mint_authority,
            freeze_authority,
            None, // no metadata pointer for this simpler test
            None, // no metadata for this simpler test
            None, // no scaled UI amount
        );

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeArgs::try_from_bytes(&inner_bytes).unwrap();

        assert_eq!(original.ix_mint.decimals, deserialized.ix_mint.decimals);
        assert_eq!(
            original.ix_mint.mint_authority,
            deserialized.ix_mint.mint_authority
        );
        assert_eq!(
            original.ix_mint.freeze_authority,
            deserialized.ix_mint.freeze_authority
        );

        assert!(deserialized.ix_metadata_pointer.is_none());
        assert!(deserialized.ix_metadata.is_none());
        assert!(deserialized.ix_scaled_ui_amount.is_none());
    }

    #[test]
    fn test_validate() {
        let mint_authority = random_pubkey();
        let freeze_authority = random_pubkey();

        // Valid args without metadata
        let valid_args = InitializeArgs::new(6, mint_authority, freeze_authority, None, None, None);
        assert!(valid_args.validate().is_ok());

        // Invalid decimals
        let invalid_decimals =
            InitializeArgs::new(25, mint_authority, freeze_authority, None, None, None);
        assert!(invalid_decimals.validate().is_err());

        // Test with a valid metadata pointer but no metadata (this should be valid)
        let metadata_pointer = MetadataPointer {
            authority: mint_authority,
            metadata_address: mint_authority,
        };
        let valid_with_metadata_pointer_only = InitializeArgs::new(
            6,
            mint_authority,
            freeze_authority,
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
            freeze_authority,
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
            freeze_authority,
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
            freeze_authority,
            Some(metadata_pointer),
            Some(bad_metadata),
            None,
        );
        assert!(invalid_metadata.validate().is_err());
    }
}

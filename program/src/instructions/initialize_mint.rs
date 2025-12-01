use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};
use shank::ShankType;

#[repr(C)]
#[derive(Clone, Debug, ShankType)]
pub struct TokenMetadataArgs {
    // Length fields are omitted because the owned values carry that information
    pub update_authority: Pubkey,
    pub mint: Pubkey,
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub additional_metadata: Vec<u8>,
}

impl TokenMetadataArgs {
    // Note: We maintain separate serialization formats for different contexts:
    // - TokenMetadataArgs uses Borsh format for instruction data (client → program)
    // - TokenMetadata in token22_extensions uses Token-2022 extension format for account data (on-chain storage). Uses lifetime arguments
    // We also will remove the TokenMetadata implementation when pinocchio_token_2022 extensions are officially implemented
    // These formats may look similar but serve different purposes and cannot be directly reused

    /// Minimum size (Borsh format): update_authority (32) + mint (32) + name_len (4) + symbol_len (4) + uri_len (4) + additional_metadata_len (4) = 80 bytes
    pub const MIN_LEN: usize = PUBKEY_BYTES + PUBKEY_BYTES + 4 + 4 + 4 + 4;

    /// Deserialize TokenMetadataArgs from bytes (Borsh format) and return consumed byte count
    pub fn try_from_bytes(data: &[u8]) -> Result<(Self, usize), ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        let mut offset: usize = 0;

        // Read update_authority (32 bytes)
        let update_authority = Pubkey::from(
            <[u8; PUBKEY_BYTES]>::try_from(&data[offset..offset + PUBKEY_BYTES])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        offset += PUBKEY_BYTES;

        // Read mint (32 bytes)
        let mint = Pubkey::from(
            <[u8; PUBKEY_BYTES]>::try_from(&data[offset..offset + PUBKEY_BYTES])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        offset += PUBKEY_BYTES;

        // Read name (Borsh format: length prefix + bytes)
        let name_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset += 4;
        if data.len() < offset + name_len {
            return Err(ProgramError::InvalidInstructionData);
        }
        let name = core::str::from_utf8(&data[offset..offset + name_len])
            .map_err(|_| ProgramError::InvalidInstructionData)?
            .to_string();
        offset += name_len;

        // Read symbol (Borsh format: length prefix + bytes)
        let symbol_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset += 4;
        if data.len() < offset + symbol_len {
            return Err(ProgramError::InvalidInstructionData);
        }
        let symbol = core::str::from_utf8(&data[offset..offset + symbol_len])
            .map_err(|_| ProgramError::InvalidInstructionData)?
            .to_string();
        offset += symbol_len;

        // Read uri (Borsh format: length prefix + bytes)
        let uri_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset += 4;
        if data.len() < offset + uri_len {
            return Err(ProgramError::InvalidInstructionData);
        }
        let uri = core::str::from_utf8(&data[offset..offset + uri_len])
            .map_err(|_| ProgramError::InvalidInstructionData)?
            .to_string();
        offset += uri_len;

        // Read additional_metadata (Borsh format: length prefix + bytes)
        let additional_metadata_len = u32::from_le_bytes(
            <[u8; 4]>::try_from(&data[offset..offset + 4])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ) as usize;
        offset += 4;
        let additional_metadata = if additional_metadata_len > 0 {
            if data.len() < offset + additional_metadata_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            data[offset..offset + additional_metadata_len].to_vec()
        } else {
            Vec::new()
        };
        offset += additional_metadata_len;

        Ok((
            Self {
                update_authority,
                mint,
                name,
                symbol,
                uri,
                additional_metadata,
            },
            offset,
        ))
    }

    /// Serialize TokenMetadata to bytes (Borsh format)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write update_authority (32 bytes)
        buf.extend_from_slice(self.update_authority.as_ref());

        // Write mint (32 bytes)
        buf.extend_from_slice(self.mint.as_ref());

        // Write name (Borsh: u32 length + bytes)
        buf.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.name.as_bytes());

        // Write symbol (Borsh: u32 length + bytes)
        buf.extend_from_slice(&(self.symbol.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.symbol.as_bytes());

        // Write uri (Borsh: u32 length + bytes)
        buf.extend_from_slice(&(self.uri.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.uri.as_bytes());

        // Write additional_metadata (Borsh: u32 length + bytes)
        buf.extend_from_slice(&(self.additional_metadata.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.additional_metadata);

        buf
    }
}

#[repr(C)]
#[derive(Clone, Debug, ShankType)]
pub struct ScaledUiAmountConfigArgs {
    pub authority: Pubkey,
    pub multiplier: [u8; 8],
    pub new_multiplier_effective_timestamp: i64, // pinocchio::sysvars::clock::UnixTimestamp;
    pub new_multiplier: [u8; 8],
}

impl ScaledUiAmountConfigArgs {
    /// Fixed size: authority (32) + multiplier (8) + timestamp (8) + new_multiplier (8) = 56 bytes
    pub const LEN: usize = PUBKEY_BYTES + 8 + 8 + 8;

    /// Deserialize ScaledUiAmountConfigArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read authority (32 bytes)
        let authority = Pubkey::from(
            <[u8; PUBKEY_BYTES]>::try_from(&data[offset..offset + PUBKEY_BYTES])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        offset += PUBKEY_BYTES;

        // Read multiplier (8 bytes)
        let multiplier = <[u8; 8]>::try_from(&data[offset..offset + 8])
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        offset += 8;

        // Read new_multiplier_effective_timestamp (8 bytes)
        let new_multiplier_effective_timestamp = i64::from_le_bytes(
            <[u8; 8]>::try_from(&data[offset..offset + 8])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        offset += 8;

        // Read new_multiplier (8 bytes)
        let new_multiplier = <[u8; 8]>::try_from(&data[offset..offset + 8])
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        Ok(Self {
            authority,
            multiplier,
            new_multiplier_effective_timestamp,
            new_multiplier,
        })
    }

    /// Serialize ScaledUiAmountConfigArgs to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::LEN);
        buf.extend_from_slice(self.authority.as_ref());
        buf.extend_from_slice(&self.multiplier);
        buf.extend_from_slice(&self.new_multiplier_effective_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.new_multiplier);
        buf
    }
}

#[repr(C)]
#[derive(Clone, Debug, ShankType)]
pub struct MetadataPointerArgs {
    pub authority: Pubkey,
    pub metadata_address: Pubkey,
}

impl MetadataPointerArgs {
    /// Fixed size: authority (32) + metadata_address (32) = 64 bytes
    pub const LEN: usize = PUBKEY_BYTES + PUBKEY_BYTES;

    /// Deserialize MetadataPointerArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let authority = Pubkey::from(
            <[u8; PUBKEY_BYTES]>::try_from(&data[..PUBKEY_BYTES])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );

        let metadata_address = Pubkey::from(
            <[u8; PUBKEY_BYTES]>::try_from(&data[PUBKEY_BYTES..PUBKEY_BYTES * 2])
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );

        Ok(Self {
            authority,
            metadata_address,
        })
    }

    /// Serialize MetadataPointerArgs to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::LEN);
        buf.extend_from_slice(self.authority.as_ref());
        buf.extend_from_slice(self.metadata_address.as_ref());
        buf
    }
}

#[repr(C)]
#[derive(Clone, Debug, ShankType)]
pub struct MintArgs {
    /// Number of decimals for the token
    pub decimals: u8,
    /// Mint authority public key
    pub mint_authority: Pubkey,
    /// Optional freeze authority public key
    pub freeze_authority: Pubkey,
}

#[repr(C)]
#[derive(Clone, ShankType)]
pub struct InitializeMintArgs {
    /// Basic mint arguments
    pub ix_mint: MintArgs,
    /// Optional metadata pointer configuration
    pub ix_metadata_pointer: Option<MetadataPointerArgs>, // pinocchio_token_2022::extensions::metadata_pointer::MetadataPointer
    /// Optional metadata
    pub ix_metadata: Option<TokenMetadataArgs>, // pinocchio_token_2022::extensions::metadata::TokenMetadata
    /// Optional scaled UI amount configuration
    pub ix_scaled_ui_amount: Option<ScaledUiAmountConfigArgs>, //  pinocchio_token_2022::extensions::scaled_ui_amount::ScaledUiAmountConfig
}

impl MintArgs {
    /// Fixed size: decimals (1 byte) + mint_authority (32 bytes) + freeze_authority (32 bytes) = 65 bytes
    pub const LEN: usize = 1 + PUBKEY_BYTES + PUBKEY_BYTES;

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
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read decimals (1 byte)
        let decimals = data[offset];
        offset += 1;

        // Read mint_authority (32 bytes)
        let mint_authority: Pubkey = data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        offset += PUBKEY_BYTES;

        // Read freeze_authority (32 bytes)
        let freeze_authority: Pubkey = data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        Ok(Self {
            decimals,
            mint_authority,
            freeze_authority,
        })
    }
}

impl std::fmt::Debug for InitializeMintArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitializeArgs")
            .field("ix_mint", &self.ix_mint)
            .field("ix_metadata_pointer", &self.ix_metadata_pointer)
            .field("ix_metadata", &self.ix_metadata)
            .field("ix_scaled_ui_amount", &self.ix_scaled_ui_amount)
            .finish()
    }
}

impl InitializeMintArgs {
    /// Create new InitializeArgs with optional metadata pointer and metadata
    pub fn new(
        decimals: u8,
        mint_authority: Pubkey,
        freeze_authority: Pubkey,
        metadata_pointer: Option<MetadataPointerArgs>,
        metadata: Option<TokenMetadataArgs>,
        scaled_ui_amount: Option<ScaledUiAmountConfigArgs>,
    ) -> Self {
        Self {
            ix_mint: MintArgs {
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
            buf.extend_from_slice(&metadata_pointer.to_bytes());
        } else {
            buf.push(0); // no metadata pointer
        }

        // Pack metadata presence flag and data if present
        if let Some(metadata) = &self.ix_metadata {
            buf.push(1); // has metadata
            buf.extend_from_slice(&metadata.to_bytes());
        } else {
            buf.push(0); // no metadata
        }

        // Pack scaled UI amount presence flag and data if present
        if let Some(scaled_ui_amount) = &self.ix_scaled_ui_amount {
            buf.push(1); // has scaled UI amount
            buf.extend_from_slice(&scaled_ui_amount.to_bytes());
        } else {
            buf.push(0); // no scaled UI amount
        }

        buf
    }

    /// Deserialize arguments from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        // First, try_from_bytes the mint arguments
        let ix_mint = MintArgs::try_from_bytes(data)?;

        // Determine the offset after mint args
        let mut offset = MintArgs::LEN;
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
            let metadata_pointer = MetadataPointerArgs::try_from_bytes(&data[offset..])?;
            offset += MetadataPointerArgs::LEN;
            Some(metadata_pointer)
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
            let (meta, consumed) = TokenMetadataArgs::try_from_bytes(&data[offset..])?;
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
            let scaled_ui_amount = ScaledUiAmountConfigArgs::try_from_bytes(&data[offset..])?;
            Some(scaled_ui_amount)
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
    use crate::test_utils::random_pubkey;

    #[test]
    fn test_initialize_mint_args_to_bytes_inner_try_from_bytes() {
        let mint_authority = random_pubkey();
        let freeze_authority = random_pubkey();

        let original = MintArgs {
            decimals: 6,
            mint_authority,
            freeze_authority,
        };

        let inner_bytes = original.to_bytes_inner();
        let deserialized = MintArgs::try_from_bytes(&inner_bytes).unwrap();

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
        let additional_metadata = vec![];

        let metadata = TokenMetadataArgs {
            update_authority,
            mint,
            name: name.to_string(),
            symbol: symbol.to_string(),
            uri: uri.to_string(),
            additional_metadata,
        };

        let metadata_pointer = MetadataPointerArgs {
            authority: update_authority,
            metadata_address: mint,
        };

        let scaled_ui_amount = ScaledUiAmountConfigArgs {
            authority: multiplier_authority,
            multiplier: 2.0f64.to_le_bytes(),
            new_multiplier_effective_timestamp: 0,
            new_multiplier: 2.0f64.to_le_bytes(),
        };

        let original = InitializeMintArgs::new(
            6,
            mint_authority,
            freeze_authority,
            Some(metadata_pointer.clone()),
            Some(metadata.clone()),
            Some(scaled_ui_amount.clone()),
        );

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeMintArgs::try_from_bytes(&inner_bytes).unwrap();

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
    fn test_initialize_args_without_metadata() {
        let mint_authority = random_pubkey();
        let freeze_authority = random_pubkey();

        // Create a test with simple metadata (no scaled UI amount for simplicity)
        let original = InitializeMintArgs::new(
            6,
            mint_authority,
            freeze_authority,
            None, // no metadata pointer for this simpler test
            None, // no metadata for this simpler test
            None, // no scaled UI amount
        );

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeMintArgs::try_from_bytes(&inner_bytes).unwrap();

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
        let valid_args =
            InitializeMintArgs::new(6, mint_authority, freeze_authority, None, None, None);
        assert!(valid_args.validate().is_ok());

        // Invalid decimals
        let invalid_decimals =
            InitializeMintArgs::new(25, mint_authority, freeze_authority, None, None, None);
        assert!(invalid_decimals.validate().is_err());

        // Test with a valid metadata pointer but no metadata (this should be valid)
        let metadata_pointer = MetadataPointerArgs {
            authority: mint_authority,
            metadata_address: mint_authority,
        };
        let valid_with_metadata_pointer_only = InitializeMintArgs::new(
            6,
            mint_authority,
            freeze_authority,
            Some(metadata_pointer.clone()),
            None, // no metadata
            None,
        );
        assert!(valid_with_metadata_pointer_only.validate().is_ok());

        // Test metadata validation with proper lifetime-bound data
        let name = "Test Token";
        let symbol = "TEST";
        let uri = "https://example.com";
        let additional_metadata = vec![];

        let valid_metadata = TokenMetadataArgs {
            update_authority: mint_authority,
            mint: mint_authority,
            name: name.to_string(),
            symbol: symbol.to_string(),
            uri: uri.to_string(),
            additional_metadata: additional_metadata.clone(),
        };

        let valid_with_metadata = InitializeMintArgs::new(
            6,
            mint_authority,
            freeze_authority,
            Some(metadata_pointer.clone()),
            Some(valid_metadata),
            None,
        );
        assert!(valid_with_metadata.validate().is_ok());

        // Invalid: metadata without metadata pointer (create a new metadata instance)
        let metadata_for_invalid_test = TokenMetadataArgs {
            update_authority: mint_authority,
            mint: mint_authority,
            name: name.to_string(),
            symbol: symbol.to_string(),
            uri: uri.to_string(),
            additional_metadata: additional_metadata.clone(),
        };
        let metadata_without_pointer = InitializeMintArgs::new(
            6,
            mint_authority,
            freeze_authority,
            None,
            Some(metadata_for_invalid_test),
            None,
        );
        assert!(metadata_without_pointer.validate().is_err());

        // Invalid metadata - empty name
        let bad_metadata = TokenMetadataArgs {
            update_authority: mint_authority,
            mint: mint_authority,
            name: "".to_string(),
            symbol: symbol.to_string(),
            uri: uri.to_string(),
            additional_metadata: additional_metadata.clone(),
        };
        let invalid_metadata = InitializeMintArgs::new(
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

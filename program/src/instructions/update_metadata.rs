use pinocchio::program_error::ProgramError;
use pinocchio_token_2022::extensions::metadata::TokenMetadata;

use crate::instructions::InitializeArgs;

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
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        InitializeArgs::serialize_token_metadata(&self.metadata)
    }

    /// Deserialize arguments from bytes
    pub fn try_from_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::pubkey::Pubkey;

    #[cfg(test)]
    fn random_pubkey() -> Pubkey {
        use pinocchio::pubkey::PUBKEY_BYTES;

        rand::random::<[u8; PUBKEY_BYTES]>()
    }

    #[test]
    fn test_update_metadata_args_to_bytes_inner_try_from_bytes() {
        // For now, we'll test just the to_bytes_inner/try_from_bytes mechanism without full metadata construction
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

        let inner_bytes = original.to_bytes_inner();
        let deserialized = UpdateMetadataArgs::try_from_bytes(&inner_bytes).unwrap();

        assert_eq!(
            original.metadata.update_authority,
            deserialized.metadata.update_authority
        );
        assert_eq!(original.metadata.mint, deserialized.metadata.mint);
        assert_eq!(original.metadata.name, deserialized.metadata.name);
        assert_eq!(original.metadata.symbol, deserialized.metadata.symbol);
        assert_eq!(original.metadata.uri, deserialized.metadata.uri);

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
}

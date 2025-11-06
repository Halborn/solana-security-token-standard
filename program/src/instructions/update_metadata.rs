use crate::instructions::{InitializeMintArgs, TokenMetadataArgs};
use pinocchio::program_error::ProgramError;
use shank::ShankType;

#[repr(C)]
#[derive(ShankType)]
pub struct UpdateMetadataArgs {
    pub metadata: TokenMetadataArgs,
}

impl UpdateMetadataArgs {
    /// Create new UpdateMetadataArgs
    pub fn new(metadata: TokenMetadataArgs) -> Self {
        Self { metadata }
    }

    /// Pack the arguments into bytes
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        InitializeMintArgs::serialize_token_metadata(&self.metadata)
    }

    /// Deserialize arguments from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let metadata = InitializeMintArgs::deserialize_token_metadata(data)?;
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
    use crate::test_utils::random_pubkey;

    #[test]
    fn test_update_metadata_args_to_bytes_inner_try_from_bytes() {
        // For now, we'll test just the to_bytes_inner/try_from_bytes mechanism without full metadata construction
        // since TokenMetadata requires proper lifetime management with &str and &[u8] fields

        let original = UpdateMetadataArgs::new(TokenMetadataArgs {
            update_authority: random_pubkey(),
            mint: random_pubkey(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            uri: "".to_string(),
            additional_metadata: vec![],
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
        let bad_metadata = TokenMetadataArgs {
            update_authority: random_pubkey(),
            mint: random_pubkey(),
            name: "".to_string(),
            symbol: "TST".to_string(),
            uri: "".to_string(),
            additional_metadata: vec![],
        };
        let invalid_args = UpdateMetadataArgs::new(bad_metadata);
        assert!(invalid_args.validate().is_err());
    }
}

use crate::instructions::TokenMetadataArgs;
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
        self.metadata.to_bytes()
    }

    /// Deserialize arguments from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let (metadata, _consumed) = TokenMetadataArgs::try_from_bytes(data)?;
        Ok(Self { metadata })
    }
}

//! Mint configuration account state
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};

/// Configuration data stored per mint
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintAuthority {
    /// SPL mint address this configuration belongs to
    pub mint: Pubkey,
    /// Original creator that participated in deriving the mint authority PDA
    pub mint_creator: Pubkey,
    /// Bump seed used for mint authority PDA derivation
    pub bump: u8,
}

impl MintAuthority {
    /// Serialized size of the account data (mint + creator + bump)
    pub const LEN: usize = (2 * PUBKEY_BYTES) + 1;

    /// Create a new MintAuthority
    pub fn new(mint: Pubkey, mint_creator: Pubkey, bump: u8) -> Result<Self, ProgramError> {
        let config = Self {
            mint,
            mint_creator,
            bump,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration data
    pub fn validate(&self) -> Result<(), ProgramError> {
        if self.mint == Pubkey::default() {
            return Err(ProgramError::InvalidAccountData);
        }

        if self.mint_creator == Pubkey::default() {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(())
    }

    /// Serialize the config into a byte vector
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);

        data.extend_from_slice(self.mint.as_ref());
        data.extend_from_slice(self.mint_creator.as_ref());
        data.push(self.bump);

        data
    }

    /// Deserialize config from raw bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let mint_bytes: [u8; PUBKEY_BYTES] = data[..PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        let creator_offset = PUBKEY_BYTES;
        let mint_creator_bytes: [u8; PUBKEY_BYTES] = data
            [creator_offset..creator_offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        let bump = data[creator_offset + PUBKEY_BYTES];

        let config = Self {
            mint: Pubkey::from(mint_bytes),
            mint_creator: Pubkey::from(mint_creator_bytes),
            bump,
        };

        config.validate()?;

        Ok(config)
    }
}

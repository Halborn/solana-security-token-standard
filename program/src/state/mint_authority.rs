//! Mint configuration account state
use crate::constants::seeds;
use crate::state::{
    AccountDeserialize, AccountSerialize, Discriminator, SecurityTokenDiscriminators,
};
use pinocchio::account_info::{AccountInfo, Ref};
use pinocchio::instruction::Seed;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{checked_create_program_address, Pubkey, PUBKEY_BYTES};
use shank::ShankAccount;

/// Configuration data stored per mint
#[repr(C)]
#[derive(ShankAccount)]
pub struct MintAuthority {
    /// SPL mint address this configuration belongs to
    pub mint: Pubkey,
    /// Original creator that participated in deriving the mint authority PDA
    pub mint_creator: Pubkey,
    /// Bump seed used for mint authority PDA derivation
    pub bump: u8,
}

impl Discriminator for MintAuthority {
    const DISCRIMINATOR: u8 = SecurityTokenDiscriminators::MintAuthorityDiscriminator as u8;
}

impl AccountSerialize for MintAuthority {
    fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN - 1);

        data.extend_from_slice(self.mint.as_ref());
        data.extend_from_slice(self.mint_creator.as_ref());
        data.push(self.bump);

        data
    }
}

impl AccountDeserialize for MintAuthority {
    fn try_from_bytes_inner(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN - 1 {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = 0;

        // Read mint (32 bytes)
        let mint_bytes: [u8; PUBKEY_BYTES] = data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += PUBKEY_BYTES;

        // Read mint_creator (32 bytes)
        let mint_creator_bytes: [u8; PUBKEY_BYTES] = data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += PUBKEY_BYTES;

        // Read bump (1 byte)
        let bump = data[offset];

        let config = Self {
            mint: Pubkey::from(mint_bytes),
            mint_creator: Pubkey::from(mint_creator_bytes),
            bump,
        };

        config.validate()?;

        Ok(config)
    }
}

impl MintAuthority {
    /// Serialized size of the account data (discriminator + mint + creator + bump)
    pub const LEN: usize = 1 + (2 * PUBKEY_BYTES) + 1;

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

    /// Parse from account info, verifying ownership and data length
    pub fn from_account_info(
        account_info: &AccountInfo,
    ) -> Result<Ref<MintAuthority>, ProgramError> {
        if account_info.data_len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        if !account_info.is_owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        let data_ref = account_info.try_borrow_data()?;
        let mint_authority = Self::try_from_bytes(&data_ref[..MintAuthority::LEN])?;
        Ok(Ref::map(account_info.try_borrow_data()?, |_| {
            &*Box::leak(Box::new(mint_authority))
        }))
    }

    pub fn bump_seed(&self) -> [u8; 1] {
        [self.bump]
    }

    pub fn seeds<'a>(&'a self, bump_seed: &'a [u8; 1]) -> [Seed<'a>; 4] {
        [
            Seed::from(seeds::MINT_AUTHORITY),
            Seed::from(self.mint.as_ref()),
            Seed::from(self.mint_creator.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Derive the PDA address for this MintAuthority using stored bump seed
    ///
    /// # Returns
    /// The derived PDA address or an error if derivation fails
    pub fn derive_pda(&self) -> Result<Pubkey, ProgramError> {
        let seeds = [
            seeds::MINT_AUTHORITY,
            self.mint.as_ref(),
            self.mint_creator.as_ref(),
            &[self.bump],
        ];
        checked_create_program_address(&seeds, &crate::id())
    }
}

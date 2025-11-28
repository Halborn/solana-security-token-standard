//! Receipt account state
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{create_program_address, Pubkey, PUBKEY_BYTES},
    ProgramResult,
};
use shank::ShankAccount;

use crate::{
    constants::{seeds::RECEIPT_ACCOUNT, ACTION_ID_LEN},
    state::{
        AccountDeserialize, AccountSerialize, Discriminator, ProgramAccount,
        SecurityTokenDiscriminators,
    },
    utils::parse_action_id_bytes,
};

#[repr(C)]
#[derive(Debug, ShankAccount)]
pub struct Receipt {
    /// Mint address this Receipt belongs to
    mint: Pubkey,
    /// Operation action identifier
    action_id: u64,
    /// Bump seed for PDA
    bump: u8,
}

impl Discriminator for Receipt {
    const DISCRIMINATOR: u8 = SecurityTokenDiscriminators::ReceiptDiscriminator as u8;
}

impl AccountSerialize for Receipt {
    fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);
        data.extend_from_slice(self.mint.as_ref());
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.push(self.bump);
        data
    }
}

impl AccountDeserialize for Receipt {
    fn try_from_bytes_inner(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN - 1 {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset = 0;

        // Read mint (32 bytes)
        let mint_bytes: [u8; PUBKEY_BYTES] = data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let mint = Pubkey::from(mint_bytes);
        offset += PUBKEY_BYTES;

        // Read action_id (8 bytes)
        let action_id = parse_action_id_bytes(&data[offset..offset + ACTION_ID_LEN])
            .ok_or(ProgramError::InvalidAccountData)?;
        offset += ACTION_ID_LEN;

        // Read bump (1 byte)
        let bump = data[offset];

        Ok(Self {
            mint,
            action_id,
            bump,
        })
    }
}

impl ProgramAccount for Receipt {
    fn space(&self) -> u64 {
        Self::LEN as u64
    }
}

impl Receipt {
    /// Serialized size: discriminator (1) + mint pubkey (32) + action_id (8) + bump (1) = 42 bytes
    pub const LEN: usize = 1 + PUBKEY_BYTES + ACTION_ID_LEN + 1;

    pub fn new(mint: Pubkey, action_id: u64, bump: u8) -> Result<Self, ProgramError> {
        let receipt = Self {
            mint,
            action_id,
            bump,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Issue new Receipt
    /// Create PDA account and write data into it
    pub fn issue(
        receipt_account: &AccountInfo,
        payer: &AccountInfo,
        mint: Pubkey,
        action_id: u64,
        receipt_bump: u8,
    ) -> ProgramResult {
        let receipt = Self::new(mint, action_id, receipt_bump)?;
        let action_id_seed = receipt.action_id_seed();
        let bump_seed = receipt.bump_seed();
        let seeds = receipt.seeds(&action_id_seed, &bump_seed);

        receipt.init(payer, receipt_account, &seeds)?;
        receipt.write_data(receipt_account)?;

        Ok(())
    }

    pub fn validate(&self) -> ProgramResult {
        if self.action_id == 0 {
            return Err(ProgramError::InvalidAccountData);
        };

        if self.mint == Pubkey::default() {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(())
    }

    pub fn action_id_seed(&self) -> [u8; ACTION_ID_LEN] {
        self.action_id.to_le_bytes()
    }

    pub fn bump_seed(&self) -> [u8; 1] {
        [self.bump]
    }

    pub fn seeds<'a>(&'a self, action_id_seed: &'a [u8], bump_seed: &'a [u8; 1]) -> [Seed<'a>; 4] {
        [
            Seed::from(RECEIPT_ACCOUNT),
            Seed::from(self.mint.as_ref()),
            Seed::from(action_id_seed),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    pub fn derive_pda(&self) -> Result<Pubkey, ProgramError> {
        create_program_address(
            &[
                RECEIPT_ACCOUNT,
                self.mint.as_ref(),
                &self.action_id_seed(),
                &self.bump_seed(),
            ],
            &crate::id(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::random_pubkey;
    use rstest::rstest;

    #[rstest]
    #[case(random_pubkey(), 12u64, 5u8)]
    #[case(random_pubkey(), u64::MAX, u8::MAX)]
    fn test_receipt_create(#[case] mint: Pubkey, #[case] action_id: u64, #[case] bump: u8) {
        let receipt = Receipt::new(mint, action_id, bump).expect("Should create receipt");
        receipt.validate().expect("Should be valid receipt");
    }

    #[test]
    fn test_receipt_serialize_deserialize() {
        let mint = random_pubkey();
        let action_id = 12u64;
        let bump = 5u8;
        let receipt = Receipt::new(mint, action_id, bump).expect("Should create receipt");

        let serialized = receipt.to_bytes();
        assert_eq!(serialized.len(), Receipt::LEN);
        let deserialized =
            Receipt::try_from_bytes(&serialized).expect("Should deserialize receipt");

        assert_eq!(deserialized.mint, mint);
        assert_eq!(deserialized.action_id, action_id);
        assert_eq!(deserialized.bump, bump);
    }

    #[rstest]
    #[case(random_pubkey(), 0u64, 5u8)]
    #[case(random_pubkey(), 0u64, 0u8)]
    #[case(Pubkey::default(), 0u64, 0u8)]
    fn test_create_invalid_receipt(#[case] mint: Pubkey, #[case] action_id: u64, #[case] bump: u8) {
        let receipt_error =
            Receipt::new(mint, action_id, bump).expect_err("Should not create receipt");
        assert_eq!(receipt_error, ProgramError::InvalidAccountData);
    }
}

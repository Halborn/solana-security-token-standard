//! Rate account state
use num_derive::FromPrimitive;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;

use crate::state::{
    AccountDeserialize, AccountSerialize, Discriminator, SecurityTokenDiscriminators,
};

#[derive(Clone, Debug, PartialEq, Eq, Copy, FromPrimitive)]
#[repr(u8)]
pub enum Rounding {
    Up = 0,
    Down = 1,
}

impl Into<u8> for Rounding {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Rounding {
    type Error = ProgramError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Rounding::Up),
            1 => Ok(Rounding::Down),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

/// Configuration data stored per mint
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rate {
    /// Rounding direction (Up or Down)
    pub rounding: Rounding,
    /// Rate numerator
    pub numerator: u8,
    /// Rate denominator
    pub denominator: u8,
    /// Bump seed used for PDA derivation
    pub bump: u8,
}

impl Discriminator for Rate {
    const DISCRIMINATOR: u8 = SecurityTokenDiscriminators::RateDiscriminator as u8;
}

impl AccountSerialize for Rate {
    fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN - 1);

        data.push(self.rounding.into());
        data.push(self.numerator);
        data.push(self.denominator);
        data.push(self.bump);

        data
    }
}

impl AccountDeserialize for Rate {
    fn try_from_bytes_inner(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN - 1 {
            return Err(ProgramError::InvalidAccountData);
        }

        let rounding = Rounding::try_from(data[0])?;
        let numerator = data[1];
        let denominator = data[2];
        let bump = data[3];

        Ok(Self {
            rounding,
            numerator,
            denominator,
            bump,
        })
    }
}

impl Rate {
    /// Serialized size of the account data (discriminator + rounding enum + numerator + denominator + bump)
    pub const LEN: usize = 1 + (1 + 1) + 1 + 1 + 1;

    /// Create a new Rate
    pub fn new(
        rounding: Rounding,
        numerator: u8,
        denominator: u8,
        bump: u8,
    ) -> Result<Self, ProgramError> {
        let rate = Self {
            rounding,
            numerator,
            denominator,
            bump,
        };
        rate.validate()?;
        Ok(rate)
    }

    /// Validate the rate account data
    pub fn validate(&self) -> Result<(), ProgramError> {
        if self.denominator == 0 || self.numerator == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }

    /// Calculate the rate applied to the given amount
    pub fn calculate(&self, amount: u64) -> Result<u64, ProgramError> {
        match self.rounding {
            Rounding::Up => {
                let result = amount
                    .checked_mul(self.numerator as u64)
                    .ok_or(ProgramError::ArithmeticOverflow)?
                    .div_ceil(self.denominator as u64);
                Ok(result)
            }
            Rounding::Down => {
                let result = amount
                    .checked_mul(self.numerator as u64)
                    .ok_or(ProgramError::ArithmeticOverflow)?
                    .checked_div(self.denominator as u64)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
                Ok(result)
            }
        }
    }

    /// Parse from account info
    pub fn from_account_info(account_info: &AccountInfo) -> Result<Rate, ProgramError> {
        if account_info.data_len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        if !account_info.is_owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        let data_ref = account_info.try_borrow_data()?;
        let rate = Self::try_from_bytes(&data_ref)?;
        Ok(rate)
    }
}

//! Rate account state
use pinocchio::instruction::Seed;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{create_program_address, Pubkey};
use pinocchio::{account_info::AccountInfo, ProgramResult};
use shank::{ShankAccount, ShankType};

use crate::constants::seeds::RATE_ACCOUNT;
use crate::state::{
    AccountDeserialize, AccountSerialize, Discriminator, ProgramAccount,
    SecurityTokenDiscriminators,
};

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Eq, Copy, ShankType)]
pub enum Rounding {
    Up = 0,
    Down = 1,
}

impl From<Rounding> for u8 {
    fn from(rounding: Rounding) -> Self {
        rounding as u8
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
#[repr(C)]
#[derive(ShankAccount)]
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
        if data.len() != Self::LEN - 1 {
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

impl ProgramAccount for Rate {
    fn space(&self) -> u64 {
        Self::LEN as u64
    }
}

impl Rate {
    /// Serialized size of the account data (discriminator + rounding enum + numerator + denominator + bump)
    pub const LEN: usize = 1 + 1 + 1 + 1 + 1;

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

    /// Update Rate data
    pub fn update(&mut self, rounding: Rounding, numerator: u8, denominator: u8) -> ProgramResult {
        self.rounding = rounding;
        self.numerator = numerator;
        self.denominator = denominator;
        self.validate()?;
        Ok(())
    }

    /// Validate the Rate account data
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

    pub fn bump_seed(&self) -> [u8; 1] {
        [self.bump]
    }

    pub fn seeds<'a>(
        &'a self,
        action_id_seed: &'a [u8],
        mint_from: &'a Pubkey,
        mint_to: &'a Pubkey,
        bump_seed: &'a [u8; 1],
    ) -> [Seed<'a>; 5] {
        [
            Seed::from(RATE_ACCOUNT),
            Seed::from(action_id_seed),
            Seed::from(mint_from.as_ref()),
            Seed::from(mint_to.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ]
    }

    /// Optimized PDA derivation with known bump seed
    pub fn derive_pda(
        &self,
        action_id: u64,
        mint_from: &Pubkey,
        mint_to: &Pubkey,
    ) -> Result<Pubkey, ProgramError> {
        create_program_address(
            &[
                RATE_ACCOUNT,
                action_id.to_le_bytes().as_ref(),
                mint_from,
                mint_to,
                &self.bump_seed(),
            ],
            &crate::id(),
        )
    }

    /// Convert amount of token A (amount_from) to token B (amount_to) with Rate parameters
    pub fn convert_from_to_amount(
        &self,
        amount_from: u64,
        decimals_from: u8,
        decimals_to: u8,
    ) -> Result<u64, ProgramError> {
        if amount_from == 0 {
            return Ok(0);
        }

        let (numerator_scaled, denominator_scaled): (u128, u128) = if decimals_to >= decimals_from {
            let delta = decimals_to - decimals_from;
            let scale = 10u64
                .checked_pow(delta as u32)
                .ok_or(ProgramError::ArithmeticOverflow)? as u128;
            // amount_from * numerator * 10^{delta}
            let numerator = (amount_from as u128)
                .checked_mul(self.numerator as u128)
                .and_then(|v| v.checked_mul(scale))
                .ok_or(ProgramError::ArithmeticOverflow)?;
            (numerator, self.denominator as u128)
        } else {
            let delta = decimals_from - decimals_to;
            let scale = 10u64
                .checked_pow(delta as u32)
                .ok_or(ProgramError::ArithmeticOverflow)? as u128;
            // denominator * 10^{delta}
            let denominator = (self.denominator as u128)
                .checked_mul(scale)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            let numerator = (amount_from as u128)
                .checked_mul(self.numerator as u128)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            (numerator, denominator)
        };

        let result = match self.rounding {
            Rounding::Down => numerator_scaled
                .checked_div(denominator_scaled)
                .ok_or(ProgramError::ArithmeticOverflow)?,
            Rounding::Up => numerator_scaled.div_ceil(denominator_scaled),
        };

        u64::try_from(result).map_err(|_| ProgramError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Rounding::Up, 1u8, 3u8, 100_000u64, 33_334u64)]
    #[case(Rounding::Up, 2u8, 3u8, 1000u64, 667u64)]
    #[case(Rounding::Down, 1u8, 3u8, 100_000u64, 33_333u64)]
    #[case(Rounding::Down, 2u8, 3u8, 1000u64, 666u64)]
    fn test_rate_calculate_valid_args(
        #[case] rounding: Rounding,
        #[case] numerator: u8,
        #[case] denominator: u8,
        #[case] amount: u64,
        #[case] expected: u64,
    ) {
        let rate = Rate {
            rounding,
            numerator,
            denominator,
            bump: 0,
        };

        let result = rate.calculate(amount).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case(Rounding::Down, 1, 3, 1_000, 3, 6, 333_333)]
    #[case(Rounding::Up, 1, 3, 1_000, 3, 6, 333_334)]
    #[case(Rounding::Down, 2, 3, 1_000, 3, 6, 666_666)]
    #[case(Rounding::Up, 2, 3, 1_000, 3, 6, 666_667)]
    #[case(Rounding::Down, 3, 2, 1_000, 3, 6, 1_500_000)]
    #[case(Rounding::Up, 5, 4, 1_000, 3, 6, 1_250_000)]
    #[case(Rounding::Down, 1, 2, 10_000_000, 6, 3, 5_000)]
    #[case(Rounding::Up, 1, 2, 10_500_000, 6, 3, 5_250)]
    #[case(Rounding::Down, 7, 8, 1_000, 3, 3, 875)]
    // 6 -> 9 decimals, 10 tokens
    #[case(Rounding::Down, 3, 7, 1_000_000_000, 6, 9, 428_571_428_571)]
    #[case(Rounding::Up, 3, 7, 1_000_000_000, 6, 9, 428_571_428_572)]
    // 9 -> 6 decimals, 10 tokens
    #[case(Rounding::Down, 3, 7, 10_000_000_000, 9, 6, 4_285_714)]
    #[case(Rounding::Up, 3, 7, 10_000_000_000, 9, 6, 4_285_715)]
    #[case(Rounding::Up, 1, 1, 10_000, 6, 6, 10_000)]
    #[case(Rounding::Up, 255, 255, 10_000_000, 6, 3, 10_000)]
    #[case(Rounding::Up, 1, 255, 10_000_000, 6, 3, 40)]
    #[case(Rounding::Down, 1, 255, 10_000_000, 6, 3, 39)]
    #[case(Rounding::Down, 1, 1, u64::MAX, 6, 6, u64::MAX)]
    #[case(Rounding::Down, 255, 255, u64::MAX, 9, 6, 18_446_744_073_709_551)]
    // converting small amounts with Rounding::Down can result in zero
    #[case(Rounding::Down, 1, 255, 1_000, 6, 3, 0)]
    // Rounding::Up returns 1
    #[case(Rounding::Up, 1, 255, 1_000, 6, 3, 1)]
    fn test_convert_from_to_amount_cases(
        #[case] rounding: Rounding,
        #[case] numerator: u8,
        #[case] denominator: u8,
        #[case] amount_from: u64,
        #[case] decimals_from: u8,
        #[case] decimals_to: u8,
        #[case] expected: u64,
    ) {
        let rate = Rate {
            rounding,
            numerator,
            denominator,
            bump: 0,
        };
        let calculated = rate
            .convert_from_to_amount(amount_from, decimals_from, decimals_to)
            .unwrap();
        assert_eq!(
            calculated, expected,
            "Conversion not matching expected value"
        );
    }
}

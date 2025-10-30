use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::state::Rounding;

/// Arguments to create Rate account
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CreateRateArgs {
    /// Action ID for the rate creation
    pub action_id: u64,
    /// Rate configuration arguments
    pub rate: RateArgs,
}

impl CreateRateArgs {
    /// action_id + rate arguments
    pub const LEN: usize = 8 + RateArgs::LEN;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let action_id = data
            .get(..8)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ProgramError::InvalidArgument)?;

        if action_id == 0 {
            return Err(ProgramError::InvalidArgument);
        }

        let rate_args_data = data.get(8..).ok_or(ProgramError::InvalidInstructionData)?;
        let rate_args = RateArgs::try_from_bytes(rate_args_data)?;

        let create_rate_args = Self {
            action_id,
            rate: rate_args,
        };

        Ok(create_rate_args)
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);

        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.extend_from_slice(self.rate.to_bytes_inner().as_ref());

        data
    }
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct RateArgs {
    /// Rounding direction (0 = Up, Down = 1)
    pub rounding: u8,
    /// Rate numerator
    pub numerator: u8,
    /// Rate denominator
    pub denominator: u8,
}

impl RateArgs {
    /// rounding + numerator + denominator
    pub const LEN: usize = 1 + 1 + 1;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let rounding = Rounding::try_from(data[0]).map_err(|_| ProgramError::InvalidArgument)?;
        let numerator = data[1];
        let denominator = data[2];

        if denominator == 0 || numerator == 0 {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(Self {
            rounding: rounding.into(),
            numerator,
            denominator,
        })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);

        data.push(self.rounding);
        data.push(self.numerator);
        data.push(self.denominator);

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(42u64, 1u8, 5u8, 10u8)]
    #[case(1u64, 0u8, 44u8, 33u8)]
    #[case(u64::MAX, 1u8, u8::MAX, u8::MAX)]
    fn test_create_rate_args_to_bytes_inner_try_from_bytes(
        #[case] action_id: u64,
        #[case] rounding: u8,
        #[case] numerator: u8,
        #[case] denominator: u8,
    ) {
        let original = CreateRateArgs {
            action_id,
            rate: RateArgs {
                rounding,
                numerator,
                denominator,
            },
        };

        let bytes = original.to_bytes_inner();
        let deserialized =
            CreateRateArgs::try_from_bytes(&bytes).expect("Should deserialize rate arguments");

        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.rate.rounding, deserialized.rate.rounding);
        assert_eq!(original.rate.numerator, deserialized.rate.numerator);
        assert_eq!(original.rate.denominator, deserialized.rate.denominator);
    }

    #[rstest]
    #[case(0u64, 1u8, 5u8, 10u8, "Zero action_id should be invalid")]
    #[case(1u64, 3u8, 5u8, 10u8, "Rounding enum (3u8) should be invalid")]
    #[case(1u64, 0u8, 0u8, 10u8, "Zero numerator should be invalid")]
    #[case(1u64, 0u8, 2u8, 0u8, "Zero denominator should be invalid")]
    fn test_create_rate_args_validation(
        #[case] action_id: u64,
        #[case] rounding: u8,
        #[case] numerator: u8,
        #[case] denominator: u8,
        #[case] description: &str,
    ) {
        let original = CreateRateArgs {
            action_id,
            rate: RateArgs {
                rounding,
                numerator,
                denominator,
            },
        };

        assert!(
            CreateRateArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

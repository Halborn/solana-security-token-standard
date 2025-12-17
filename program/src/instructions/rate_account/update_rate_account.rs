use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::instructions::rate_account::shared::{
    parse_action_and_rate, serialize_action_and_rate, RateConfig, ACTION_AND_RATE_ARGS_LEN,
};

/// Arguments for updating Rate account
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct UpdateRateArgs {
    /// Action ID for the rate update
    pub action_id: u64,
    /// Rate configuration arguments
    pub rate: RateConfig,
}

impl UpdateRateArgs {
    /// Fixed size: action_id (8 bytes) + rate arguments (3 bytes) = 11 bytes
    pub const LEN: usize = ACTION_AND_RATE_ARGS_LEN;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let (action_id, rate) = parse_action_and_rate(data)?;
        Ok(Self { action_id, rate })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        serialize_action_and_rate(self.action_id, &self.rate)
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
    fn test_update_rate_args_to_bytes_inner_try_from_bytes(
        #[case] action_id: u64,
        #[case] rounding: u8,
        #[case] numerator: u8,
        #[case] denominator: u8,
    ) {
        let original = UpdateRateArgs {
            action_id,
            rate: RateConfig {
                rounding,
                numerator,
                denominator,
            },
        };

        let bytes = original.to_bytes_inner();
        let deserialized =
            UpdateRateArgs::try_from_bytes(&bytes).expect("Should deserialize rate arguments");

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
    fn test_update_rate_args_validation(
        #[case] action_id: u64,
        #[case] rounding: u8,
        #[case] numerator: u8,
        #[case] denominator: u8,
        #[case] description: &str,
    ) {
        let original = UpdateRateArgs {
            action_id,
            rate: RateConfig {
                rounding,
                numerator,
                denominator,
            },
        };

        assert!(
            UpdateRateArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::instructions::rate_account::shared::parse_action_id_argument;

/// Arguments to split a token amount according to a rate
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct SplitArgs {
    /// Action ID for the split
    pub action_id: u64,
}

impl SplitArgs {
    /// action_id
    pub const LEN: usize = 8;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let action_id = parse_action_id_argument(data)?;
        Ok(Self { action_id })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(42u64)]
    #[case(1u64)]
    #[case(u64::MAX)]
    fn test_create_split_args_to_bytes(#[case] action_id: u64) {
        let original = SplitArgs { action_id };

        let bytes = original.to_bytes_inner();
        let deserialized = SplitArgs::try_from_bytes(&bytes).expect("Should deserialize SplitArgs");

        assert_eq!(original.action_id, deserialized.action_id);
    }

    #[rstest]
    #[case(0u64, "Zero action_id should be invalid")]
    fn test_create_split_args_validation(#[case] action_id: u64, #[case] description: &str) {
        let original = SplitArgs { action_id };

        assert!(
            SplitArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN, instructions::rate_account::shared::parse_action_id_argument,
};

/// Arguments to convert a token A to token B according to the rate
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct ConvertArgs {
    /// Action ID for the conversion operation
    pub action_id: u64,
    /// Amount to convert from token A to token B
    pub amount_to_convert: u64,
}

impl ConvertArgs {
    /// Fixed size: action_id (8 bytes) + amount (8 bytes) = 16 bytes
    pub const LEN: usize = ACTION_ID_LEN + 8;

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let action_id = parse_action_id_argument(&data[..ACTION_ID_LEN])?;

        let amount_to_convert = u64::from_le_bytes(
            data[ACTION_ID_LEN..ACTION_ID_LEN + 8]
                .try_into()
                .map_err(|_| ProgramError::InvalidArgument)?,
        );

        if amount_to_convert == 0 {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(Self {
            action_id,
            amount_to_convert,
        })
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::LEN);
        data.extend_from_slice(self.action_id.to_le_bytes().as_ref());
        data.extend_from_slice(self.amount_to_convert.to_le_bytes().as_ref());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(42u64, 1000u64)]
    #[case(1u64, 1u64)]
    #[case(u64::MAX, u64::MAX)]
    fn test_create_convert_args_to_bytes(#[case] action_id: u64, #[case] amount_to_convert: u64) {
        let original = ConvertArgs {
            action_id,
            amount_to_convert,
        };

        let bytes = original.to_bytes_inner();
        let deserialized =
            ConvertArgs::try_from_bytes(&bytes).expect("Should deserialize ConvertArgs");

        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.amount_to_convert, deserialized.amount_to_convert);
    }

    #[rstest]
    #[case(0u64, 100u64, "Zero action_id should be invalid")]
    #[case(1u64, 0u64, "Zero amount_to_convert should be invalid")]
    fn test_create_convert_args_validation(
        #[case] action_id: u64,
        #[case] amount_to_convert: u64,
        #[case] description: &str,
    ) {
        let original = ConvertArgs {
            action_id,
            amount_to_convert,
        };

        assert!(
            ConvertArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

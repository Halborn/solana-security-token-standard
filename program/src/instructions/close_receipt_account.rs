use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::instructions::rate_account::shared::parse_action_id_argument;

/// Arguments to close Receipt account
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CloseReceiptArgs {
    /// Action ID of the Receipt and Rate
    pub action_id: u64,
}

impl CloseReceiptArgs {
    /// Parse CloseReceiptArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let action_id = parse_action_id_argument(data)?;
        Ok(Self { action_id })
    }

    /// Pack the arguments into bytes
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        self.action_id.to_le_bytes().to_vec()
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
    fn test_close_receipt_args_try_from_bytes(#[case] action_id: u64) {
        let original = CloseReceiptArgs { action_id };

        let bytes = original.to_bytes_inner();
        let deserialized =
            CloseReceiptArgs::try_from_bytes(&bytes).expect("Should deserialize receipt arguments");

        assert_eq!(original.action_id, deserialized.action_id);
    }

    #[rstest]
    #[case(0u64, "Zero action_id should be invalid")]
    fn test_close_receipt_args_validation(#[case] action_id: u64, #[case] description: &str) {
        let original = CloseReceiptArgs { action_id };

        assert!(
            CloseReceiptArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

use pinocchio::{
    program_error::ProgramError,
    pubkey::{Pubkey, PUBKEY_BYTES},
};
use shank::ShankType;

use crate::{
    constants::ACTION_ID_LEN, instructions::rate_account::shared::parse_action_id_argument,
};

/// Arguments to closing Receipt account of operation tied to action_id and token account (e.g. split, convert)
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CloseActionReceiptArgs {
    /// Action ID of the operation
    pub action_id: u64,
    /// Token account used in the original Split/Convert — part of Receipt PDA seeds
    pub token_account: Pubkey,
}

impl CloseActionReceiptArgs {
    pub const LEN: usize = ACTION_ID_LEN + PUBKEY_BYTES;

    /// Parse CloseActionReceiptArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let action_id = parse_action_id_argument(&data[..ACTION_ID_LEN])?;
        let token_account: Pubkey = data[ACTION_ID_LEN..ACTION_ID_LEN + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        Ok(Self {
            action_id,
            token_account,
        })
    }

    /// Pack the arguments into bytes
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut bytes = self.action_id.to_le_bytes().to_vec();
        bytes.extend_from_slice(self.token_account.as_ref());
        bytes
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
    fn test_close_action_receipt_args_try_from_bytes(#[case] action_id: u64) {
        let token_account = [7u8; PUBKEY_BYTES];
        let original = CloseActionReceiptArgs {
            action_id,
            token_account,
        };

        let bytes = original.to_bytes_inner();
        let deserialized = CloseActionReceiptArgs::try_from_bytes(&bytes)
            .expect("Should deserialize CloseActionReceiptArgs");
        assert_eq!(original.action_id, deserialized.action_id);
        assert_eq!(original.token_account, deserialized.token_account);
    }

    #[rstest]
    #[case(0u64, "Zero action_id should be invalid")]
    fn test_close_common_receipt_args_validation(
        #[case] action_id: u64,
        #[case] description: &str,
    ) {
        let original = CloseActionReceiptArgs {
            action_id,
            token_account: [0u8; PUBKEY_BYTES],
        };

        assert!(
            CloseActionReceiptArgs::try_from_bytes(&original.to_bytes_inner()).is_err(),
            "{}",
            description
        );
    }
}

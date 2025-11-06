use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::instructions::rate_account::shared::parse_action_id_argument;

/// Arguments to close Rate account
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CloseRateArgs {
    /// Action ID of the Rate
    pub action_id: u64,
}

impl CloseRateArgs {
    /// Parse CloseRateArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let action_id = parse_action_id_argument(data)?;
        Ok(Self { action_id })
    }
}

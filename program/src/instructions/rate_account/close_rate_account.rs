use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::instructions::rate_account::parse_action_id;

/// Arguments to close Rate account
#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct CloseRateArgs {
    /// Action ID of the rate
    pub action_id: u64,
}

impl CloseRateArgs {
    /// Parse CloseRateArgs from bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let action_id = parse_action_id(data)?;
        Ok(Self { action_id })
    }
}

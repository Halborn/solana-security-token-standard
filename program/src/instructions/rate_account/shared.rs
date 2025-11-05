use pinocchio::program_error::ProgramError;
use shank::ShankType;

use crate::{constants::ACTION_ID_LEN, state::Rounding, utils::parse_action_id_bytes};

pub const ACTION_AND_RATE_ARGS_LEN: usize = ACTION_ID_LEN + RateArgs::LEN;

#[repr(C)]
#[derive(Clone, Debug, PartialEq, ShankType)]
pub struct RateArgs {
    /// Rounding direction (0 = Up, 1 = Down)
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

/// Parse (action_id, RateArgs) from bytes
pub fn parse_action_and_rate(data: &[u8]) -> Result<(u64, RateArgs), ProgramError> {
    if data.len() != ACTION_AND_RATE_ARGS_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let action_id = parse_action_id_argument(&data[..ACTION_ID_LEN])?;

    let rate_args_data = &data[ACTION_ID_LEN..];
    let rate_args = RateArgs::try_from_bytes(rate_args_data)?;

    Ok((action_id, rate_args))
}

/// Parse action_id from bytes
pub fn parse_action_id_argument(data: &[u8]) -> Result<u64, ProgramError> {
    if data.len() != ACTION_ID_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let action_id = parse_action_id_bytes(data).ok_or(ProgramError::InvalidArgument)?;

    if action_id == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(action_id)
}

/// Serialize (action_id, Rate arguments) into bytes
pub fn serialize_action_and_rate(action_id: u64, rate: &RateArgs) -> Vec<u8> {
    let mut data = Vec::with_capacity(ACTION_AND_RATE_ARGS_LEN);
    data.extend_from_slice(action_id.to_le_bytes().as_ref());
    data.extend_from_slice(rate.to_bytes_inner().as_ref());
    data
}

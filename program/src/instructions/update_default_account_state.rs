use pinocchio::program_error::ProgramError;
use pinocchio_token_2022::state::AccountState;
use shank::ShankType;

#[repr(C)]
#[derive(ShankType)]
pub struct UpdateDefaultAccountStateArgs {
    pub state: u8,
}

impl UpdateDefaultAccountStateArgs {
    pub fn new(state: u8) -> Self {
        Self { state }
    }

    pub fn to_bytes_inner(&self) -> Vec<u8> {
        vec![self.state]
    }

    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(Self { state: data[0] })
    }

    pub fn validate(&self) -> Result<(), ProgramError> {
        if !matches!(AccountState::from(self.state), AccountState::Initialized | AccountState::Frozen) {
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }
}

use pinocchio::program_error::ProgramError;

/// Trait for PDA-backed account types that expose a unique discriminator byte.
///
/// Every serialized account stores its discriminator as the very first byte so that
/// deserializers can quickly detect which concrete account layout should be used.
pub trait Discriminator {
    const DISCRIMINATOR: u8;
}

#[repr(u8)]
pub enum SecurityTokenDiscriminators {
    MintAuthorityDiscriminator = 0,
    VerificationConfigDiscriminator = 1,
}

impl TryFrom<u8> for SecurityTokenDiscriminators {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SecurityTokenDiscriminators::MintAuthorityDiscriminator),
            1 => Ok(SecurityTokenDiscriminators::VerificationConfigDiscriminator),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

pub trait AccountSerialize: Discriminator {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(Self::DISCRIMINATOR);

        data.extend(self.to_bytes_inner());

        data
    }

    /// Serialize the struct body without the discriminator byte.
    fn to_bytes_inner(&self) -> Vec<u8>;
}

pub trait AccountDeserialize: Discriminator + Sized {
    fn try_from_bytes_inner(data: &[u8]) -> Result<Self, ProgramError>;

    fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let (disc, rest) = data.split_first().ok_or(ProgramError::InvalidAccountData)?;
        if *disc != Self::DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Self::try_from_bytes_inner(rest)
    }
}

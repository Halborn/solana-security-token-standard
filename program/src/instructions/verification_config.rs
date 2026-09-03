//! Verification configuration instruction arguments and utilities
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};
use shank::ShankType;
use spl_tlv_account_resolution::{pubkey_data::PubkeyData, seeds::Seed};

use crate::constants::{
    MAX_TOTAL_VERIFICATION_EXTRAS, MAX_VERIFICATION_EXTRAS_PER_PROGRAM, MAX_VERIFICATION_PROGRAMS,
};
use crate::instruction::SecurityTokenInstruction;

const MAX_PDA_SEED_LEN: usize = 32;
const TRANSFER_HOOK_EXECUTE_DATA_OFFSET: u8 = 8;

/// Wire-compatible representation of SPL `ExtraAccountMeta`.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, ShankType)]
pub struct VerificationAccountMeta {
    pub discriminator: u8,
    pub address_config: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

impl VerificationAccountMeta {
    pub const LEN: usize = 35;
}

/// One verification program and its private ordered extra-account declarations.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, ShankType)]
pub struct VerificationProgramConfig {
    pub program_id: Pubkey,
    pub extra_accounts: Vec<VerificationAccountMeta>,
}

/// Arguments for InitializeVerificationConfig instruction
#[repr(C)]
#[derive(ShankType)]
pub struct InitializeVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// 1-byte CPI mode
    pub cpi_mode: bool,
    /// Verification programs and their extra account declarations
    pub programs: Vec<VerificationProgramConfig>,
}

/// Arguments for UpdateVerificationConfig instruction
#[repr(C)]
#[derive(ShankType)]
pub struct UpdateVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// 1-byte CPI mode
    pub cpi_mode: bool,
    /// Offset at which to start replacement/insertion (0-based index)
    pub offset: u8,
    /// New verification programs and their extra account declarations
    pub programs: Vec<VerificationProgramConfig>,
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<usize, ProgramError> {
    let end = offset
        .checked_add(4)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let value = u32::from_le_bytes(
        data.get(*offset..end)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    ) as usize;
    *offset = end;
    Ok(value)
}

pub(crate) fn read_bool(data: &[u8], offset: &mut usize) -> Result<bool, ProgramError> {
    let value = *data
        .get(*offset)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *offset = offset
        .checked_add(1)
        .ok_or(ProgramError::InvalidInstructionData)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub(crate) fn serialize_programs(programs: &[VerificationProgramConfig], data: &mut Vec<u8>) {
    data.extend_from_slice(&(programs.len() as u32).to_le_bytes());
    for program in programs {
        data.extend_from_slice(program.program_id.as_ref());
        data.extend_from_slice(&(program.extra_accounts.len() as u32).to_le_bytes());
        for meta in &program.extra_accounts {
            data.push(meta.discriminator);
            data.extend_from_slice(&meta.address_config);
            data.push(meta.is_signer as u8);
            data.push(meta.is_writable as u8);
        }
    }
}

pub(crate) fn parse_programs(
    data: &[u8],
    offset: &mut usize,
) -> Result<Vec<VerificationProgramConfig>, ProgramError> {
    let program_count = read_u32(data, offset)?;
    if program_count > MAX_VERIFICATION_PROGRAMS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut total_extras = 0usize;
    let mut programs = Vec::with_capacity(program_count);
    for _ in 0..program_count {
        let program_end = offset
            .checked_add(PUBKEY_BYTES)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let program_id = Pubkey::from(
            <[u8; PUBKEY_BYTES]>::try_from(
                data.get(*offset..program_end)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )
            .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        *offset = program_end;

        let extra_count = read_u32(data, offset)?;
        if extra_count > MAX_VERIFICATION_EXTRAS_PER_PROGRAM {
            return Err(ProgramError::InvalidInstructionData);
        }
        total_extras = total_extras
            .checked_add(extra_count)
            .ok_or(ProgramError::InvalidInstructionData)?;
        if total_extras > MAX_TOTAL_VERIFICATION_EXTRAS {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut extra_accounts = Vec::with_capacity(extra_count);
        for _ in 0..extra_count {
            let discriminator = *data
                .get(*offset)
                .ok_or(ProgramError::InvalidInstructionData)?;
            *offset = offset
                .checked_add(1)
                .ok_or(ProgramError::InvalidInstructionData)?;
            let address_end = offset
                .checked_add(32)
                .ok_or(ProgramError::InvalidInstructionData)?;
            let address_config = data
                .get(*offset..address_end)
                .ok_or(ProgramError::InvalidInstructionData)?
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            *offset = address_end;
            let is_signer = read_bool(data, offset)?;
            let is_writable = read_bool(data, offset)?;
            extra_accounts.push(VerificationAccountMeta {
                discriminator,
                address_config,
                is_signer,
                is_writable,
            });
        }
        programs.push(VerificationProgramConfig {
            program_id,
            extra_accounts,
        });
    }
    Ok(programs)
}

/// Number of fixed Core accounts (verification overhead excluded).
pub fn core_account_count(instruction_discriminator: u8) -> Result<usize, ProgramError> {
    use SecurityTokenInstruction::*;
    match SecurityTokenInstruction::try_from(instruction_discriminator)
        .map_err(|_| ProgramError::InvalidArgument)?
    {
        InitializeMint | Verify => Err(ProgramError::InvalidArgument),
        UpdateMetadata => Ok(5),
        InitializeVerificationConfig | UpdateVerificationConfig | TrimVerificationConfig => Ok(7),
        Mint | Burn | Freeze | Thaw => Ok(4),
        Pause
        | Resume
        | UpdateRateAccount
        | CloseActionReceiptAccount
        | UpdateDefaultAccountState => Ok(3),
        Transfer => Ok(6),
        CreateRateAccount | CreateProofAccount | UpdateProofAccount | CloseClaimReceiptAccount => {
            Ok(5)
        }
        CloseRateAccount => Ok(4),
        Split => Ok(9),
        Convert => Ok(11),
        CreateDistributionEscrow => Ok(7),
        ClaimDistribution => Ok(10),
    }
}

/// Number of accounts visible in a verifier's canonical base.
pub fn canonical_base_count(instruction_discriminator: u8) -> Result<usize, ProgramError> {
    if instruction_discriminator == SecurityTokenInstruction::Transfer.discriminant() {
        Ok(4)
    } else {
        core_account_count(instruction_discriminator)
    }
}

fn fixed_instruction_data_len(instruction_discriminator: u8) -> Option<usize> {
    use SecurityTokenInstruction::*;
    match SecurityTokenInstruction::try_from(instruction_discriminator).ok()? {
        TrimVerificationConfig => Some(4),
        Mint | Burn | Transfer => Some(9),
        Pause | Resume | Freeze | Thaw => Some(1),
        CloseActionReceiptAccount => Some(41),
        UpdateDefaultAccountState => Some(2),
        _ => None,
    }
}

fn validate_meta(
    meta: &VerificationAccountMeta,
    available_accounts: usize,
    instruction_data_len: Option<usize>,
) -> ProgramResult {
    match meta.discriminator {
        0 => Ok(()),
        1 => {
            if meta.is_signer {
                return Err(ProgramError::InvalidArgument);
            }
            let seeds = Seed::unpack_address_config(&meta.address_config)
                .map_err(|_| ProgramError::InvalidArgument)?;
            if Seed::pack_into_address_config(&seeds).map_err(|_| ProgramError::InvalidArgument)?
                != meta.address_config
            {
                return Err(ProgramError::InvalidArgument);
            }
            for seed in seeds {
                match seed {
                    Seed::AccountKey { index } if index as usize >= available_accounts => {
                        return Err(ProgramError::InvalidArgument)
                    }
                    Seed::AccountData {
                        account_index,
                        length,
                        ..
                    } if account_index as usize >= available_accounts
                        || length as usize > MAX_PDA_SEED_LEN =>
                    {
                        return Err(ProgramError::InvalidArgument)
                    }
                    Seed::InstructionData { index, length }
                        if length as usize > MAX_PDA_SEED_LEN
                            || instruction_data_len.is_some_and(|data_len| {
                                match (index as usize).checked_add(length as usize) {
                                    Some(end) => end > data_len,
                                    None => true,
                                }
                            }) =>
                    {
                        return Err(ProgramError::InvalidArgument)
                    }
                    _ => {}
                }
            }
            Ok(())
        }
        2 => {
            let pubkey_data = PubkeyData::unpack(&meta.address_config)
                .map_err(|_| ProgramError::InvalidArgument)?;
            if PubkeyData::pack_into_address_config(&pubkey_data)
                .map_err(|_| ProgramError::InvalidArgument)?
                != meta.address_config
            {
                return Err(ProgramError::InvalidArgument);
            }
            match pubkey_data {
                PubkeyData::Uninitialized => Err(ProgramError::InvalidArgument),
                PubkeyData::AccountData { account_index, .. }
                    if account_index as usize >= available_accounts =>
                {
                    Err(ProgramError::InvalidArgument)
                }
                PubkeyData::InstructionData { index }
                    if instruction_data_len.is_some_and(|data_len| {
                        match (index as usize).checked_add(PUBKEY_BYTES) {
                            Some(end) => end > data_len,
                            None => true,
                        }
                    }) =>
                {
                    Err(ProgramError::InvalidArgument)
                }
                _ => Ok(()),
            }
        }
        _ => Err(ProgramError::InvalidArgument),
    }
}

fn validate_transfer_meta_compilation(meta: &VerificationAccountMeta) -> ProgramResult {
    // Transfer declarations must fit the 32-byte SPL meta encoding after Core's local
    // instruction/account indices are translated into the Hook Execute namespace.
    match meta.discriminator {
        0 => Ok(()),
        1 => {
            let seeds = Seed::unpack_address_config(&meta.address_config)
                .map_err(|_| ProgramError::InvalidArgument)?;
            let mut compiled = Vec::with_capacity(seeds.len() + 1);
            for seed in seeds {
                match seed {
                    Seed::InstructionData { index: 0, length } if length > 0 => {
                        compiled.push(Seed::Literal {
                            bytes: vec![SecurityTokenInstruction::Transfer.discriminant()],
                        });
                        if length > 1 {
                            compiled.push(Seed::InstructionData {
                                index: TRANSFER_HOOK_EXECUTE_DATA_OFFSET,
                                length: length - 1,
                            });
                        }
                    }
                    Seed::InstructionData { index, length } => {
                        compiled.push(Seed::InstructionData {
                            index: if length == 0 {
                                TRANSFER_HOOK_EXECUTE_DATA_OFFSET
                            } else {
                                index
                                    .checked_add(TRANSFER_HOOK_EXECUTE_DATA_OFFSET - 1)
                                    .ok_or(ProgramError::InvalidArgument)?
                            },
                            length,
                        });
                    }
                    seed => compiled.push(seed),
                }
            }
            Seed::pack_into_address_config(&compiled).map_err(|_| ProgramError::InvalidArgument)?;
            Ok(())
        }
        2 => match PubkeyData::unpack(&meta.address_config)
            .map_err(|_| ProgramError::InvalidArgument)?
        {
            PubkeyData::AccountData { .. } => Ok(()),
            PubkeyData::InstructionData { .. } | PubkeyData::Uninitialized => {
                Err(ProgramError::InvalidArgument)
            }
        },
        _ => Err(ProgramError::InvalidArgument),
    }
}

pub fn validate_programs(
    instruction_discriminator: u8,
    programs: &[VerificationProgramConfig],
) -> ProgramResult {
    // Validate program count doesn't exceed maximum
    if programs.is_empty() || programs.len() > MAX_VERIFICATION_PROGRAMS {
        return Err(ProgramError::InvalidArgument);
    }

    let base_count = canonical_base_count(instruction_discriminator)?;
    let instruction_data_len = fixed_instruction_data_len(instruction_discriminator);
    let mut total_extras = 0usize;
    // Statically known duplicate keys must carry one logical role across all entries.
    // Dynamic duplicates receive the equivalent check during runtime resolution.
    let mut fixed_privileges = Vec::<(Pubkey, bool, bool)>::new();
    for program in programs {
        // Validate program address and extra account declarations
        if program.program_id == Pubkey::default()
            || program.extra_accounts.len() > MAX_VERIFICATION_EXTRAS_PER_PROGRAM
        {
            return Err(ProgramError::InvalidArgument);
        }
        for (index, meta) in program.extra_accounts.iter().enumerate() {
            validate_meta(meta, base_count + index, instruction_data_len)?;
            if instruction_discriminator == SecurityTokenInstruction::Transfer.discriminant() {
                validate_transfer_meta_compilation(meta)?;
            }
            if meta.discriminator == 0 {
                let key = Pubkey::from(meta.address_config);
                if let Some((_, is_signer, is_writable)) =
                    fixed_privileges.iter().find(|(fixed, _, _)| fixed == &key)
                {
                    if (*is_signer, *is_writable) != (meta.is_signer, meta.is_writable) {
                        return Err(ProgramError::InvalidArgument);
                    }
                } else {
                    fixed_privileges.push((key, meta.is_signer, meta.is_writable));
                }
            }
        }
        total_extras = total_extras
            .checked_add(program.extra_accounts.len())
            .ok_or(ProgramError::InvalidArgument)?;
        if total_extras > MAX_TOTAL_VERIFICATION_EXTRAS {
            return Err(ProgramError::InvalidArgument);
        }
    }
    Ok(())
}

impl InitializeVerificationConfigArgs {
    /// Minimum size: instruction_discriminator (1) + cpi_mode (1) + vector length (4) = 6 bytes
    pub const MIN_LEN: usize = 6;

    /// Create new InitializeVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        cpi_mode: bool,
        programs: &[VerificationProgramConfig],
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            programs: programs.to_vec(),
        })
    }

    /// Serialize to bytes using manual serialization (following SAS pattern)
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Write instruction discriminator (1 byte)
        data.push(self.instruction_discriminator);
        // Write cpi_mode (1 byte)
        data.push(self.cpi_mode as u8);

        // Write programs and their extra account declarations
        serialize_programs(&self.programs, &mut data);

        data
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read instruction discriminator (1 byte)
        let instruction_discriminator = data[offset];
        offset += 1;

        // Read cpi_mode (1 byte)
        let cpi_mode = read_bool(data, &mut offset)?;

        // Read programs and their extra account declarations
        let programs = parse_programs(data, &mut offset)?;
        if offset != data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            programs,
        })
    }

    pub fn validate(&self) -> ProgramResult {
        validate_programs(self.instruction_discriminator, &self.programs)
    }

    /// Get program count
    pub fn program_count(&self) -> u8 {
        self.programs.len() as u8
    }

    /// Get programs and their extra account declarations as a slice
    pub fn programs(&self) -> &[VerificationProgramConfig] {
        &self.programs
    }

    /// Get specific program address by index
    pub fn get_program_address(&self, index: usize) -> Option<Pubkey> {
        self.programs.get(index).map(|program| program.program_id)
    }
}

impl UpdateVerificationConfigArgs {
    /// Minimum size: instruction_discriminator (1) + cpi_mode (1) + offset (1) + vector length (4) = 7 bytes
    pub const MIN_LEN: usize = 7;

    /// Create new UpdateVerificationConfigArgs
    pub fn new(
        instruction_discriminator: u8,
        cpi_mode: bool,
        programs: &[VerificationProgramConfig],
        offset: u8,
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            programs: programs.to_vec(),
            offset,
        })
    }

    /// Serialize to bytes using manual serialization (following SAS pattern)
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Write instruction discriminator (1 byte)
        data.push(self.instruction_discriminator);

        // Write cpi_mode (1 byte)
        data.push(self.cpi_mode as u8);

        // Write offset (1 byte)
        data.push(self.offset);

        // Write programs and their extra account declarations
        serialize_programs(&self.programs, &mut data);

        data
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset_pos = 0;

        // Read instruction discriminator (1 byte)
        let instruction_discriminator = data[offset_pos];
        offset_pos += 1;

        // Read cpi_mode (1 byte)
        let cpi_mode = read_bool(data, &mut offset_pos)?;

        // Read offset (1 byte)
        let offset = data[offset_pos];
        offset_pos += 1;

        // Read programs and their extra account declarations
        let programs = parse_programs(data, &mut offset_pos)?;
        if offset_pos != data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self {
            instruction_discriminator,
            cpi_mode,
            offset,
            programs,
        })
    }

    pub fn validate(&self) -> ProgramResult {
        // Validate offset is within bounds (0-based index, so offset < MAX)
        if self.offset >= MAX_VERIFICATION_PROGRAMS as u8 {
            return Err(ProgramError::InvalidArgument);
        }

        // Validate that offset + program count doesn't exceed maximum
        let total_programs = self.offset as usize + self.programs.len();
        if total_programs > MAX_VERIFICATION_PROGRAMS {
            return Err(ProgramError::InvalidArgument);
        }
        if self.programs.is_empty() {
            return Ok(());
        }
        validate_programs(self.instruction_discriminator, &self.programs)
    }

    /// Get programs as slice with their extra account declarations
    pub fn programs(&self) -> &[VerificationProgramConfig] {
        &self.programs
    }

    /// Get offset
    pub fn offset(&self) -> u8 {
        self.offset
    }
}

/// Arguments for TrimVerificationConfig instruction
#[derive(ShankType)]
#[repr(C)]
pub struct TrimVerificationConfigArgs {
    /// 1-byte instruction discriminator (e.g., MINT_TOKENS, BURN_TOKENS, etc.)
    pub instruction_discriminator: u8,
    /// New size of the program array (number of Pubkeys to keep)
    pub size: u8,
    /// Whether to close the account completely
    pub close: bool,
}

impl TrimVerificationConfigArgs {
    /// Fixed size: instruction_discriminator (1) + size (1) + close (1) = 3 bytes
    pub const LEN: usize = 3;

    /// Creates a new `TrimVerificationConfigArgs` instance.
    ///
    /// # Arguments
    ///
    /// * `instruction_discriminator` - 1-byte instruction discriminator.
    /// * `size` - New size of the program array (number of Pubkeys to keep).
    /// * `close` - Whether to close the account completely.
    pub fn new(instruction_discriminator: u8, size: u8, close: bool) -> Result<Self, ProgramError> {
        Ok(Self {
            instruction_discriminator,
            size,
            close,
        })
    }

    /// Serialize to bytes using manual serialization (following SAS pattern)
    pub fn to_bytes_inner(&self) -> Vec<u8> {
        vec![self.instruction_discriminator, self.size, self.close as u8]
    }

    /// Deserialize from bytes using manual deserialization (following SAS pattern)
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 0;

        // Read instruction_discriminator (1 byte)
        let instruction_discriminator = data[offset];
        offset += 1;

        // Read size (1 byte)
        let size = data[offset];
        offset += 1;

        // Read close (1 byte)
        let close = read_bool(data, &mut offset)?;

        Ok(Self {
            instruction_discriminator,
            size,
            close,
        })
    }
}

type ProgramResult = Result<(), ProgramError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::random_pubkey;
    use rstest::rstest;
    use spl_tlv_account_resolution::{
        account::ExtraAccountMeta, pubkey_data::PubkeyData, seeds::Seed,
    };

    fn fixed(key: Pubkey) -> VerificationAccountMeta {
        VerificationAccountMeta {
            discriminator: 0,
            address_config: key,
            is_signer: false,
            is_writable: true,
        }
    }

    fn program(
        program_id: Pubkey,
        extras: Vec<VerificationAccountMeta>,
    ) -> VerificationProgramConfig {
        VerificationProgramConfig {
            program_id,
            extra_accounts: extras,
        }
    }

    #[test]
    fn test_initialize_verification_config_args_to_bytes_inner_try_from_bytes() {
        let program1 = random_pubkey();
        let program2 = random_pubkey();
        let programs = vec![
            program(program1, vec![fixed(random_pubkey())]),
            program(program2, vec![]),
        ];
        let original = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::UpdateMetadata.discriminant(),
            false,
            &programs,
        )
        .unwrap();

        let inner_bytes = original.to_bytes_inner();
        let deserialized = InitializeVerificationConfigArgs::try_from_bytes(&inner_bytes).unwrap();

        assert_eq!(
            original.instruction_discriminator,
            deserialized.instruction_discriminator
        );
        assert_eq!(original.cpi_mode, deserialized.cpi_mode);
        assert_eq!(original.programs(), deserialized.programs());
        assert_eq!(programs, deserialized.programs());
    }

    #[test]
    fn verification_config_args_reject_noncanonical_bools_and_trailing_bytes() {
        let programs = vec![program(random_pubkey(), vec![])];

        let initialize = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            true,
            &programs,
        )
        .unwrap();
        let mut invalid_bool = initialize.to_bytes_inner();
        invalid_bool[1] = 2;
        assert!(InitializeVerificationConfigArgs::try_from_bytes(&invalid_bool).is_err());
        let mut trailing = initialize.to_bytes_inner();
        trailing.push(0);
        assert!(InitializeVerificationConfigArgs::try_from_bytes(&trailing).is_err());

        let update = UpdateVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            true,
            &programs,
            0,
        )
        .unwrap();
        let mut invalid_bool = update.to_bytes_inner();
        invalid_bool[1] = 2;
        assert!(UpdateVerificationConfigArgs::try_from_bytes(&invalid_bool).is_err());
        let mut trailing = update.to_bytes_inner();
        trailing.push(0);
        assert!(UpdateVerificationConfigArgs::try_from_bytes(&trailing).is_err());

        let trim =
            TrimVerificationConfigArgs::new(SecurityTokenInstruction::Mint.discriminant(), 1, true)
                .unwrap();
        let mut invalid_bool = trim.to_bytes_inner();
        invalid_bool[2] = 2;
        assert!(TrimVerificationConfigArgs::try_from_bytes(&invalid_bool).is_err());
        let mut trailing = trim.to_bytes_inner();
        trailing.push(0);
        assert!(TrimVerificationConfigArgs::try_from_bytes(&trailing).is_err());
    }

    #[rstest]
    #[case(10, true)]
    #[case(9, true)]
    #[case(11, false)]
    fn test_initialize_verification_config_programs_limit(
        #[case] num_programs: usize,
        #[case] should_succeed: bool,
    ) {
        let programs: Vec<VerificationProgramConfig> = (0..num_programs)
            .map(|_| program(random_pubkey(), vec![]))
            .collect();
        let args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            false,
            &programs,
        )
        .unwrap();

        let result = args.validate();

        if should_succeed {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case(11, 10, false)]
    #[case(10, 1, false)]
    #[case(9, 1, true)]
    #[case(8, 2, true)]
    #[case(9, 2, false)]
    fn test_update_verification_config_programs_limit(
        #[case] offset: u8,
        #[case] num_programs: usize,
        #[case] should_succeed: bool,
    ) {
        let programs: Vec<VerificationProgramConfig> = (0..num_programs)
            .map(|_| program(random_pubkey(), vec![]))
            .collect();

        let args = UpdateVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            false,
            &programs,
            offset,
        )
        .unwrap();

        let result = args.validate();

        if should_succeed {
            assert!(
                result.is_ok(),
                "Expected success for offset={} with {} programs",
                offset,
                num_programs
            );
        } else {
            assert!(
                result.is_err(),
                "Expected failure for offset={} with {} programs",
                offset,
                num_programs
            );
        }
    }

    #[test]
    fn test_initialize_verification_config_rejects_default_pubkey() {
        let programs = vec![
            program(random_pubkey(), vec![]),
            program(Pubkey::default(), vec![]),
            program(random_pubkey(), vec![]),
        ];

        let args = InitializeVerificationConfigArgs::new(
            SecurityTokenInstruction::Mint.discriminant(),
            false,
            &programs,
        )
        .unwrap();

        let result = args.validate();

        assert!(matches!(result, Err(ProgramError::InvalidArgument)));
    }

    #[test]
    fn test_update_verification_config_rejects_default_pubkey() {
        let programs = vec![
            program(random_pubkey(), vec![]),
            program(Pubkey::default(), vec![]),
        ];

        let args = UpdateVerificationConfigArgs::new(
            SecurityTokenInstruction::Transfer.discriminant(),
            false,
            &programs,
            0,
        )
        .unwrap();

        let result = args.validate();

        assert!(matches!(result, Err(ProgramError::InvalidArgument)));
    }

    #[test]
    fn validates_pda_references_and_signer_rule() {
        let spl_meta =
            ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 3 }], false, false)
                .unwrap();
        let valid = VerificationAccountMeta {
            discriminator: spl_meta.discriminator,
            address_config: spl_meta.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(validate_programs(
            SecurityTokenInstruction::Mint.discriminant(),
            &[program(random_pubkey(), vec![valid.clone()])]
        )
        .is_ok());

        let signer = VerificationAccountMeta {
            is_signer: true,
            ..valid
        };
        assert!(validate_programs(
            SecurityTokenInstruction::Mint.discriminant(),
            &[program(random_pubkey(), vec![signer])]
        )
        .is_err());
    }

    #[test]
    fn transfer_accepts_compilable_extras() {
        assert!(validate_programs(
            SecurityTokenInstruction::Transfer.discriminant(),
            &[program(random_pubkey(), vec![fixed(random_pubkey())])]
        )
        .is_ok());

        let signer = VerificationAccountMeta {
            is_signer: true,
            ..fixed(random_pubkey())
        };
        assert!(validate_programs(
            SecurityTokenInstruction::Transfer.discriminant(),
            &[program(random_pubkey(), vec![signer])]
        )
        .is_ok());
    }

    #[test]
    fn rejects_conflicting_fixed_privileges() {
        let key = random_pubkey();
        let readonly = VerificationAccountMeta {
            is_writable: false,
            ..fixed(key)
        };
        let writable = fixed(key);
        assert!(validate_programs(
            SecurityTokenInstruction::Mint.discriminant(),
            &[
                program(random_pubkey(), vec![readonly]),
                program(random_pubkey(), vec![writable]),
            ]
        )
        .is_err());
    }

    #[test]
    fn rejects_oversized_pda_seed_and_uncompilable_transfer_layout() {
        let oversized = ExtraAccountMeta::new_with_seeds(
            &[Seed::AccountData {
                account_index: 0,
                data_index: 0,
                length: 33,
            }],
            false,
            false,
        )
        .unwrap();
        let oversized = VerificationAccountMeta {
            discriminator: oversized.discriminator,
            address_config: oversized.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(validate_programs(
            SecurityTokenInstruction::Transfer.discriminant(),
            &[program(random_pubkey(), vec![oversized])]
        )
        .is_err());

        let mut seeds = vec![Seed::AccountKey { index: 0 }; 14];
        seeds.push(Seed::InstructionData {
            index: 0,
            length: 9,
        });
        let unpackable_after_translation =
            ExtraAccountMeta::new_with_seeds(&seeds, false, false).unwrap();
        let unpackable_after_translation = VerificationAccountMeta {
            discriminator: unpackable_after_translation.discriminator,
            address_config: unpackable_after_translation.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(validate_programs(
            SecurityTokenInstruction::Transfer.discriminant(),
            &[program(random_pubkey(), vec![unpackable_after_translation])]
        )
        .is_err());
    }

    #[test]
    fn validates_pubkey_data_ranges_and_forward_references() {
        let at_token_account = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::InstructionData { index: 9 },
            false,
            false,
        )
        .unwrap();
        let valid = VerificationAccountMeta {
            discriminator: at_token_account.discriminator,
            address_config: at_token_account.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(validate_programs(
            SecurityTokenInstruction::CloseActionReceiptAccount.discriminant(),
            &[program(random_pubkey(), vec![valid])]
        )
        .is_ok());

        let transfer_instruction_data = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::InstructionData { index: 0 },
            false,
            false,
        )
        .unwrap();
        assert!(validate_programs(
            SecurityTokenInstruction::Transfer.discriminant(),
            &[program(
                random_pubkey(),
                vec![VerificationAccountMeta {
                    discriminator: transfer_instruction_data.discriminator,
                    address_config: transfer_instruction_data.address_config,
                    is_signer: false,
                    is_writable: false,
                }],
            )]
        )
        .is_err());

        let out_of_range = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::InstructionData { index: 10 },
            false,
            false,
        )
        .unwrap();
        let invalid_range = VerificationAccountMeta {
            discriminator: out_of_range.discriminator,
            address_config: out_of_range.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(validate_programs(
            SecurityTokenInstruction::CloseActionReceiptAccount.discriminant(),
            &[program(random_pubkey(), vec![invalid_range])]
        )
        .is_err());

        let forward = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::AccountData {
                account_index: 4,
                data_index: 0,
            },
            false,
            false,
        )
        .unwrap();
        let invalid_forward = VerificationAccountMeta {
            discriminator: forward.discriminator,
            address_config: forward.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(validate_programs(
            SecurityTokenInstruction::Mint.discriminant(),
            &[program(random_pubkey(), vec![invalid_forward])]
        )
        .is_err());
    }
}

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{create_program_address, find_program_address, Pubkey},
    ProgramResult,
};
use solana_pubkey::Pubkey as SolanaPubkey;
use spl_tlv_account_resolution::{
    pubkey_data::PubkeyData, seeds::Seed as ResolutionSeed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::{
    get_extra_account_metas_address_and_bump_seed, instruction::ExecuteInstruction,
};
use spl_type_length_value::state::TlvStateBorrowed;
use std::collections::HashMap;

use super::{
    helpers::{read_bool, read_u32},
    SECURITY_TOKEN_PROGRAM_ID, TRANSFER_DISCRIMINATOR, VERIFIER_INSTRUCTION_DATA_LEN,
};

// VerificationConfig PDA seeds.
const VERIFICATION_CONFIG_SEED: &[u8] = b"verification_config";

// Security Token config discriminator.
const TRANSFER_VERIFICATION_CONFIG_DISCRIMINATOR: u8 = 1;

// Verification config limits.
const MAX_VERIFICATION_PROGRAMS: usize = 10;
const MAX_VERIFICATION_EXTRAS_PER_PROGRAM: usize = 8;
const MAX_TOTAL_VERIFICATION_EXTRAS: usize = 32;
const MAX_PDA_SEED_LEN: usize = 32;

// Verification program interface.
const VERIFIER_BASE_ACCOUNT_COUNT: usize = 4;

/// A wire-compatible dynamic account declaration.
#[derive(Clone, Copy)]
struct VerificationAccountMeta {
    discriminator: u8,
    address_config: [u8; 32],
    is_signer: bool,
    is_writable: bool,
}

/// A verifier program and its private dynamic account declarations.
struct VerificationProgramConfig {
    program_id: Pubkey,
    extra_accounts: Vec<VerificationAccountMeta>,
}

/// Runtime accounts routed to one verifier program.
struct RoutingGroup<'a> {
    program: &'a AccountInfo,
    extras: &'a [AccountInfo],
}

/// Validates routing state and invokes every configured Transfer verifier.
pub(super) fn verify_transfer<'a>(
    program_id: &Pubkey,
    mint: &AccountInfo,
    meta_list: &AccountInfo,
    verification_config: &AccountInfo,
    routing_accounts: &'a [AccountInfo],
    canonical_accounts: &[&'a AccountInfo; VERIFIER_BASE_ACCOUNT_COUNT],
    instruction_data: &[u8; VERIFIER_INSTRUCTION_DATA_LEN],
) -> ProgramResult {
    let verification_programs = load_verification_programs(mint, verification_config)?;
    let expected_meta_count = verification_programs
        .iter()
        .try_fold(1usize, |count, entry| {
            count
                .checked_add(1)
                .and_then(|count| count.checked_add(entry.extra_accounts.len()))
        })
        .ok_or(ProgramError::InvalidAccountData)?;
    validate_meta_list(program_id, mint, meta_list, expected_meta_count)?;

    let routing_groups = parse_and_validate_routing(
        &verification_programs,
        canonical_accounts,
        routing_accounts,
        instruction_data,
    )?;
    execute_verification_programs(
        &verification_programs,
        &routing_groups,
        canonical_accounts,
        instruction_data,
    )
}

/// Loads and validates a Transfer VerificationConfig account.
fn load_verification_programs(
    mint: &AccountInfo,
    verification_config: &AccountInfo,
) -> Result<Vec<VerificationProgramConfig>, ProgramError> {
    if verification_config.data_is_empty() {
        return Err(ProgramError::UninitializedAccount);
    }

    if !verification_config.is_owned_by(&SECURITY_TOKEN_PROGRAM_ID) {
        return Err(ProgramError::IllegalOwner);
    }

    let config_data = verification_config.try_borrow_data()?;

    let config_discriminator = config_data
        .first()
        .ok_or(ProgramError::InvalidAccountData)?;
    if *config_discriminator != TRANSFER_VERIFICATION_CONFIG_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    let operation_discriminator = config_data.get(1).ok_or(ProgramError::InvalidAccountData)?;
    if *operation_discriminator != TRANSFER_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    // Layout: [0] discriminator, [1] instruction_discriminator, [2] cpi_mode, [3] bump, [4-7] count, [8..] programs
    if config_data.len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }
    let bump = config_data[3];

    // Bind this SSTS-owned account to the Transfer config PDA encoded by its stored bump.
    let discriminator_seed = [TRANSFER_DISCRIMINATOR];
    let bump_seed = [bump];
    let config_seeds = &[
        VERIFICATION_CONFIG_SEED,
        mint.key().as_ref(),
        discriminator_seed.as_ref(),
        bump_seed.as_ref(),
    ];
    let verification_config_pda = create_program_address(config_seeds, &SECURITY_TOKEN_PROGRAM_ID)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if verification_config.key() != &verification_config_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    parse_verification_programs(&config_data)
}

/// Validates one dynamic account declaration against its local namespace.
fn validate_verification_meta(
    meta: &VerificationAccountMeta,
    available_accounts: usize,
) -> ProgramResult {
    match meta.discriminator {
        0 => Ok(()),
        // ResolutionSeed-based PDA.
        1 => {
            if meta.is_signer {
                return Err(ProgramError::InvalidAccountData);
            }
            let seeds = ResolutionSeed::unpack_address_config(&meta.address_config)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            if ResolutionSeed::pack_into_address_config(&seeds)
                .map_err(|_| ProgramError::InvalidAccountData)?
                != meta.address_config
            {
                return Err(ProgramError::InvalidAccountData);
            }
            for seed in seeds {
                match seed {
                    ResolutionSeed::AccountKey { index }
                        if index as usize >= available_accounts =>
                    {
                        return Err(ProgramError::InvalidAccountData)
                    }
                    ResolutionSeed::AccountData {
                        account_index,
                        length,
                        ..
                    } if account_index as usize >= available_accounts
                        || length as usize > MAX_PDA_SEED_LEN =>
                    {
                        return Err(ProgramError::InvalidAccountData)
                    }
                    ResolutionSeed::InstructionData { index, length } => {
                        let end = (index as usize)
                            .checked_add(length as usize)
                            .ok_or(ProgramError::InvalidAccountData)?;
                        if length as usize > MAX_PDA_SEED_LEN || end > VERIFIER_INSTRUCTION_DATA_LEN
                        {
                            return Err(ProgramError::InvalidAccountData);
                        }
                    }
                    ResolutionSeed::Uninitialized => return Err(ProgramError::InvalidAccountData),
                    _ => {}
                }
            }
            Ok(())
        }
        // PubkeyData-based PDA.
        2 => {
            let pubkey_data = PubkeyData::unpack(&meta.address_config)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            if PubkeyData::pack_into_address_config(&pubkey_data)
                .map_err(|_| ProgramError::InvalidAccountData)?
                != meta.address_config
            {
                return Err(ProgramError::InvalidAccountData);
            }
            match pubkey_data {
                PubkeyData::AccountData { account_index, .. }
                    if account_index as usize >= available_accounts =>
                {
                    Err(ProgramError::InvalidAccountData)
                }
                PubkeyData::InstructionData { index } => {
                    let end = (index as usize)
                        .checked_add(32)
                        .ok_or(ProgramError::InvalidAccountData)?;
                    if end > VERIFIER_INSTRUCTION_DATA_LEN {
                        Err(ProgramError::InvalidAccountData)
                    } else {
                        Ok(())
                    }
                }
                PubkeyData::Uninitialized => Err(ProgramError::InvalidAccountData),
                _ => Ok(()),
            }
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}

/// Parses all verifier entries from serialized VerificationConfig data.
fn parse_verification_programs(
    config_data: &[u8],
) -> Result<Vec<VerificationProgramConfig>, ProgramError> {
    // The Hook cannot depend on Core's Rust state types, so it decodes the shared wire format
    // locally with the same caps and exact-consumption rule. There is no legacy flat fallback.
    if config_data.len() < 8 || !matches!(config_data[2], 0 | 1) {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut offset = 4usize;
    let verification_programs_count = read_u32(config_data, &mut offset)?;
    if verification_programs_count == 0 || verification_programs_count > MAX_VERIFICATION_PROGRAMS {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut verification_programs = Vec::with_capacity(verification_programs_count);
    let mut total_extras = 0usize;
    for _ in 0..verification_programs_count {
        let program_end = offset
            .checked_add(32)
            .ok_or(ProgramError::InvalidAccountData)?;
        let program_id: Pubkey = config_data
            .get(offset..program_end)
            .ok_or(ProgramError::InvalidAccountData)?
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        if program_id == Pubkey::default() {
            return Err(ProgramError::InvalidAccountData);
        }
        offset = program_end;
        let extra_count = read_u32(config_data, &mut offset)?;
        if extra_count > MAX_VERIFICATION_EXTRAS_PER_PROGRAM {
            return Err(ProgramError::InvalidAccountData);
        }
        total_extras = total_extras
            .checked_add(extra_count)
            .ok_or(ProgramError::InvalidAccountData)?;
        if total_extras > MAX_TOTAL_VERIFICATION_EXTRAS {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut extra_accounts = Vec::with_capacity(extra_count);
        for index in 0..extra_count {
            let discriminator = *config_data
                .get(offset)
                .ok_or(ProgramError::InvalidAccountData)?;
            offset = offset
                .checked_add(1)
                .ok_or(ProgramError::InvalidAccountData)?;
            let address_end = offset
                .checked_add(32)
                .ok_or(ProgramError::InvalidAccountData)?;
            let address_config = config_data
                .get(offset..address_end)
                .ok_or(ProgramError::InvalidAccountData)?
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?;
            offset = address_end;
            let meta = VerificationAccountMeta {
                discriminator,
                address_config,
                is_signer: read_bool(config_data, &mut offset)?,
                is_writable: read_bool(config_data, &mut offset)?,
            };
            validate_verification_meta(&meta, VERIFIER_BASE_ACCOUNT_COUNT + index)?;
            extra_accounts.push(meta);
        }
        verification_programs.push(VerificationProgramConfig {
            program_id,
            extra_accounts,
        });
    }
    if offset != config_data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(verification_programs)
}

/// Validates the Hook discovery account against the authoritative config size.
fn validate_meta_list(
    program_id: &Pubkey,
    mint: &AccountInfo,
    meta_list: &AccountInfo,
    expected_meta_count: usize,
) -> ProgramResult {
    // VerificationConfig is authoritative at runtime. The meta list is discovery state, so
    // identity, TLV validity, and entry count are checked here; keys and privileges are resolved
    // independently from the config below instead of duplicating the full compiler in the Hook.
    if !meta_list.is_owned_by(program_id) || meta_list.data_is_empty() {
        return Err(ProgramError::InvalidAccountData);
    }
    let (expected_pda, _) = get_extra_account_metas_address_and_bump_seed(
        &SolanaPubkey::new_from_array(*mint.key()),
        &SolanaPubkey::new_from_array(*program_id),
    );
    if meta_list.key() != &expected_pda.to_bytes() {
        return Err(ProgramError::InvalidSeeds);
    }

    let data = meta_list.try_borrow_data()?;
    let state = TlvStateBorrowed::unpack(&data).map_err(|_| ProgramError::InvalidAccountData)?;
    let metas = ExtraAccountMetaList::unpack_with_tlv_state::<ExecuteInstruction>(&state)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if metas.data().len() != expected_meta_count {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// Resolves one configured dynamic account against local runtime inputs.
fn resolve_verification_meta(
    meta: &VerificationAccountMeta,
    verifier_program_id: &Pubkey,
    local_accounts: &[&AccountInfo],
    instruction_data: &[u8],
) -> Result<Pubkey, ProgramError> {
    // local_accounts grows after every resolved extra, allowing references to canonical
    // accounts and earlier own extras while making forward and cross-entry references impossible.
    match meta.discriminator {
        0 => Ok(meta.address_config),
        1 => {
            let seeds = ResolutionSeed::unpack_address_config(&meta.address_config)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            let mut owned_seeds = Vec::with_capacity(seeds.len());
            for seed in seeds {
                let bytes = match seed {
                    ResolutionSeed::Uninitialized => return Err(ProgramError::InvalidAccountData),
                    ResolutionSeed::Literal { bytes } => bytes,
                    ResolutionSeed::InstructionData { index, length } => {
                        let start = index as usize;
                        let end = start
                            .checked_add(length as usize)
                            .ok_or(ProgramError::InvalidInstructionData)?;
                        instruction_data
                            .get(start..end)
                            .ok_or(ProgramError::InvalidInstructionData)?
                            .to_vec()
                    }
                    ResolutionSeed::AccountKey { index } => local_accounts
                        .get(index as usize)
                        .ok_or(ProgramError::NotEnoughAccountKeys)?
                        .key()
                        .to_vec(),
                    ResolutionSeed::AccountData {
                        account_index,
                        data_index,
                        length,
                    } => {
                        let account = local_accounts
                            .get(account_index as usize)
                            .ok_or(ProgramError::NotEnoughAccountKeys)?;
                        let data = account.try_borrow_data()?;
                        let start = data_index as usize;
                        let end = start
                            .checked_add(length as usize)
                            .ok_or(ProgramError::InvalidAccountData)?;
                        data.get(start..end)
                            .ok_or(ProgramError::InvalidAccountData)?
                            .to_vec()
                    }
                };
                owned_seeds.push(bytes);
            }
            let seed_refs: Vec<&[u8]> = owned_seeds.iter().map(Vec::as_slice).collect();
            Ok(find_program_address(&seed_refs, verifier_program_id).0)
        }
        2 => match PubkeyData::unpack(&meta.address_config)
            .map_err(|_| ProgramError::InvalidAccountData)?
        {
            PubkeyData::Uninitialized => Err(ProgramError::InvalidAccountData),
            PubkeyData::InstructionData { index } => {
                let start = index as usize;
                let end = start
                    .checked_add(32)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                instruction_data
                    .get(start..end)
                    .ok_or(ProgramError::InvalidInstructionData)?
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)
            }
            PubkeyData::AccountData {
                account_index,
                data_index,
            } => {
                let account = local_accounts
                    .get(account_index as usize)
                    .ok_or(ProgramError::NotEnoughAccountKeys)?;
                let data = account.try_borrow_data()?;
                let start = data_index as usize;
                let end = start
                    .checked_add(32)
                    .ok_or(ProgramError::InvalidAccountData)?;
                data.get(start..end)
                    .ok_or(ProgramError::InvalidAccountData)?
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)
            }
        },
        _ => Err(ProgramError::InvalidAccountData),
    }
}

/// Splits and validates the runtime routing tail into verifier groups.
fn parse_and_validate_routing<'a>(
    programs: &[VerificationProgramConfig],
    canonical_accounts: &[&'a AccountInfo; VERIFIER_BASE_ACCOUNT_COUNT],
    routing_accounts: &'a [AccountInfo],
    instruction_data: &[u8],
) -> Result<Vec<RoutingGroup<'a>>, ProgramError> {
    // Group boundaries come only from config counts. The routing tail must be consumed exactly;
    // searching by key would be ambiguous when program IDs or resolved extras repeat.
    validate_routing_account_count(programs, routing_accounts.len())?;

    let mut cursor = 0usize;
    let mut groups = Vec::with_capacity(programs.len());
    // SPL invokes the Hook with its four canonical accounts de-escalated to read-only.
    let canonical_flags = [(false, false); VERIFIER_BASE_ACCOUNT_COUNT];
    let mut canonical_privileges = HashMap::<Pubkey, (bool, bool)>::new();
    for (account, flags) in canonical_accounts.iter().zip(canonical_flags) {
        canonical_privileges
            .entry(*account.key())
            .and_modify(|existing| {
                existing.0 |= flags.0;
                existing.1 |= flags.1;
            })
            .or_insert(flags);
    }
    // Compatible duplicate keys are valid, but conflicting logical roles would be observed
    // differently by the transaction, Hook CPI, and Core paths and therefore fail closed.
    let mut resolved_extra_privileges = HashMap::<Pubkey, (bool, bool)>::new();
    for entry in programs {
        let program = routing_accounts
            .get(cursor)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        if program.key() != &entry.program_id || !program.executable() {
            return Err(ProgramError::IncorrectProgramId);
        }
        cursor += 1;
        let extras_end = cursor
            .checked_add(entry.extra_accounts.len())
            .ok_or(ProgramError::InvalidAccountData)?;
        let extras = routing_accounts
            .get(cursor..extras_end)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;

        let mut local_accounts = canonical_accounts.to_vec();
        for (declaration, account) in entry.extra_accounts.iter().zip(extras) {
            let expected = resolve_verification_meta(
                declaration,
                &entry.program_id,
                &local_accounts,
                instruction_data,
            )?;
            if account.key() != &expected
                || (declaration.is_signer && !account.is_signer())
                || (declaration.is_writable && !account.is_writable())
            {
                return Err(ProgramError::InvalidAccountData);
            }
            if let Some((canonical_signer, canonical_writable)) =
                canonical_privileges.get(&expected)
            {
                if (declaration.is_signer && !canonical_signer)
                    || (declaration.is_writable && !canonical_writable)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            if let Some(flags) = resolved_extra_privileges.get(&expected) {
                if *flags != (declaration.is_signer, declaration.is_writable) {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            resolved_extra_privileges
                .insert(expected, (declaration.is_signer, declaration.is_writable));
            local_accounts.push(account);
        }
        groups.push(RoutingGroup { program, extras });
        cursor = extras_end;
    }
    if cursor != routing_accounts.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(groups)
}

/// Requires the routing tail to contain exactly the configured accounts.
fn validate_routing_account_count(
    programs: &[VerificationProgramConfig],
    actual_count: usize,
) -> ProgramResult {
    let expected_count = programs.iter().try_fold(0usize, |count, entry| {
        count
            .checked_add(1)
            .and_then(|count| count.checked_add(entry.extra_accounts.len()))
    });
    if expected_count != Some(actual_count) {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    Ok(())
}

/// Invokes each verifier with canonical accounts and only its own extras.
fn execute_verification_programs(
    verification_programs: &[VerificationProgramConfig],
    routing_groups: &[RoutingGroup<'_>],
    canonical_accounts: &[&AccountInfo; VERIFIER_BASE_ACCOUNT_COUNT],
    instruction_data: &[u8; VERIFIER_INSTRUCTION_DATA_LEN],
) -> ProgramResult {
    // Build CPI metas explicitly from the canonical contract and each entry's declarations.
    // Copying outer AccountInfo privileges would leak transaction-wide privilege promotion.
    let base_flags = [(false, false); VERIFIER_BASE_ACCOUNT_COUNT];
    for (entry, group) in verification_programs.iter().zip(routing_groups) {
        let mut account_metas =
            Vec::with_capacity(VERIFIER_BASE_ACCOUNT_COUNT + group.extras.len());
        let mut account_refs = Vec::with_capacity(VERIFIER_BASE_ACCOUNT_COUNT + group.extras.len());
        for (account, (is_signer, is_writable)) in canonical_accounts.iter().zip(base_flags) {
            account_metas.push(pinocchio::instruction::AccountMeta {
                pubkey: account.key(),
                is_signer,
                is_writable,
            });
            account_refs.push(*account);
        }
        for (declaration, account) in entry.extra_accounts.iter().zip(group.extras) {
            account_metas.push(pinocchio::instruction::AccountMeta {
                pubkey: account.key(),
                is_signer: declaration.is_signer,
                is_writable: declaration.is_writable,
            });
            account_refs.push(account);
        }
        let verification_instruction = pinocchio::instruction::Instruction {
            program_id: group.program.key(),
            accounts: &account_metas,
            data: instruction_data,
        };
        pinocchio::program::slice_invoke(&verification_instruction, &account_refs)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spl_tlv_account_resolution::account::ExtraAccountMeta;

    fn nested_config(extras: &[VerificationAccountMeta]) -> Vec<u8> {
        let mut data = vec![
            TRANSFER_VERIFICATION_CONFIG_DISCRIMINATOR,
            TRANSFER_DISCRIMINATOR,
            0,
            255,
        ];
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[7; 32]);
        data.extend_from_slice(&(extras.len() as u32).to_le_bytes());
        for meta in extras {
            data.push(meta.discriminator);
            data.extend_from_slice(&meta.address_config);
            data.push(meta.is_signer as u8);
            data.push(meta.is_writable as u8);
        }
        data
    }

    #[test]
    fn parses_nested_zero_extra_config() {
        let programs = parse_verification_programs(&nested_config(&[])).unwrap();
        assert_eq!(programs.len(), 1);
        assert_eq!(programs[0].program_id, [7; 32]);
        assert!(programs[0].extra_accounts.is_empty());
    }

    #[test]
    fn parses_dynamic_config_and_rejects_trailing_bytes() {
        let fixed = VerificationAccountMeta {
            discriminator: 0,
            address_config: [9; 32],
            is_signer: false,
            is_writable: true,
        };
        let programs = parse_verification_programs(&nested_config(&[fixed])).unwrap();
        assert_eq!(programs[0].extra_accounts.len(), 1);
        assert_eq!(programs[0].extra_accounts[0].address_config, [9; 32]);
        assert!(programs[0].extra_accounts[0].is_writable);

        let mut trailing = nested_config(&[]);
        trailing.push(0);
        assert!(parse_verification_programs(&trailing).is_err());
    }

    #[test]
    fn rejects_forward_references_and_signer_pdas() {
        let forward = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::AccountData {
                account_index: VERIFIER_BASE_ACCOUNT_COUNT as u8,
                data_index: 0,
            },
            false,
            false,
        )
        .unwrap();
        let forward = VerificationAccountMeta {
            discriminator: forward.discriminator,
            address_config: forward.address_config,
            is_signer: false,
            is_writable: false,
        };
        assert!(parse_verification_programs(&nested_config(&[forward])).is_err());

        let pda = ExtraAccountMeta::new_with_seeds(
            &[ResolutionSeed::AccountKey { index: 1 }],
            true,
            false,
        )
        .unwrap();
        let signer_pda = VerificationAccountMeta {
            discriminator: pda.discriminator,
            address_config: pda.address_config,
            is_signer: true,
            is_writable: false,
        };
        assert!(parse_verification_programs(&nested_config(&[signer_pda])).is_err());
    }

    #[test]
    fn rejects_missing_and_trailing_routing_accounts() {
        let programs = parse_verification_programs(&nested_config(&[])).unwrap();
        assert!(validate_routing_account_count(&programs, 0).is_err());
        assert!(validate_routing_account_count(&programs, 1).is_ok());
        assert!(validate_routing_account_count(&programs, 2).is_err());
    }
}

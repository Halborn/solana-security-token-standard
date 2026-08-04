//! Verification Module
//!
//! Handles authorization checks, compliance verification, and instruction validation
//! according to the Security Token specification.

use crate::token22_extensions::default_account_state::{
    AccountState, InitializeDefaultAccountState,
    UpdateDefaultAccountState as UpdateDefaultAccountStateCpi,
};
use crate::token22_extensions::metadata::{Field, UpdateField};
use crate::token22_extensions::pausable::InitializePausable;
use crate::token22_extensions::permanent_delegate::InitializePermanentDelegate;
use crate::token22_extensions::scaled_ui_amount::InitializeScaledUiAmount;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use pinocchio::sysvars::Sysvar;
use pinocchio::sysvars::{instructions::Instructions, rent::Rent};
use pinocchio::ProgramResult;
use pinocchio_system::instructions::{CreateAccount, Transfer};
use pinocchio_token_2022::instructions::{AuthorityType, InitializeMint2, SetAuthority};
use pinocchio_token_2022::state::Mint;
use spl_pod::primitives::PodBool;
use spl_tlv_account_resolution::pubkey_data::PubkeyData;
use spl_tlv_account_resolution::seeds::Seed as ResolutionSeed;
use spl_tlv_account_resolution::state::ExtraAccountMetaList;

use crate::constants::{seeds, INSTRUCTION_ACCOUNTS_OFFSET, TRANSFER_HOOK_PROGRAM_ID};
use crate::error::SecurityTokenError;
use crate::instruction::SecurityTokenInstruction;
use crate::instructions::verification_config::{
    canonical_base_count, core_account_count, TrimVerificationConfigArgs, VerificationAccountMeta,
    VerificationProgramConfig,
};
use crate::instructions::{
    InitializeMintArgs, UpdateDefaultAccountStateArgs, UpdateMetadataArgs, VerifyArgs,
};
use crate::modules::{
    verify_account_initialized, verify_account_not_initialized, verify_instructions_sysvar,
    verify_mint_keys_match, verify_owner, verify_pda_keys_match, verify_rent_sysvar, verify_signer,
    verify_system_program, verify_token22_program, verify_transfer_hook_program, verify_writable,
};
use crate::state::{
    AccountDeserialize, AccountSerialize, MintAuthority, SecurityTokenDiscriminators,
    VerificationConfig,
};
use crate::token22_extensions::metadata::{InitializeTokenMetadata, RemoveKey, TokenMetadata};
use crate::token22_extensions::metadata_pointer::{InitializeMetadataPointer, MetadataPointer};
use crate::token22_extensions::transfer_hook::{
    InitializeExtraAccountMetaList, InitializeTransferHook, UpdateExtraAccountMetaList,
};
use crate::token22_extensions::{
    get_extension_data_bytes_for_variable_pack, get_extension_from_bytes, ExtensionType,
};
use crate::utils;
use crate::utils::find_extra_account_metas_pda;
use spl_tlv_account_resolution::account::ExtraAccountMeta;
use std::collections::HashMap;

/// Verification Module - handles all authorization and compliance checks
pub struct VerificationModule;

struct RoutingGroup<'a> {
    program: &'a AccountInfo,
    extras: &'a [AccountInfo],
}

type ParsedRouting<'a> = (
    &'a [AccountInfo],
    Vec<&'a AccountInfo>,
    Vec<RoutingGroup<'a>>,
);

const TRANSFER_CANONICAL_ACCOUNT_COUNT: usize = 4;
// SPL Execute has five fixed accounts before its resolved meta-list accounts, and its
// amount starts after the 8-byte Execute discriminator rather than Core's 1-byte discriminator.
const TRANSFER_HOOK_FIXED_ACCOUNT_COUNT: usize = 5;
const TRANSFER_HOOK_EXECUTE_DATA_OFFSET: u8 = 8;

fn checked_hook_index(index: usize) -> Result<u8, ProgramError> {
    u8::try_from(index).map_err(|_| ProgramError::InvalidArgument)
}

fn remap_transfer_account_index(
    local_index: u8,
    previous_extra_indices: &[u8],
) -> Result<u8, ProgramError> {
    // Config indices use [source, mint, destination, authority, own previous extras].
    // The hook meta list uses absolute Execute-account indices, so only previous extras move.
    let local_index = local_index as usize;
    if local_index < TRANSFER_CANONICAL_ACCOUNT_COUNT {
        return checked_hook_index(local_index);
    }
    previous_extra_indices
        .get(local_index - TRANSFER_CANONICAL_ACCOUNT_COUNT)
        .copied()
        .ok_or(ProgramError::InvalidArgument)
}

fn compile_transfer_seeds(
    address_config: &[u8; 32],
    previous_extra_indices: &[u8],
) -> Result<Vec<ResolutionSeed>, ProgramError> {
    // Translate the verifier-visible [Transfer discriminator | amount] namespace into
    // SPL Execute data [8-byte discriminator | amount] without changing the derived PDA.
    let seeds = ResolutionSeed::unpack_address_config(address_config)
        .map_err(|_| ProgramError::InvalidArgument)?;
    let mut compiled = Vec::with_capacity(seeds.len() + 1);
    for seed in seeds {
        match seed {
            ResolutionSeed::Uninitialized => return Err(ProgramError::InvalidArgument),
            ResolutionSeed::Literal { bytes } => {
                compiled.push(ResolutionSeed::Literal { bytes });
            }
            ResolutionSeed::InstructionData { index, length } if index == 0 && length > 0 => {
                compiled.push(ResolutionSeed::Literal {
                    bytes: vec![SecurityTokenInstruction::Transfer.discriminant()],
                });
                if length > 1 {
                    compiled.push(ResolutionSeed::InstructionData {
                        index: TRANSFER_HOOK_EXECUTE_DATA_OFFSET,
                        length: length - 1,
                    });
                }
            }
            ResolutionSeed::InstructionData { index, length } => {
                let index = if length == 0 {
                    TRANSFER_HOOK_EXECUTE_DATA_OFFSET
                } else {
                    index
                        .checked_add(TRANSFER_HOOK_EXECUTE_DATA_OFFSET - 1)
                        .ok_or(ProgramError::InvalidArgument)?
                };
                compiled.push(ResolutionSeed::InstructionData { index, length });
            }
            ResolutionSeed::AccountKey { index } => {
                compiled.push(ResolutionSeed::AccountKey {
                    index: remap_transfer_account_index(index, previous_extra_indices)?,
                });
            }
            ResolutionSeed::AccountData {
                account_index,
                data_index,
                length,
            } => {
                compiled.push(ResolutionSeed::AccountData {
                    account_index: remap_transfer_account_index(
                        account_index,
                        previous_extra_indices,
                    )?,
                    data_index,
                    length,
                });
            }
        }
    }
    ResolutionSeed::pack_into_address_config(&compiled)
        .map_err(|_| ProgramError::InvalidArgument)?;
    Ok(compiled)
}

fn compile_transfer_meta(
    meta: &VerificationAccountMeta,
    verifier_program_index: u8,
    previous_extra_indices: &[u8],
) -> Result<ExtraAccountMeta, ProgramError> {
    // Verifier PDAs become SPL external-PDA metas because the deriving program is a
    // dynamically listed verifier, not the transfer hook itself.
    match meta.discriminator {
        0 => Ok(ExtraAccountMeta {
            discriminator: 0,
            address_config: meta.address_config,
            is_signer: PodBool(meta.is_signer as u8),
            is_writable: PodBool(meta.is_writable as u8),
        }),
        1 => {
            let seeds = compile_transfer_seeds(&meta.address_config, previous_extra_indices)?;
            ExtraAccountMeta::new_external_pda_with_seeds(
                verifier_program_index,
                &seeds,
                meta.is_signer,
                meta.is_writable,
            )
            .map_err(|_| ProgramError::InvalidArgument)
        }
        2 => {
            let pubkey_data = PubkeyData::unpack(&meta.address_config)
                .map_err(|_| ProgramError::InvalidArgument)?;
            let compiled = match pubkey_data {
                PubkeyData::AccountData {
                    account_index,
                    data_index,
                } => PubkeyData::AccountData {
                    account_index: remap_transfer_account_index(
                        account_index,
                        previous_extra_indices,
                    )?,
                    data_index,
                },
                PubkeyData::InstructionData { .. } | PubkeyData::Uninitialized => {
                    return Err(ProgramError::InvalidArgument)
                }
            };
            ExtraAccountMeta::new_with_pubkey_data(&compiled, meta.is_signer, meta.is_writable)
                .map_err(|_| ProgramError::InvalidArgument)
        }
        _ => Err(ProgramError::InvalidArgument),
    }
}

fn compile_transfer_account_metas(
    verification_config_pda: Pubkey,
    programs: &[VerificationProgramConfig],
) -> Result<Vec<ExtraAccountMeta>, ProgramError> {
    // Discovery order must match the runtime routing tail exactly:
    // [config, program_0, own extras_0, program_1, own extras_1, ...].
    let total_extras = programs
        .iter()
        .try_fold(0usize, |count, entry| {
            count.checked_add(entry.extra_accounts.len())
        })
        .ok_or(ProgramError::InvalidArgument)?;
    let capacity = 1usize
        .checked_add(programs.len())
        .and_then(|count| count.checked_add(total_extras))
        .ok_or(ProgramError::InvalidArgument)?;
    let mut account_metas = Vec::with_capacity(capacity);
    account_metas.push(ExtraAccountMeta {
        discriminator: 0,
        address_config: verification_config_pda,
        is_signer: PodBool(0),
        is_writable: PodBool(0),
    });

    for program in programs {
        let verifier_program_index = checked_hook_index(
            TRANSFER_HOOK_FIXED_ACCOUNT_COUNT
                .checked_add(account_metas.len())
                .ok_or(ProgramError::InvalidArgument)?,
        )?;
        account_metas.push(ExtraAccountMeta {
            discriminator: 0,
            address_config: program.program_id,
            is_signer: PodBool(0),
            is_writable: PodBool(0),
        });

        let mut previous_extra_indices = Vec::with_capacity(program.extra_accounts.len());
        for meta in &program.extra_accounts {
            let compiled =
                compile_transfer_meta(meta, verifier_program_index, &previous_extra_indices)?;
            let global_index = checked_hook_index(
                TRANSFER_HOOK_FIXED_ACCOUNT_COUNT
                    .checked_add(account_metas.len())
                    .ok_or(ProgramError::InvalidArgument)?,
            )?;
            account_metas.push(compiled);
            previous_extra_indices.push(global_index);
        }
    }
    Ok(account_metas)
}

#[cfg(test)]
mod transfer_meta_compiler_tests {
    use super::*;

    fn local_meta(meta: ExtraAccountMeta) -> VerificationAccountMeta {
        VerificationAccountMeta {
            discriminator: meta.discriminator,
            address_config: meta.address_config,
            is_signer: bool::from(meta.is_signer),
            is_writable: bool::from(meta.is_writable),
        }
    }

    #[test]
    fn compiles_external_pda_and_remaps_transfer_namespace() {
        let fixed_key = [8; 32];
        let fixed = VerificationAccountMeta {
            discriminator: 0,
            address_config: fixed_key,
            is_signer: false,
            is_writable: true,
        };
        let pda = ExtraAccountMeta::new_with_seeds(
            &[
                ResolutionSeed::InstructionData {
                    index: 0,
                    length: 9,
                },
                ResolutionSeed::AccountKey { index: 0 },
                ResolutionSeed::AccountKey { index: 4 },
            ],
            false,
            false,
        )
        .unwrap();
        let metas = compile_transfer_account_metas(
            [3; 32],
            &[VerificationProgramConfig {
                program_id: [7; 32],
                extra_accounts: vec![fixed, local_meta(pda)],
            }],
        )
        .unwrap();

        assert_eq!(metas.len(), 4);
        assert_eq!(metas[0].address_config, [3; 32]);
        assert_eq!(metas[1].address_config, [7; 32]);
        assert_eq!(metas[2].address_config, fixed_key);
        assert_eq!(metas[3].discriminator, 128 + 6);
        assert_eq!(
            ResolutionSeed::unpack_address_config(&metas[3].address_config).unwrap(),
            vec![
                ResolutionSeed::Literal { bytes: vec![12] },
                ResolutionSeed::InstructionData {
                    index: 8,
                    length: 8,
                },
                ResolutionSeed::AccountKey { index: 0 },
                ResolutionSeed::AccountKey { index: 7 },
            ]
        );
    }

    #[test]
    fn remaps_pubkey_account_data_to_previous_extra() {
        let fixed = VerificationAccountMeta {
            discriminator: 0,
            address_config: [8; 32],
            is_signer: false,
            is_writable: false,
        };
        let pubkey_data = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::AccountData {
                account_index: 4,
                data_index: 9,
            },
            false,
            true,
        )
        .unwrap();
        let metas = compile_transfer_account_metas(
            [3; 32],
            &[VerificationProgramConfig {
                program_id: [7; 32],
                extra_accounts: vec![fixed, local_meta(pubkey_data)],
            }],
        )
        .unwrap();

        assert_eq!(
            PubkeyData::unpack(&metas[3].address_config).unwrap(),
            PubkeyData::AccountData {
                account_index: 7,
                data_index: 9,
            }
        );
        assert!(bool::from(metas[3].is_writable));
    }

    #[test]
    fn resolves_pubkey_from_core_instruction_data() {
        let expected = [6; 32];
        let pubkey_data = ExtraAccountMeta::new_with_pubkey_data(
            &PubkeyData::InstructionData { index: 9 },
            false,
            false,
        )
        .unwrap();
        let mut instruction_data = vec![0; 41];
        instruction_data[9..].copy_from_slice(&expected);
        assert_eq!(
            resolve_verification_meta(&local_meta(pubkey_data), &[7; 32], &[], &instruction_data,)
                .unwrap(),
            expected
        );
    }
}

fn canonical_accounts(
    discriminator: u8,
    core_accounts: &[AccountInfo],
) -> Result<Vec<&AccountInfo>, ProgramError> {
    if discriminator == SecurityTokenInstruction::Transfer.discriminant() {
        // Forced Transfer uses a different Core layout, but verifiers always observe the
        // same semantic order as a regular Token-2022 hook invocation.
        let [authority, mint, source, destination, _hook, _token] = core_accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(vec![source, mint, destination, authority])
    } else {
        Ok(core_accounts.iter().collect())
    }
}

fn canonical_account_flags(discriminator: u8, index: usize) -> Result<(bool, bool), ProgramError> {
    use SecurityTokenInstruction::*;
    let instruction = SecurityTokenInstruction::try_from(discriminator)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let is_signer = matches!(
        (instruction.clone(), index),
        (UpdateMetadata, 1)
            | (InitializeVerificationConfig | UpdateVerificationConfig, 0)
            | (CreateRateAccount, 0)
            | (Split | Convert, 2)
            | (CreateProofAccount | UpdateProofAccount, 0)
            | (CreateDistributionEscrow | ClaimDistribution, 1)
    );
    let is_writable = match instruction {
        UpdateMetadata => matches!(index, 1 | 2),
        InitializeVerificationConfig | UpdateVerificationConfig => matches!(index, 0 | 2 | 4),
        TrimVerificationConfig => matches!(index, 1 | 2 | 4),
        Mint | Burn => matches!(index, 1 | 2),
        Pause | Resume => index == 1,
        Freeze | Thaw => index == 2,
        // Token-2022 de-escalates all four canonical accounts before invoking the hook.
        // Core uses the same read-only verifier ABI so policies behave identically on both paths.
        Transfer => false,
        CreateRateAccount => matches!(index, 0 | 1),
        UpdateRateAccount => index == 0,
        CloseRateAccount => matches!(index, 0 | 1),
        Split => matches!(index, 2 | 3 | 4 | 6),
        Convert => matches!(index, 2 | 3 | 4 | 5 | 6 | 8),
        CreateProofAccount | UpdateProofAccount => matches!(index, 0 | 2),
        CreateDistributionEscrow => matches!(index, 1 | 2),
        ClaimDistribution => matches!(index, 1 | 3 | 4 | 5),
        CloseActionReceiptAccount | CloseClaimReceiptAccount => matches!(index, 0 | 1),
        UpdateDefaultAccountState => index == 1,
        InitializeMint | Verify => return Err(ProgramError::InvalidInstructionData),
    };
    Ok((is_signer, is_writable))
}

fn resolve_verification_meta(
    meta: &VerificationAccountMeta,
    program_id: &Pubkey,
    local_accounts: &[&AccountInfo],
    instruction_data: &[u8],
) -> Result<Pubkey, ProgramError> {
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
            Ok(pinocchio::pubkey::find_program_address(&seed_refs, program_id).0)
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

fn parse_and_validate_routing<'a>(
    config: &VerificationConfig,
    instruction_accounts: &'a [AccountInfo],
    instruction_data: &[u8],
) -> Result<ParsedRouting<'a>, ProgramError> {
    let routing_count = config.programs.iter().try_fold(0usize, |count, entry| {
        count.checked_add(1 + entry.extra_accounts.len())
    });
    let routing_count = routing_count.ok_or(ProgramError::InvalidAccountData)?;
    let core_count = instruction_accounts
        .len()
        .checked_sub(routing_count)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if core_count != core_account_count(config.instruction_discriminator)? {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    // Split the config-sized routing tail from the instruction's fixed accounts.
    let (core_accounts, routing_accounts) = instruction_accounts.split_at(core_count);
    let canonical = canonical_accounts(config.instruction_discriminator, core_accounts)?;
    if canonical.len() != canonical_base_count(config.instruction_discriminator)? {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut cursor = 0usize;
    let mut groups = Vec::with_capacity(config.programs.len());
    // The same pubkey may appear in the canonical base and in a declared extra. Do not let
    // that alias promote the verifier-visible role beyond the canonical contract.
    let mut canonical_privileges = HashMap::<Pubkey, (bool, bool)>::new();
    for (index, account) in canonical.iter().enumerate() {
        let flags = canonical_account_flags(config.instruction_discriminator, index)?;
        canonical_privileges
            .entry(*account.key())
            .and_modify(|existing| {
                existing.0 |= flags.0;
                existing.1 |= flags.1;
            })
            .or_insert(flags);
    }
    // Repeated extras are allowed, including across program entries, but their logical
    // privileges must agree so CPI, introspection, and hook discovery cannot diverge.
    let mut resolved_extra_privileges = HashMap::<Pubkey, (bool, bool)>::new();
    for entry in &config.programs {
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

        let mut local_accounts = canonical.clone();
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
                return Err(SecurityTokenError::AccountIntersectionMismatch.into());
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
    Ok((core_accounts, canonical, groups))
}

impl VerificationModule {
    /// Initialize mint with all extensions and metadata
    /// Creates initial configuration of the verification module  
    pub fn initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &InitializeMintArgs,
    ) -> ProgramResult {
        let decimals = args.ix_mint.decimals;
        let client_mint_authority = args.ix_mint.mint_authority;
        let freeze_authority = args.ix_mint.freeze_authority;
        let metadata_pointer_opt = &args.ix_metadata_pointer;
        let metadata_opt = &args.ix_metadata;
        let scaled_ui_amount_opt = &args.ix_scaled_ui_amount;
        let default_account_state_opt = &args.ix_default_account_state;

        let [mint_info, mint_authority_account, creator_info, token_program_info, system_program_info, rent_info] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_token22_program(token_program_info)?;
        verify_system_program(system_program_info)?;
        verify_rent_sysvar(rent_info)?;
        verify_signer(creator_info)?;
        verify_signer(mint_info)?;
        verify_writable(creator_info)?;
        verify_writable(mint_info)?;
        verify_writable(mint_authority_account)?;
        verify_account_not_initialized(mint_authority_account)?;

        // Fail fast if caller-supplied mint authority doesn’t match the creator; SetAuthority would fail later otherwise
        if client_mint_authority != *creator_info.key() {
            return Err(ProgramError::InvalidArgument);
        }

        let (freeze_authority_pda, _bump) =
            utils::find_freeze_authority_pda(mint_info.key(), program_id);

        verify_pda_keys_match(&freeze_authority, &freeze_authority_pda)?;

        // Validate metadata pointer and metadata configuration to prevent DoS
        // Two storage models are supported:
        // 1. Internally owned: metadata_address == mint (metadata stored in mint account)
        //    - Requires ix_metadata to initialize TokenMetadata extension
        //    - Program manages metadata lifecycle
        // 2. Externally owned: metadata_address != mint (metadata in separate account)
        //    - Must NOT provide ix_metadata (client manages external account separately)
        //    - Client is responsible for ensuring metadata_address is valid
        //    - External metadata should be managed via Token-2022 directly

        if let Some(client_metadata_pointer) = metadata_pointer_opt {
            let is_internal = client_metadata_pointer.metadata_address == *mint_info.key();
            match (is_internal, metadata_opt.is_some()) {
                // internal + no metadata provided
                (true, false) => {
                    return Err(SecurityTokenError::InternalMetadataRequiresData.into())
                }
                // external + metadata provided
                (false, true) => return Err(SecurityTokenError::ExternalMetadataForbidsData.into()),
                _ => {} // valid combinations
            }
        }

        let mut extensions_buf: [ExtensionType; 6] = [ExtensionType::Pausable; 6];
        let mut ext_count: usize = 0;
        let required_extensions: &[ExtensionType] = &[
            ExtensionType::PermanentDelegate,
            ExtensionType::TransferHook,
            ExtensionType::Pausable,
        ];
        for &ext in required_extensions {
            extensions_buf[ext_count] = ext;
            ext_count += 1;
        }

        // Add MetadataPointer if provided by client
        if metadata_pointer_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::MetadataPointer;
            ext_count += 1;
        }

        // Add ScaledUiAmount if provided by client
        if scaled_ui_amount_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::ScaledUiAmount;
            ext_count += 1;
        }

        // Add DefaultAccountState if provided by client
        if default_account_state_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::DefaultAccountState;
            ext_count += 1;
        }

        // Calculate mint size with extensions (but without metadata TLV data)
        let mint_size = if ext_count == 0 {
            Mint::BASE_LEN
        } else {
            utils::calculate_mint_size_with_extensions(&extensions_buf[..ext_count])
        };

        let metadata_size = if let Some(metadata) = &metadata_opt {
            utils::calculate_metadata_tlv_size(metadata)?
        } else {
            0
        };

        let total_size = mint_size + metadata_size;
        let rent = Rent::from_account_info(rent_info)?;
        let required_lamports = rent.minimum_balance(total_size);
        let create_account_instruction = CreateAccount {
            from: creator_info,              // from (payer)
            to: mint_info,                   // to (new account)
            lamports: required_lamports,     // amount
            space: mint_size as u64,         // space (full size including metadata)
            owner: token_program_info.key(), // owner (SPL Token 2022 program)
        };

        create_account_instruction.invoke()?;

        // Calculate all PDAs that will be used for extensions and mint initialization
        let (transfer_hook_pda, _bump) = utils::find_transfer_hook_pda(mint_info.key(), program_id);
        let (permanent_delegate_pda, _bump) =
            utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        let (pause_authority_pda, _bump) =
            utils::find_pause_authority_pda(mint_info.key(), program_id);

        let permanent_delegate_initialize = InitializePermanentDelegate {
            mint: mint_info,
            delegate: permanent_delegate_pda,
        };

        permanent_delegate_initialize.invoke()?;

        let transfer_hook_initialize = InitializeTransferHook {
            mint: mint_info,
            authority: transfer_hook_pda.into(),
            // TODO: A direct import of security_token_transfer_hook::id() causes build issues with the allocator, investigate later
            program_id: Some(TRANSFER_HOOK_PROGRAM_ID),
        };

        transfer_hook_initialize.invoke()?;

        let pausable_initialize = InitializePausable {
            mint: mint_info,
            authority: pause_authority_pda,
        };

        pausable_initialize.invoke()?;

        // Initialize MetadataPointer extension if provided by client
        if let Some(client_metadata_pointer) = metadata_pointer_opt {
            let metadata_pointer_initialize = InitializeMetadataPointer {
                mint: mint_info,
                authority: client_metadata_pointer.authority.into(),
                metadata_address: client_metadata_pointer.metadata_address.into(),
            };
            metadata_pointer_initialize.invoke()?;
        }

        // Initialize ScaledUiAmount extension if provided by client
        if let Some(scaled_ui_amount_config) = &scaled_ui_amount_opt {
            let scaled_ui_amount_initialize = InitializeScaledUiAmount {
                mint: mint_info,
                authority: scaled_ui_amount_config.authority.into(),
                multiplier: f64::from_le_bytes(scaled_ui_amount_config.multiplier),
            };

            scaled_ui_amount_initialize.invoke()?;
        }

        // Initialize DefaultAccountState extension if provided by client
        if let Some(&state_byte) = default_account_state_opt.as_ref() {
            InitializeDefaultAccountState {
                mint: mint_info,
                state: AccountState::from(state_byte),
            }
            .invoke()?;
        }

        // Use client-provided authorities for base initialize to match client expectations/tests
        let initialize_mint_instruction = InitializeMint2 {
            mint: mint_info,
            decimals,
            mint_authority: &client_mint_authority,
            freeze_authority: Some(&freeze_authority),
            token_program: token_program_info.key(),
        };

        initialize_mint_instruction.invoke()?;

        // NOTE: Transfer mint authority to PDA, review it
        // Get mint authority PDA - this will be the mint authority for the token
        let (mint_authority_pda, mint_authority_bump) =
            utils::find_mint_authority_pda(mint_info.key(), creator_info.key(), program_id);

        verify_pda_keys_match(mint_authority_account.key(), &mint_authority_pda)?;

        let mint_authority_config =
            MintAuthority::new(*mint_info.key(), *creator_info.key(), mint_authority_bump)?;

        let authority_account_required_lamports = rent.minimum_balance(MintAuthority::LEN);
        let create_mint_authority_instruction = CreateAccount {
            from: creator_info,                            // from (payer)
            to: mint_authority_account,                    // to (new PDA account)
            lamports: authority_account_required_lamports, // amount
            space: MintAuthority::LEN as u64,              // space (serialized state size)
            owner: program_id,                             // owner (program-owned account)
        };

        let bump_seed = [mint_authority_bump];
        let mint_authority_seeds = [
            Seed::from(seeds::MINT_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(creator_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let mint_authority_signer = Signer::from(&mint_authority_seeds);

        create_mint_authority_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
        {
            let mut data = mint_authority_account.try_borrow_mut_data()?;
            let config_bytes = mint_authority_config.to_bytes();
            data[..config_bytes.len()].copy_from_slice(&config_bytes);
        }

        let set_authority_instruction = SetAuthority {
            account: mint_info,
            authority: creator_info,
            authority_type: AuthorityType::MintTokens,
            new_authority: Some(&mint_authority_pda),
            token_program: token_program_info.key(),
        };

        set_authority_instruction.invoke()?;

        let Some(metadata) = metadata_opt else {
            return Ok(());
        };

        // At this point we are guaranteed to initialize internally-stored metadata only
        // The validation at the beginning ensures that
        let metadata_init_instruction = InitializeTokenMetadata {
            metadata: mint_info,
            update_authority: mint_authority_account,
            mint: mint_info,
            mint_authority: mint_authority_account,
            name: &metadata.name,
            symbol: &metadata.symbol,
            uri: &metadata.uri,
        };

        metadata_init_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Add additional metadata fields if present - each field requires separate instruction
        if !metadata.additional_metadata.is_empty() {
            // Parse additional metadata from raw bytes and process each field
            utils::parse_additional_metadata(
                metadata.additional_metadata.as_slice(),
                |key, value| {
                    let update_field_instruction = UpdateField {
                        metadata: mint_info,
                        update_authority: mint_authority_account,
                        field: Field::Key(key),
                        value,
                    };
                    update_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    /// Update metadata for existing mint
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn update_metadata(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &UpdateMetadataArgs,
    ) -> ProgramResult {
        let [mint_authority, payer, mint_info, token_program_info, system_program_info] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;

        verify_token22_program(token_program_info)?;
        verify_system_program(system_program_info)?;
        verify_signer(payer)?;
        verify_owner(mint_authority, program_id)?;
        verify_writable(payer)?;
        verify_writable(mint_info)?;

        let mint_authority_data = MintAuthority::from_account_info(mint_authority)?;

        if &mint_authority_data.mint != mint_info.key() {
            return Err(ProgramError::InvalidAccountData);
        }

        // Get metadata account address from MetadataPointer extension
        let metadata_address: Option<Pubkey> = {
            let mint_data = mint_info.try_borrow_data()?;

            // Use pinocchio's get_extension_from_bytes instead of StateWithExtensions
            let metadata_pointer = get_extension_from_bytes::<MetadataPointer>(&mint_data)
                .ok_or(ProgramError::InvalidAccountData)?;

            metadata_pointer.metadata_address.into()
        }; // Borrow is released here
        let metadata_address = metadata_address.ok_or(ProgramError::InvalidAccountData)?;

        // We only support internally owned metadata (metadata stored in the mint account itself)
        // External metadata should be managed directly
        if metadata_address != *mint_info.key() {
            return Err(SecurityTokenError::CannotModifyExternalMetadataAccount.into());
        }

        // NOTE: No need to verify TokenMetadata extension existence here because:
        // - initialize_mint already validates that internally owned metadata pointer requires TokenMetadata
        // - Since metadata_address == mint (checked above), the extension is guaranteed to exist
        // - Token-2022 UpdateField will fail gracefully if extension is somehow missing
        //
        // {
        //     let mint_data = mint_info.try_borrow_data()?;
        //     get_extension_data_bytes_for_variable_pack::<TokenMetadata>(&mint_data)
        //         .ok_or(ProgramError::InvalidAccountData)?;
        // }

        // Calculate current and new metadata sizes
        let new_metadata_size = utils::calculate_metadata_tlv_size(&args.metadata)?;
        // Get current metadata size to calculate the difference
        let current_metadata_size = {
            let mint_data = mint_info.try_borrow_data()?;

            // Use pinocchio's get_extension_data_bytes_for_variable_pack to get current metadata
            if let Some(metadata_bytes) =
                get_extension_data_bytes_for_variable_pack::<TokenMetadata>(&mint_data)
            {
                // The length of the raw extension data includes TLV headers
                // For simplification, use the raw byte length as the current size
                metadata_bytes.len() + 4 // Add 4 bytes for TLV header (type + length)
            } else {
                // No metadata currently, so current size is 0
                0
            }
        };

        if new_metadata_size > current_metadata_size {
            let additional_metadata_space = new_metadata_size - current_metadata_size;
            let rent = Rent::get()?;
            let additional_rent = rent.minimum_balance(additional_metadata_space);
            let transfer = Transfer {
                from: payer,               // from (authority pays)
                to: mint_info,             // to (mint account)
                lamports: additional_rent, // amount
            };
            transfer.invoke()?;
        }

        let bump_seed = [mint_authority_data.bump];
        let mint_authority_seeds = [
            Seed::from(seeds::MINT_AUTHORITY),
            Seed::from(mint_authority_data.mint.as_ref()),
            Seed::from(mint_authority_data.mint_creator.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let mint_authority_signer = Signer::from(&mint_authority_seeds);

        let update_field_instruction = UpdateField {
            metadata: mint_info,
            update_authority: mint_authority,
            field: Field::Name,
            value: &args.metadata.name,
        };

        update_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Update symbol
        let update_symbol_instruction = UpdateField {
            metadata: mint_info,
            update_authority: mint_authority,
            field: Field::Symbol,
            value: &args.metadata.symbol,
        };

        update_symbol_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Update URI
        let update_uri_instruction = UpdateField {
            metadata: mint_info,
            update_authority: mint_authority,
            field: Field::Uri,
            value: &args.metadata.uri,
        };

        update_uri_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Handle additional metadata fields atomically
        let existing_additional_fields = {
            // Try to parse existing metadata using pinocchio's from_account_info
            if let Ok(existing_metadata) = TokenMetadata::from_account_info(mint_info) {
                let mut fields_buffer: [[u8; 64]; 16] = [[0u8; 64]; 16]; // Static buffer for field names
                let mut field_lengths: [usize; 16] = [0; 16];
                let mut field_count = 0;

                // Parse existing additional metadata to extract all field keys
                let parse_result = utils::parse_additional_metadata(
                    existing_metadata.additional_metadata,
                    |key, _value| {
                        if field_count < 16 && key.len() <= 64 {
                            // Copy key bytes to static buffer
                            let key_bytes = key.as_bytes();
                            fields_buffer[field_count][..key_bytes.len()]
                                .copy_from_slice(key_bytes);
                            field_lengths[field_count] = key_bytes.len();
                            field_count += 1;
                        }
                        Ok(())
                    },
                );

                if parse_result.is_err() {
                    field_count = 0; // Reset to 0 if parsing failed
                }

                (fields_buffer, field_lengths, field_count)
            } else {
                let fields_buffer: [[u8; 64]; 16] = [[0u8; 64]; 16];
                let field_lengths: [usize; 16] = [0; 16];
                let field_count = 0;
                (fields_buffer, field_lengths, field_count)
            }
        };

        let (fields_buffer, field_lengths, field_count) = existing_additional_fields;

        // Step 2: Remove only existing fields that are NOT in the new metadata
        if field_count > 0 {
            for i in 0..field_count {
                let key_bytes = &fields_buffer[i][..field_lengths[i]];
                if let Ok(existing_key) = core::str::from_utf8(key_bytes) {
                    // Check if this existing field is in the new metadata by parsing new metadata
                    let mut found_in_new = false;

                    if !args.metadata.additional_metadata.is_empty() {
                        let _check_result = utils::parse_additional_metadata(
                            args.metadata.additional_metadata.as_slice(),
                            |new_key, _value| {
                                if existing_key == new_key {
                                    found_in_new = true;
                                }
                                Ok(())
                            },
                        );
                    }

                    if !found_in_new {
                        let remove_field_instruction = RemoveKey {
                            metadata: mint_info,
                            update_authority: mint_authority,
                            key: existing_key,
                            idempotent: true, // don't error if key doesn't exist
                        };

                        remove_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
                        // Ignore errors since we're using idempotent flag
                    }
                }
            }
        }

        // Step 4: Add/update new additional metadata fields
        if args.metadata.additional_metadata.is_empty() {
            return Ok(());
        }
        let result = utils::parse_additional_metadata(
            args.metadata.additional_metadata.as_slice(),
            |key, value| {
                let update_field_instruction = UpdateField {
                    metadata: mint_info,
                    update_authority: mint_authority,
                    field: Field::Key(key),
                    value,
                };
                update_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
                Ok(())
            },
        );
        result.map_err(|_e| ProgramError::InvalidInstructionData)?;
        Ok(())
    }

    /// Verify specific operation against configured verification programs
    ///
    /// Client is responsible for deriving and providing the correct VerificationConfig PDA
    /// based on mint and instruction discriminator they want to verify.
    ///
    /// Each verification call must immediately precede this instruction and contain exactly the
    /// configured program's canonical base accounts followed by only that program's declared extras.
    pub fn verify_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &VerifyArgs,
    ) -> ProgramResult {
        let mut instruction_data = Vec::with_capacity(1 + args.instruction_data.len());
        instruction_data.push(args.ix);
        instruction_data.extend_from_slice(&args.instruction_data);
        Self::verify_by_programs(program_id, accounts, args.ix, &instruction_data)?;
        Ok(())
    }

    /// Verify specific operation either through configured verification programs or mint authority
    /// Decides which method to use based on the PDA account provided in accounts[1]
    ///
    /// # Returns
    /// * `verified_mint_info` - The authorized Mint account (prevents mint substitution attacks in operations)
    /// * `cleaned_accounts` - Remaining instruction accounts after verification overhead
    pub fn verify_by_strategy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo],
        ix_discriminator: u8,
        instruction_data: &[u8],
    ) -> Result<(&'a AccountInfo, &'a [AccountInfo]), ProgramError> {
        let [mint_info, verification_config_or_mint_authority, instructions_sysvar_or_signer, _instruction_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        let config_data = verification_config_or_mint_authority.try_borrow_data()?;
        let state_discriminator = config_data
            .first()
            .ok_or(ProgramError::InvalidAccountData)?;
        let disc = SecurityTokenDiscriminators::try_from(*state_discriminator)?;
        match disc {
            SecurityTokenDiscriminators::VerificationConfigDiscriminator => {
                let (mint_info, cleaned_accounts) = Self::verify_by_programs(
                    program_id,
                    accounts,
                    ix_discriminator,
                    instruction_data,
                )?;
                Ok((mint_info, cleaned_accounts))
            }
            SecurityTokenDiscriminators::MintAuthorityDiscriminator => {
                let mint_authority_account = verification_config_or_mint_authority;
                let mint_creator_info = instructions_sysvar_or_signer;
                let mint_info = Self::verify_by_mint_authority(
                    program_id,
                    mint_info,
                    mint_authority_account,
                    mint_creator_info,
                )?;
                Ok((mint_info, &accounts[INSTRUCTION_ACCOUNTS_OFFSET..]))
            }
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    /// Verify that the provided signer corresponds to the original mint authority PDA.
    ///
    /// # Returns
    /// * `verified_mint_info` - The authorized Mint account (prevents mint substitution attacks in operations)
    pub fn verify_by_mint_authority<'a>(
        program_id: &Pubkey,
        mint_info: &'a AccountInfo,
        mint_authority: &'a AccountInfo,
        candidate_authority: &'a AccountInfo,
    ) -> Result<&'a AccountInfo, ProgramError> {
        verify_signer(candidate_authority)?;
        verify_owner(mint_authority, program_id)?;
        verify_owner(mint_info, &pinocchio_token_2022::ID)?;

        let data = mint_authority.try_borrow_data()?;
        if data.len() < MintAuthority::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let mint_authority_state = MintAuthority::try_from_bytes(&data)?;

        // CRITICAL: Verify that the authority is for the correct mint and signed by correct creator
        // These checks prevent using a valid MintAuthority PDA for a different mint/creator combination
        if mint_authority_state.mint != *mint_info.key() {
            return Err(ProgramError::InvalidAccountData);
        }

        if mint_authority_state.mint_creator != *candidate_authority.key() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Use stored bump with derive_pda for optimized PDA verification
        let expected_pda = mint_authority_state.derive_pda()?;

        verify_pda_keys_match(mint_authority.key(), &expected_pda)?;

        Ok(mint_info)
    }

    /// Verify specific operation against configured verification programs
    ///
    /// # Returns
    /// * `verified_mint_info` - The authorized Mint account (prevents mint substitution attacks in operations)
    /// * `cleaned_accounts` - Remaining instruction accounts after verification overhead
    pub fn verify_by_programs<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo],
        ix_discriminator: u8,
        instruction_data: &[u8],
    ) -> Result<(&'a AccountInfo, &'a [AccountInfo]), ProgramError> {
        let [mint_info, verification_config, instructions_sysvar, instruction_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_instructions_sysvar(instructions_sysvar)?;
        verify_owner(verification_config, program_id)?;
        verify_owner(mint_info, &pinocchio_token_2022::ID)?;
        verify_account_initialized(verification_config)?;

        let config_data = VerificationConfig::from_account_info(verification_config)?;

        // CRITICAL: Verify that the config is for the expected instruction discriminator
        // This prevents instruction substitution attacks where attacker provides
        // a valid VerificationConfig PDA for instruction X when code expects instruction Y
        if config_data.instruction_discriminator != ix_discriminator {
            return Err(ProgramError::InvalidAccountData);
        }

        // Use stored bump with derive_pda for optimized PDA verification
        // PDA derivation includes mint and instruction_discriminator in seeds,
        // so successful verification cryptographically guarantees this config
        // is for the correct mint and instruction type
        let expected_config_pda = config_data.derive_pda(mint_info.key())?;

        if verification_config.key().ne(&expected_config_pda) {
            return Err(SecurityTokenError::InvalidVerificationConfigPda.into());
        }

        if config_data.programs.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        }

        let (cleaned_accounts, canonical_accounts, routing_groups) =
            parse_and_validate_routing(&config_data, instruction_accounts, instruction_data)?;

        if config_data.cpi_mode {
            Self::execute_cpi_mode_verification(
                &config_data,
                &canonical_accounts,
                &routing_groups,
                instruction_data,
            )?;
        } else {
            Self::execute_introspection_verification(
                &config_data,
                instructions_sysvar,
                &canonical_accounts,
                &routing_groups,
                instruction_data,
            )?;
        }

        Ok((mint_info, cleaned_accounts))
    }

    fn execute_cpi_mode_verification(
        config: &VerificationConfig,
        canonical_accounts: &[&AccountInfo],
        routing_groups: &[RoutingGroup<'_>],
        target_instruction_data: &[u8],
    ) -> ProgramResult {
        for (entry, group) in config.programs.iter().zip(routing_groups) {
            let mut account_metas =
                Vec::with_capacity(canonical_accounts.len() + group.extras.len());
            let mut account_refs =
                Vec::with_capacity(canonical_accounts.len() + group.extras.len());
            for (index, account) in canonical_accounts.iter().enumerate() {
                let (is_signer, is_writable) =
                    canonical_account_flags(config.instruction_discriminator, index)?;
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
                data: target_instruction_data,
            };
            pinocchio::program::slice_invoke(&verification_instruction, &account_refs)?;
        }
        Ok(())
    }

    /// Execute introspection-based verification
    /// Validates that required verification programs were called before the current instruction
    /// by examining the instructions sysvar and comparing their accounts and arguments with current instruction accounts
    fn execute_introspection_verification(
        config: &VerificationConfig,
        instructions_sysvar: &AccountInfo,
        canonical_accounts: &[&AccountInfo],
        routing_groups: &[RoutingGroup<'_>],
        target_instruction_data: &[u8],
    ) -> ProgramResult {
        // Get current instruction index
        let instructions = Instructions::try_from(instructions_sysvar)?;
        let current_index = instructions.load_current_index() as usize;
        let block_start = current_index
            .checked_sub(config.programs.len())
            .ok_or(SecurityTokenError::VerificationProgramNotFound)?;

        for (entry_index, (entry, group)) in config.programs.iter().zip(routing_groups).enumerate()
        {
            let instruction = instructions
                .load_instruction_at(block_start + entry_index)
                .map_err(|_| SecurityTokenError::VerificationProgramNotFound)?;
            if instruction.get_program_id() != &entry.program_id
                || instruction.get_instruction_data() != target_instruction_data
            {
                return Err(SecurityTokenError::VerificationProgramNotFound.into());
            }
            let expected_len = canonical_accounts.len() + group.extras.len();
            for index in 0..expected_len {
                let observed = instruction
                    .get_account_meta_at(index)
                    .map_err(|_| SecurityTokenError::AccountIntersectionMismatch)?;
                let expected = if index < canonical_accounts.len() {
                    canonical_accounts[index].key()
                } else {
                    group.extras[index - canonical_accounts.len()].key()
                };
                if &observed.key != expected {
                    return Err(SecurityTokenError::AccountIntersectionMismatch.into());
                }
            }
            if instruction.get_account_meta_at(expected_len).is_ok() {
                return Err(SecurityTokenError::AccountIntersectionMismatch.into());
            }
        }
        Ok(())
    }

    /// Initialize verification configuration for an instruction
    ///
    /// Creates a VerificationConfig PDA for a specific instruction type.
    /// Each instruction (burn, transfer, mint, etc.) gets its own config.
    pub fn initialize_verification_config(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &crate::instructions::InitializeVerificationConfigArgs,
    ) -> ProgramResult {
        let [payer, mint_account, config_account, system_program_info, transfer_hook_accounts @ ..] =
            &accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        verify_system_program(system_program_info)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_writable(config_account)?;
        verify_owner(mint_account, &pinocchio_token_2022::ID)?;

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        // Derive expected PDA address
        let (expected_config_pda, bump) =
            utils::find_verification_config_pda(mint_account.key(), discriminator, program_id);

        // Verify that the provided config account matches the expected PDA
        verify_pda_keys_match(config_account.key(), &expected_config_pda)?;

        // Check if account already exists
        if config_account.data_len() > 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // Create the VerificationConfig data first to calculate exact size
        let config = VerificationConfig::new(discriminator, args.cpi_mode, bump, args.programs())?;

        let account_size = config.serialized_size();

        // Calculate rent for the account
        let rent = Rent::get()?;
        let required_lamports = rent.minimum_balance(account_size);

        // Create the PDA account
        let create_account_instruction = CreateAccount {
            from: payer,
            to: config_account,
            lamports: required_lamports,
            space: account_size as u64,
            owner: program_id,
        };

        // Create seeds for PDA signing
        let bump_seed = [bump];
        let discriminator_seed = [discriminator];
        let seeds = [
            Seed::from(seeds::VERIFICATION_CONFIG),
            Seed::from(mint_account.key().as_ref()),
            Seed::from(discriminator_seed.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let signer = Signer::from(&seeds);

        create_account_instruction.invoke_signed(&[signer])?;

        // Write data to the account using manual serialization
        {
            let mut data = config_account.try_borrow_mut_data()?;
            let config_bytes = config.to_bytes();
            data[..config_bytes.len()].copy_from_slice(&config_bytes);
        }

        if discriminator == SecurityTokenInstruction::Transfer as u8 {
            // Initialize transfer hook extra account metas
            Self::initialize_transfer_hook_account_metas(
                program_id,
                payer,
                mint_account,
                system_program_info,
                transfer_hook_accounts,
                *config_account.key(),
                args.programs(),
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sync_transfer_hook_account_metas(
        program_id: &Pubkey,
        payer: &AccountInfo,
        mint_info: &AccountInfo,
        system_program_info: &AccountInfo,
        transfer_hook_accounts: &[AccountInfo],
        verification_config_pda: Pubkey,
        programs: &[VerificationProgramConfig],
        is_initialization: bool,
    ) -> ProgramResult {
        let [account_metas_pda_info, transfer_hook_pda_info, transfer_hook_program] =
            transfer_hook_accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_writable(account_metas_pda_info)?;
        verify_transfer_hook_program(transfer_hook_program)?;
        let (transfer_hook_pda, bump) = utils::find_transfer_hook_pda(mint_info.key(), program_id);
        verify_pda_keys_match(&transfer_hook_pda, transfer_hook_pda_info.key())?;
        let (account_metas_pda, _bump) = find_extra_account_metas_pda(mint_info.key());
        verify_pda_keys_match(&account_metas_pda, account_metas_pda_info.key())?;

        // VerificationConfig is authoritative; this list is derived discovery state for
        // standard Token-2022 clients and is updated in the same transaction as the config.
        let account_metas = compile_transfer_account_metas(verification_config_pda, programs)?;

        let new_account_size = ExtraAccountMetaList::size_of(account_metas.len())
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let rent = Rent::get()?;
        let required_lamports = rent.minimum_balance(new_account_size);
        let rent_deficit = required_lamports.saturating_sub(account_metas_pda_info.lamports());
        if rent_deficit > 0 {
            let transfer = Transfer {
                from: payer,
                to: account_metas_pda_info,
                lamports: rent_deficit,
            };
            transfer.invoke()?;
        }

        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::TRANSFER_HOOK),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let signer = Signer::from(&seeds);
        if is_initialization {
            let instruction = InitializeExtraAccountMetaList {
                program_id: &TRANSFER_HOOK_PROGRAM_ID,
                extra_account_metas_pda: account_metas_pda_info,
                mint: mint_info,
                authority: transfer_hook_pda_info,
                system_program: system_program_info,
                metas: &account_metas,
            };
            instruction.invoke_signed(&[signer])?;
        } else {
            let instruction = UpdateExtraAccountMetaList {
                program_id: &TRANSFER_HOOK_PROGRAM_ID,
                extra_account_metas_pda: account_metas_pda_info,
                mint: mint_info,
                authority: transfer_hook_pda_info,
                system_program: system_program_info,
                recipient: Some(payer),
                metas: &account_metas,
            };
            instruction.invoke_signed(&[signer])?;
        }
        Ok(())
    }

    fn update_transfer_hook_account_metas(
        program_id: &Pubkey,
        payer: &AccountInfo,
        mint_info: &AccountInfo,
        system_program_info: &AccountInfo,
        transfer_hook_accounts: &[AccountInfo],
        verification_config_pda: Pubkey,
        programs: &[VerificationProgramConfig],
    ) -> ProgramResult {
        Self::sync_transfer_hook_account_metas(
            program_id,
            payer,
            mint_info,
            system_program_info,
            transfer_hook_accounts,
            verification_config_pda,
            programs,
            false,
        )
    }

    fn initialize_transfer_hook_account_metas(
        program_id: &Pubkey,
        payer: &AccountInfo,
        mint_info: &AccountInfo,
        system_program_info: &AccountInfo,
        transfer_hook_accounts: &[AccountInfo],
        verification_config_pda: Pubkey,
        programs: &[VerificationProgramConfig],
    ) -> ProgramResult {
        Self::sync_transfer_hook_account_metas(
            program_id,
            payer,
            mint_info,
            system_program_info,
            transfer_hook_accounts,
            verification_config_pda,
            programs,
            true,
        )
    }

    /// Update verification configuration for an instruction
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn update_verification_config(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &crate::instructions::UpdateVerificationConfigArgs,
    ) -> ProgramResult {
        let [payer, mint_account, config_account, system_program_info, transfer_hook_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        verify_system_program(system_program_info)?;
        verify_owner(mint_account, &pinocchio_token_2022::ID)?;
        verify_owner(config_account, program_id)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_writable(config_account)?;
        verify_account_initialized(config_account)?;

        let mut existing_config = VerificationConfig::from_account_info(config_account)?;
        let expected_config_pda = existing_config.derive_pda(mint_account.key())?;

        // Verify that the provided config account matches the expected PDA
        verify_pda_keys_match(config_account.key(), &expected_config_pda)?;
        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;
        // Verify discriminator matches
        if existing_config.instruction_discriminator != discriminator {
            return Err(ProgramError::InvalidAccountData);
        }
        let offset = args.offset() as usize;

        // Offset can't be greater than existing program count
        if offset > existing_config.programs.len() {
            return Err(ProgramError::InvalidArgument);
        }

        // Update cpi_mode
        existing_config.cpi_mode = args.cpi_mode;

        // Replace verification programs starting at the specified offset
        for (i, new_program) in args.programs().iter().enumerate() {
            let index = offset.checked_add(i).ok_or(ProgramError::InvalidArgument)?;
            if index < existing_config.programs.len() {
                existing_config.programs[index] = new_program.clone();
            } else {
                existing_config.programs.push(new_program.clone());
            }
        }

        existing_config.validate()?;

        let new_size = existing_config.serialized_size();
        let current_size = config_account.data_len();
        let rent = Rent::get()?;
        let current_minimum_balance = rent.minimum_balance(current_size);
        let new_minimum_balance = rent.minimum_balance(new_size);
        let mut recovered_rent = 0u64;

        // Fund only the actual deficit and refund only the rent-minimum delta. Any existing
        // surplus remains attached to the config rather than becoming claimable by an updater.
        if new_size > current_size {
            let rent_deficit = new_minimum_balance.saturating_sub(config_account.lamports());
            if rent_deficit > 0 {
                let transfer = Transfer {
                    from: payer,
                    to: config_account,
                    lamports: rent_deficit,
                };
                transfer.invoke()?;
            }
            config_account.resize(new_size)?;
        } else if new_size < current_size {
            config_account.resize(new_size)?;
            let rent_delta = current_minimum_balance.saturating_sub(new_minimum_balance);
            let refundable_balance = config_account
                .lamports()
                .saturating_sub(new_minimum_balance);
            recovered_rent = rent_delta.min(refundable_balance);
        }

        let config_bytes = existing_config.to_bytes();

        {
            let mut data = config_account.try_borrow_mut_data()?;
            data[..config_bytes.len()].copy_from_slice(&config_bytes);
        }

        // Synchronize derived hook discovery state before releasing the shrink refund. A CPI
        // failure aborts the instruction, so config, meta list, and balances roll back together.
        if discriminator == SecurityTokenInstruction::Transfer as u8 {
            Self::update_transfer_hook_account_metas(
                program_id,
                payer,
                mint_account,
                system_program_info,
                transfer_hook_accounts,
                *config_account.key(),
                existing_config.programs.as_slice(),
            )?;
        }
        if recovered_rent > 0 {
            let config_lamports = config_account.lamports();
            let payer_lamports = payer.lamports();
            *config_account.try_borrow_mut_lamports()? = config_lamports
                .checked_sub(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;
            *payer.try_borrow_mut_lamports()? = payer_lamports
                .checked_add(recovered_rent)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
        Ok(())
    }

    /// Trim verification configuration to recover rent
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn trim_verification_config(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &TrimVerificationConfigArgs,
    ) -> ProgramResult {
        let [mint_account, config_account, recipient, system_program_info, transfer_hook_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        verify_system_program(system_program_info)?;
        verify_owner(config_account, program_id)?;
        verify_owner(mint_account, &pinocchio_token_2022::ID)?;
        verify_writable(recipient)?;
        verify_writable(config_account)?;
        verify_account_initialized(config_account)?;

        let mut existing_config = VerificationConfig::from_account_info(config_account)?;
        let expected_config_pda = existing_config.derive_pda(mint_account.key())?;

        // Verify that the provided config account matches the expected PDA
        verify_pda_keys_match(config_account.key(), &expected_config_pda)?;

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;
        // Verify discriminator matches
        if existing_config.instruction_discriminator != discriminator {
            return Err(ProgramError::InvalidAccountData);
        }

        let current_program_count = existing_config.programs.len();
        let new_size = args.size as usize;

        // Validate new size
        if new_size > current_program_count {
            return Err(ProgramError::InvalidArgument);
        }

        let (new_program_list, recovered_rent) = if args.close {
            let config_lamports = config_account.lamports();
            (&[][..], config_lamports)
        } else if new_size < current_program_count {
            // Trim: truncate program list, calculate recovered rent
            existing_config.programs.truncate(new_size);
            existing_config.validate()?;

            let new_account_size = existing_config.serialized_size();
            let current_account_size = config_account.data_len();

            if new_account_size < current_account_size {
                let rent = Rent::get()?;
                let old_rent = rent.minimum_balance(current_account_size);
                let new_rent = rent.minimum_balance(new_account_size);
                let recovered = old_rent - new_rent;
                (existing_config.programs.as_slice(), recovered)
            } else {
                // No size change, just update data
                let config_bytes = existing_config.to_bytes();
                let mut data = config_account.try_borrow_mut_data()?;
                data[..config_bytes.len()].copy_from_slice(&config_bytes);
                return Ok(());
            }
        } else {
            return Ok(());
        };

        // Update transfer hook BEFORE any balance changes
        if discriminator == SecurityTokenInstruction::Transfer as u8 {
            Self::update_transfer_hook_account_metas(
                program_id,
                recipient,
                mint_account,
                system_program_info,
                transfer_hook_accounts,
                *config_account.key(),
                new_program_list,
            )?;
        }

        if args.close {
            // Close the account completely
            *config_account.try_borrow_mut_lamports()? = 0;
            *recipient.try_borrow_mut_lamports()? = recipient
                .lamports()
                .checked_add(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;
            config_account.resize(0)?;
        } else {
            let new_account_size = existing_config.serialized_size();
            config_account.resize(new_account_size)?;

            let config_bytes = existing_config.to_bytes();
            {
                let mut data = config_account.try_borrow_mut_data()?;
                data[..config_bytes.len()].copy_from_slice(&config_bytes);
            }

            *config_account.try_borrow_mut_lamports()? = config_account
                .lamports()
                .checked_sub(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;

            *recipient.try_borrow_mut_lamports()? = recipient
                .lamports()
                .checked_add(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;
        }
        Ok(())
    }

    pub fn update_default_account_state(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &UpdateDefaultAccountStateArgs,
    ) -> ProgramResult {
        let [freeze_authority, mint_info, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_writable(mint_info)?;
        verify_owner(mint_info, &pinocchio_token_2022::ID)?;

        let (freeze_authority_pda, bump) =
            utils::find_freeze_authority_pda(mint_info.key(), program_id);
        verify_pda_keys_match(freeze_authority.key(), &freeze_authority_pda)?;

        let state = AccountState::from(args.state);
        let bump_seed = [bump];
        let signer_seeds = [
            Seed::from(seeds::FREEZE_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let freeze_authority_signer = Signer::from(&signer_seeds);

        UpdateDefaultAccountStateCpi {
            mint: mint_info,
            freeze_authority,
            state,
        }
        .invoke_signed(&[freeze_authority_signer])
    }
}

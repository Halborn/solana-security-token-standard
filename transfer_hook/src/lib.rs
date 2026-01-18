//! Security Token transfer hook implementation
#![allow(unexpected_cfgs)]

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{checked_create_program_address, find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::{declare_id, pubkey};
use pinocchio_system::instructions::{Allocate, Assign};
use solana_pubkey::Pubkey as SolanaPubkey;
use spl_discriminator::SplDiscriminate;
use spl_pod::slice::PodSlice;
use spl_tlv_account_resolution::{account::ExtraAccountMeta, state::ExtraAccountMetaList};
use spl_transfer_hook_interface::get_extra_account_metas_address_and_bump_seed;
use spl_transfer_hook_interface::instruction::{
    ExecuteInstruction, InitializeExtraAccountMetaListInstruction,
    UpdateExtraAccountMetaListInstruction,
};
pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH");
const PERMANENT_DELEGATE_SEED: &[u8] = b"mint.permanent_delegate";
const TRANSFER_HOOK_SEED: &[u8] = b"mint.transfer_hook";
const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
const VERIFICATION_CONFIG_SEED: &[u8] = b"verification_config";
const TRANSFER_DISCRIMINATOR: u8 = 12; // Security Token transfer instruction discriminator
const TRANSFER_VERIFICATION_CONFIG_DISCRIMINATOR: u8 = 1; // Account discriminator for Security Token verification config
const MAX_VERIFICATION_PROGRAMS: usize = 10;

// NOTE: Replace with the finalized program ID generated for the transfer hook deployment.
declare_id!("DTUuEirVJFg53cKgyTPKtVgvi5SV5DCDQpvbmdwBtYdd");

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::entrypoint;
#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < ExecuteInstruction::SPL_DISCRIMINATOR_SLICE.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (discriminator, rest) =
        instruction_data.split_at(ExecuteInstruction::SPL_DISCRIMINATOR_SLICE.len());

    match discriminator {
        ExecuteInstruction::SPL_DISCRIMINATOR_SLICE => process_execute(accounts, rest),
        InitializeExtraAccountMetaListInstruction::SPL_DISCRIMINATOR_SLICE => {
            process_initialize_extra_account_meta_list(program_id, accounts, rest)
        }
        UpdateExtraAccountMetaListInstruction::SPL_DISCRIMINATOR_SLICE => {
            process_update_extra_account_meta_list(program_id, accounts, rest)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_execute(accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [_from, mint, _to, authority, extra_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if is_permanent_delegate_transfer(mint, authority, extra_accounts)? {
        return Ok(());
    }

    let verification_programs = load_verification_programs(mint, extra_accounts)?;

    if verification_programs.is_empty() {
        //TODO fix return Ok(());
        return Err(ProgramError::InvalidAccountData);
    }
    let amount = rest
        .get(..8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ProgramError::InvalidInstructionData)?;
    execute_verification_programs(&verification_programs, accounts, amount)?;
    Ok(())
}

fn is_permanent_delegate_transfer(
    mint: &AccountInfo,
    authority: &AccountInfo,
    extra_accounts: &[AccountInfo],
) -> Result<bool, ProgramError> {
    let (permanent_delegate_pda, _bump) = find_program_address(
        &[PERMANENT_DELEGATE_SEED, mint.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );
    // NOTE: Permanent delegate with no extra accounts means security token program call
    Ok(authority.key() == &permanent_delegate_pda && extra_accounts.is_empty())
}

fn load_verification_programs(
    mint: &AccountInfo,
    extra_accounts: &[AccountInfo],
) -> Result<Vec<[u8; 32]>, ProgramError> {
    // [0] - validate_state_pubkey (added by Token-2022)
    // [1] - verification_config_pda
    if extra_accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let verification_config = &extra_accounts[1];

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

    let seeds = &[
        VERIFICATION_CONFIG_SEED,
        mint.key().as_ref(),
        &[TRANSFER_DISCRIMINATOR],
        &[bump],
    ];

    let verification_config_pda =
        checked_create_program_address(seeds, &SECURITY_TOKEN_PROGRAM_ID)?;

    if verification_config.key() != &verification_config_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    let verification_programs_data = &config_data[8..];

    if verification_programs_data.len() % 32 != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    let verification_programs_count = verification_programs_data.len() / 32;

    // Anti CPI DDOS
    if verification_programs_count > MAX_VERIFICATION_PROGRAMS {
        return Err(ProgramError::InvalidAccountData);
    }

    verification_programs_data
        .chunks_exact(32)
        .map(|chunk| {
            chunk
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)
        })
        .collect()
}

fn execute_verification_programs(
    verification_programs: &[[u8; 32]],
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    // Build instruction data: [discriminator (1 byte) | amount (8 bytes)]
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = TRANSFER_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let verification_account_metas: Vec<pinocchio::instruction::AccountMeta> = accounts
        .iter()
        .map(|acc| pinocchio::instruction::AccountMeta {
            pubkey: acc.key(),
            is_signer: acc.is_signer(),
            is_writable: acc.is_writable(),
        })
        .collect();

    let account_refs: Vec<_> = accounts.iter().collect();

    for program_id in verification_programs.iter() {
        let verification_instruction = pinocchio::instruction::Instruction {
            program_id,
            accounts: &verification_account_metas,
            data: &instruction_data,
        };
        // Use slice_invoke to handle the future variable number of accounts
        pinocchio::program::slice_invoke(&verification_instruction, &account_refs)?;
    }
    Ok(())
}

/// Validate common account checks for extra account meta list operations
fn validate_extra_account_meta_accounts(
    program_id: &Pubkey,
    extra_meta_info: &AccountInfo,
    mint_info: &AccountInfo,
    authority_info: &AccountInfo,
) -> Result<(Pubkey, u8), ProgramError> {
    if !extra_meta_info.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (transfer_hook_pda, _bump) = find_program_address(
        &[TRANSFER_HOOK_SEED, mint_info.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    if authority_info.key() != &transfer_hook_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    if !mint_info.is_owned_by(&pinocchio_token_2022::ID) {
        return Err(ProgramError::IllegalOwner);
    }

    let (expected_pda, bump) = get_extra_account_metas_address_and_bump_seed(
        &SolanaPubkey::new_from_array(*mint_info.key()),
        &SolanaPubkey::new_from_array(*program_id),
    );

    if extra_meta_info.key() != &expected_pda.to_bytes() {
        return Err(ProgramError::InvalidSeeds);
    }

    Ok((expected_pda.to_bytes(), bump))
}

fn process_initialize_extra_account_meta_list(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    rest: &[u8],
) -> ProgramResult {
    let [extra_meta_info, mint_info, authority_info, system_program_info] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if system_program_info.key() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    if extra_meta_info.is_owned_by(program_id) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let (_expected_pda, bump) = validate_extra_account_meta_accounts(
        program_id,
        extra_meta_info,
        mint_info,
        authority_info,
    )?;

    let pod_slice = PodSlice::<ExtraAccountMeta>::unpack(rest)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let extra_account_metas = pod_slice.data().to_vec();
    let count = extra_account_metas.len();
    let account_size =
        ExtraAccountMetaList::size_of(count).map_err(|_| ProgramError::InvalidAccountData)?;

    if extra_meta_info.lamports() == 0 {
        return Err(ProgramError::AccountNotRentExempt);
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(EXTRA_ACCOUNT_METAS_SEED),
        Seed::from(mint_info.key().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    let signer = Signer::from(&seeds);

    let allocate = Allocate {
        account: extra_meta_info,
        space: account_size as u64,
    };
    allocate.invoke_signed(&[signer.clone()])?;

    let assign = Assign {
        account: extra_meta_info,
        owner: program_id,
    };
    assign.invoke_signed(&[signer])?;

    {
        let mut data = extra_meta_info.try_borrow_mut_data()?;
        ExtraAccountMetaList::init::<ExecuteInstruction>(&mut data, &extra_account_metas)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    }
    Ok(())
}

fn process_update_extra_account_meta_list(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    rest: &[u8],
) -> ProgramResult {
    let [extra_meta_info, mint_info, authority_info, rest_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !extra_meta_info.is_owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    validate_extra_account_meta_accounts(program_id, extra_meta_info, mint_info, authority_info)?;

    let pod_slice = PodSlice::<ExtraAccountMeta>::unpack(rest)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let extra_account_metas = pod_slice.data().to_vec();
    let new_count = extra_account_metas.len();

    let new_account_size =
        ExtraAccountMetaList::size_of(new_count).map_err(|_| ProgramError::InvalidAccountData)?;
    let current_account_size = extra_meta_info.data_len();

    if new_account_size > current_account_size {
        if !rest_accounts
            .iter()
            .any(|acc| acc.key() == &pinocchio_system::ID)
        {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        extra_meta_info.resize(new_account_size)?;
    }
    {
        let mut data = extra_meta_info.try_borrow_mut_data()?;
        ExtraAccountMetaList::update::<ExecuteInstruction>(&mut data, &extra_account_metas)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    } // Release borrow before realloc

    if new_account_size < current_account_size {
        let [system_program_info, recipient_info] = rest_accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        if system_program_info.key() != &pinocchio_system::ID {
            return Err(ProgramError::IncorrectProgramId);
        }

        if !recipient_info.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }

        extra_meta_info.resize(new_account_size)?;
        let current_lamports = extra_meta_info.lamports();
        let required_lamports = Rent::get()?.minimum_balance(new_account_size);
        let lamports_to_return = current_lamports.saturating_sub(required_lamports);

        if lamports_to_return > 0 {
            *extra_meta_info.try_borrow_mut_lamports()? = extra_meta_info
                .lamports()
                .checked_sub(lamports_to_return)
                .ok_or(ProgramError::InsufficientFunds)?;
            *recipient_info.try_borrow_mut_lamports()? = recipient_info
                .lamports()
                .checked_add(lamports_to_return)
                .ok_or(ProgramError::InsufficientFunds)?;
        }
    }

    Ok(())
}

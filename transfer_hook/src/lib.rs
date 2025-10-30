//! Security Token transfer hook implementation
#![allow(unexpected_cfgs)]

use pinocchio::sysvars::rent::Rent;
use pinocchio::sysvars::Sysvar;
use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
};
use pinocchio_pubkey::{declare_id, pubkey};
use pinocchio_system::instructions::Transfer;
use pinocchio_system::instructions::{Allocate, Assign};
use solana_pubkey::Pubkey as SolanaPubkey;
use spl_discriminator::SplDiscriminate;
use spl_pod::slice::PodSlice;
use spl_tlv_account_resolution::{account::ExtraAccountMeta, state::ExtraAccountMetaList};
use spl_transfer_hook_interface::{
    get_extra_account_metas_address_and_bump_seed, instruction::ExecuteInstruction,
};

pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH");
const PERMANENT_DELEGATE_SEED: &[u8] = b"mint.permanent_delegate";
const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
const VERIFICATION_CONFIG_SEED: &[u8] = b"verification_config";
const TRANSFER_DISCRIMINATOR: u8 = 12;
const TRANSFER_VERIFICATION_CONFIG_DISCRIMINATOR: u8 = 1;

// NOTE: Replace with the finalized program ID generated for the transfer hook deployment.
declare_id!("DTUuEirVJFg53cKgyTPKtVgvi5SV5DCDQpvbmdwBtYdd");

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    use spl_transfer_hook_interface::instruction::{
        ExecuteInstruction, InitializeExtraAccountMetaListInstruction,
    };

    if instruction_data.len() < ExecuteInstruction::SPL_DISCRIMINATOR_SLICE.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (discriminator, rest) =
        instruction_data.split_at(ExecuteInstruction::SPL_DISCRIMINATOR_SLICE.len());

    if discriminator == ExecuteInstruction::SPL_DISCRIMINATOR_SLICE {
        return process_execute(program_id, accounts, rest);
    }

    if discriminator == InitializeExtraAccountMetaListInstruction::SPL_DISCRIMINATOR_SLICE {
        return process_initialize_extra_account_meta_list(program_id, accounts, rest);
    }

    Err(ProgramError::InvalidInstructionData)
}

fn process_execute(_program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [_from, mint, _to, authority, extra_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let amount = rest
        .get(..8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ProgramError::InvalidInstructionData)?;

    if is_permanent_delegate_transfer(mint, authority, extra_accounts)? {
        return Ok(());
    }

    let verification_programs = load_verification_programs(mint, extra_accounts)?;

    if verification_programs.is_empty() {
        return Ok(());
    }
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

    // NOTE: Permanent delegate with no extra accounts means native SPL call
    Ok(authority.key() == &permanent_delegate_pda && extra_accounts.is_empty())
}

/// Load and parse verification programs from verification config
fn load_verification_programs(
    mint: &AccountInfo,
    extra_accounts: &[AccountInfo],
) -> Result<Vec<[u8; 32]>, ProgramError> {
    let (verification_config_pda, _bump) = find_program_address(
        &[
            VERIFICATION_CONFIG_SEED,
            mint.key().as_ref(),
            &[TRANSFER_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    let verification_config = extra_accounts
        .iter()
        .find(|acc| acc.key() == &verification_config_pda)
        .ok_or_else(|| ProgramError::InvalidSeeds)?;

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

    let verification_programs_data = &config_data[6..];
    let verification_programs_count = verification_programs_data.len() / 32;

    let mut verification_programs = Vec::with_capacity(verification_programs_count);
    for i in 0..verification_programs_count {
        let start = i * 32;
        let end = start + 32;
        let pubkey_bytes: [u8; 32] = verification_programs_data[start..end]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        verification_programs.push(pubkey_bytes);
    }
    Ok(verification_programs)
}

fn execute_verification_programs(
    verification_programs: &[[u8; 32]],
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let mut instruction_data = Vec::with_capacity(9);
    instruction_data.push(TRANSFER_DISCRIMINATOR);
    instruction_data.extend_from_slice(&amount.to_le_bytes());

    let verification_account_metas = [
        pinocchio::instruction::AccountMeta {
            pubkey: accounts[0].key(),
            is_signer: accounts[0].is_signer(),
            is_writable: accounts[0].is_writable(),
        },
        pinocchio::instruction::AccountMeta {
            pubkey: accounts[1].key(),
            is_signer: accounts[1].is_signer(),
            is_writable: accounts[1].is_writable(),
        },
        pinocchio::instruction::AccountMeta {
            pubkey: accounts[2].key(),
            is_signer: accounts[2].is_signer(),
            is_writable: accounts[2].is_writable(),
        },
        pinocchio::instruction::AccountMeta {
            pubkey: accounts[3].key(),
            is_signer: accounts[3].is_signer(),
            is_writable: accounts[3].is_writable(),
        },
    ];

    for program_id in verification_programs.iter() {
        let verification_instruction = pinocchio::instruction::Instruction {
            program_id,
            accounts: &verification_account_metas,
            data: &instruction_data,
        };

        let account_refs = [&accounts[0], &accounts[1], &accounts[2], &accounts[3]];
        pinocchio::program::invoke(&verification_instruction, &account_refs)?;
    }
    Ok(())
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

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if unsafe { *mint_info.owner() } != pinocchio_token_2022::ID {
        return Err(ProgramError::IllegalOwner);
    }

    let (expected_pda, bump) = get_extra_account_metas_address_and_bump_seed(
        &SolanaPubkey::new_from_array(*mint_info.key()),
        &SolanaPubkey::new_from_array(*program_id),
    );

    if extra_meta_info.key() != &expected_pda.to_bytes() {
        return Err(ProgramError::InvalidSeeds);
    }

    let pod_slice = PodSlice::<ExtraAccountMeta>::unpack(rest)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let extra_account_metas = pod_slice.data().to_vec();
    let count = extra_account_metas.len();
    let account_size =
        ExtraAccountMetaList::size_of(count).map_err(|_| ProgramError::InvalidAccountData)?;

    if unsafe { *extra_meta_info.owner() } != *program_id {
        if unsafe { *extra_meta_info.owner() } != pinocchio_system::ID {
            return Err(ProgramError::IllegalOwner);
        }

        let rent = Rent::get()?;
        let required_lamports = rent.minimum_balance(account_size);
        let transfer = Transfer {
            from: authority_info,
            to: extra_meta_info,
            lamports: required_lamports,
        };
        transfer.invoke()?;

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
        if extra_meta_info.data_len() != account_size {
            extra_meta_info.realloc(account_size, false)?;
        }
    } else if extra_meta_info.data_len() != account_size {
        extra_meta_info.realloc(account_size, false)?;
    }
    {
        let mut data = extra_meta_info.try_borrow_mut_data()?;
        ExtraAccountMetaList::init::<ExecuteInstruction>(&mut data, &extra_account_metas)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    }
    Ok(())
}

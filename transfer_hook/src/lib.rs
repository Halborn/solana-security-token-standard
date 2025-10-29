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
use pinocchio_log::log;
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
const TRANSFER_HOOK_SEED: &[u8] = b"mint.transfer_hook";
const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
const VERIFICATION_CONFIG_SEED: &[u8] = b"verification_config";
const TRANSFER_DISCRIMINATOR: u8 = 12;

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

    // NOTE: Check the stack height?
    log!(
        "Transfer execute called with {} extra accounts",
        extra_accounts.len()
    );

    let amount = rest
        .get(..8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ProgramError::InvalidInstructionData)?;

    let (transfer_hook_pda, _bump) = find_program_address(
        &[TRANSFER_HOOK_SEED, mint.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    if authority.key() == &transfer_hook_pda {
        log!("P2P Transfer via Transfer Hook PDA for amount {}", amount);
        return Err(ProgramError::UnsupportedSysvar);
    }

    let (permanent_delegate_pda, _bump) = find_program_address(
        &[PERMANENT_DELEGATE_SEED, mint.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    if authority.key() != &permanent_delegate_pda {
        return Err(ProgramError::IllegalOwner);
    }

    log!("Transfer execute validated for amount {}", amount);
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
        allocate.invoke_signed(&[signer])?;

        let bump_seed = [bump];
        let assign_seeds = [
            Seed::from(EXTRA_ACCOUNT_METAS_SEED),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let assign_signer = Signer::from(&assign_seeds);

        let assign = Assign {
            account: extra_meta_info,
            owner: program_id,
        };
        assign.invoke_signed(&[assign_signer])?;
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
    log!("Initialized extra account meta list with {} entries", count);
    Ok(())
}

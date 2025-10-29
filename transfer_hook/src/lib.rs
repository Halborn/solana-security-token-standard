//! Security Token transfer hook implementation
#![allow(unexpected_cfgs)]

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
use pinocchio_system::instructions::{Allocate, Assign};

// NOTE: Spl token array discriminator length
// https://github.com/solana-program/libraries/blob/main/discriminator/src/discriminator.rs
pub const ARRAY_DISCRIMINATOR_LENGTH: usize = 8;
pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH");
pub static PERMANENT_DELEGATE_SEED: &[u8] = b"mint.permanent_delegate";

// From solana-program implementation
// #[derive(SplDiscriminate)]
// #[discriminator_hash_input("spl-transfer-hook-interface:execute")
pub const TRANSFER_HOOK_EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
// #[derive(SplDiscriminate)]
// #[discriminator_hash_input("spl-transfer-hook-interface:initialize-extra-account-metas")]
pub const TRANSFER_HOOK_INITIALIZE_ACCOUNT_METAS_DISCRIMINATOR: [u8; 8] =
    [43, 34, 13, 49, 167, 88, 235, 235];

const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
const META_COUNT_LEN: usize = core::mem::size_of::<u32>();
const EXTRA_ACCOUNT_META_LEN: usize = 35;
const TLV_LENGTH_LEN: usize = core::mem::size_of::<u32>();
const TLV_HEADER_LEN: usize = ARRAY_DISCRIMINATOR_LENGTH + TLV_LENGTH_LEN;

// NOTE: Replace with the finalized program ID generated for the transfer hook deployment.
declare_id!("DTUuEirVJFg53cKgyTPKtVgvi5SV5DCDQpvbmdwBtYdd");

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < ARRAY_DISCRIMINATOR_LENGTH {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (discriminator, rest) = instruction_data.split_at(ARRAY_DISCRIMINATOR_LENGTH);

    if discriminator == TRANSFER_HOOK_EXECUTE_DISCRIMINATOR {
        return process_execute(program_id, accounts, rest);
    }

    if discriminator == TRANSFER_HOOK_INITIALIZE_ACCOUNT_METAS_DISCRIMINATOR {
        return process_initialize_extra_account_meta_list(program_id, accounts, rest);
    }

    Err(ProgramError::InvalidInstructionData)
}

fn process_execute(_program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [_from, mint, _to, authority, extra_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    log!("XXXXXXX!!!!");
    log!(
        "Transfer execute called with {} extra accounts",
        extra_accounts.len()
    );

    let amount = rest
        .get(..8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ProgramError::InvalidInstructionData)?;

    let (expected_pda, _bump) = find_program_address(
        &[b"mint.permanent_delegate", mint.key().as_ref()],
        &SECURITY_TOKEN_PROGRAM_ID,
    );

    if authority.key() != &expected_pda {
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

    if rest.len() < META_COUNT_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let count = u32::from_le_bytes(
        rest[..META_COUNT_LEN]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    ) as usize;

    let expected_payload_len = count
        .checked_mul(EXTRA_ACCOUNT_META_LEN)
        .ok_or(ProgramError::InvalidInstructionData)?
        .checked_add(META_COUNT_LEN)
        .ok_or(ProgramError::InvalidInstructionData)?;

    if expected_payload_len != rest.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if unsafe { *mint_info.owner() } != pinocchio_token_2022::ID {
        return Err(ProgramError::IllegalOwner);
    }

    let (expected_pda, bump) = find_program_address(
        &[EXTRA_ACCOUNT_METAS_SEED, mint_info.key().as_ref()],
        program_id,
    );

    if extra_meta_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let account_size = 2 * ARRAY_DISCRIMINATOR_LENGTH + TLV_LENGTH_LEN + rest.len();

    if unsafe { *extra_meta_info.owner() } != *program_id {
        if unsafe { *extra_meta_info.owner() } != pinocchio_system::ID {
            return Err(ProgramError::IllegalOwner);
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
        write_tlv_payload(&mut data, rest)?;
    }

    log!("Initialized extra account meta list with {} entries", count);

    Ok(())
}

fn write_tlv_payload(destination: &mut [u8], rest: &[u8]) -> ProgramResult {
    if destination.len() != 2 * ARRAY_DISCRIMINATOR_LENGTH + TLV_LENGTH_LEN + rest.len() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Write array discriminator at the start
    destination[..ARRAY_DISCRIMINATOR_LENGTH].copy_from_slice(&TRANSFER_HOOK_EXECUTE_DISCRIMINATOR);

    // Write TLV type (using TRANSFER_HOOK_EXECUTE_DISCRIMINATOR)
    let tlv_type_start = ARRAY_DISCRIMINATOR_LENGTH;
    destination[tlv_type_start..tlv_type_start + ARRAY_DISCRIMINATOR_LENGTH]
        .copy_from_slice(&TRANSFER_HOOK_EXECUTE_DISCRIMINATOR);

    // Write TLV length
    let length_start = tlv_type_start + ARRAY_DISCRIMINATOR_LENGTH;
    let value_length =
        u32::try_from(rest.len()).map_err(|_| ProgramError::InvalidInstructionData)?;
    destination[length_start..length_start + TLV_LENGTH_LEN]
        .copy_from_slice(&value_length.to_le_bytes());

    // Write TLV value
    let value_start = length_start + TLV_LENGTH_LEN;
    destination[value_start..value_start + rest.len()].copy_from_slice(rest);
    Ok(())
}

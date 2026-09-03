//! Security Token transfer hook implementation
#![allow(unexpected_cfgs)]

mod helpers;
mod verification;

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::{declare_id, pubkey};
use pinocchio_system::instructions::{Allocate, Assign};
use solana_pubkey::Pubkey as SolanaPubkey;
#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;
use spl_discriminator::SplDiscriminate;
use spl_pod::slice::PodSlice;
use spl_tlv_account_resolution::{account::ExtraAccountMeta, state::ExtraAccountMetaList};
use spl_transfer_hook_interface::get_extra_account_metas_address_and_bump_seed;
use spl_transfer_hook_interface::instruction::{
    ExecuteInstruction, InitializeExtraAccountMetaListInstruction,
    UpdateExtraAccountMetaListInstruction,
};
pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =
    pubkey!("SSTS8Qk2bW3aVaBEsY1Ras95YdbaaYQQx21JWHxvjap");

// Transfer Hook account seeds.
const TRANSFER_HOOK_SEED: &[u8] = b"mint.transfer_hook";
const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";

// Verification program interface.
const TRANSFER_DISCRIMINATOR: u8 = 12;
const TRANSFER_AMOUNT_LEN: usize = core::mem::size_of::<u64>();
const VERIFIER_INSTRUCTION_DATA_LEN: usize = 1 + TRANSFER_AMOUNT_LEN;

// NOTE: Replace with the finalized program ID generated for the transfer hook deployment.
declare_id!("HookXqLKgPaNrHBJ9Jui7oQZz93vMbtA88JjsLa8bmfL");

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "SSTS Security Token Transfer Hook",
    project_url: "https://ssts.org",
    contacts: "link:https://ssts.org/.well-known/security.txt",
    policy: "https://github.com/Solana-Security-Token-Standard/solana-security-token-standard/blob/main/SECURITY.md",
    source_code: "https://github.com/Solana-Security-Token-Standard/solana-security-token-standard"
}

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::entrypoint;
#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Dispatches Transfer Hook instructions to their processors.
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
        ExecuteInstruction::SPL_DISCRIMINATOR_SLICE => process_execute(program_id, accounts, rest),
        InitializeExtraAccountMetaListInstruction::SPL_DISCRIMINATOR_SLICE => {
            process_initialize_extra_account_meta_list(program_id, accounts, rest)
        }
        UpdateExtraAccountMetaListInstruction::SPL_DISCRIMINATOR_SLICE => {
            process_update_extra_account_meta_list(program_id, accounts, rest)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Processes a Token-2022 Transfer Hook execution.
fn process_execute(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [source, mint, destination, authority, remaining @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Forced transfers originate in Core and intentionally invoke the hook without discovery
    // accounts; Core already ran the configured verifiers for that operation.
    if helpers::is_permanent_delegate_transfer(mint, authority, remaining)? {
        return Ok(());
    }

    helpers::validate_transferring_token_account(source, mint)?;
    helpers::validate_transferring_token_account(destination, mint)?;

    let [meta_list, verification_config, routing_accounts @ ..] = remaining else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if rest.len() != TRANSFER_AMOUNT_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        rest.try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let mut verifier_instruction_data = [0u8; VERIFIER_INSTRUCTION_DATA_LEN];
    verifier_instruction_data[0] = TRANSFER_DISCRIMINATOR;
    verifier_instruction_data[1..].copy_from_slice(&amount.to_le_bytes());

    let canonical_accounts = [source, mint, destination, authority];
    verification::verify_transfer(
        program_id,
        mint,
        meta_list,
        verification_config,
        routing_accounts,
        &canonical_accounts,
        &verifier_instruction_data,
    )
}

/// Validates accounts shared by ExtraAccountMetaList lifecycle instructions.
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

/// Initializes the ExtraAccountMetaList used by Token-2022 account discovery.
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

    let minimum_balance = Rent::get()?.minimum_balance(account_size);
    if extra_meta_info.lamports() < minimum_balance {
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

/// Updates and resizes the ExtraAccountMetaList used by Token-2022.
fn process_update_extra_account_meta_list(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    rest: &[u8],
) -> ProgramResult {
    let [extra_meta_info, mint_info, authority_info, system_program_info, recipient_info] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !extra_meta_info.is_owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    validate_extra_account_meta_accounts(program_id, extra_meta_info, mint_info, authority_info)?;
    if system_program_info.key() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !recipient_info.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    let pod_slice = PodSlice::<ExtraAccountMeta>::unpack(rest)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let extra_account_metas = pod_slice.data().to_vec();
    let new_count = extra_account_metas.len();

    let new_account_size =
        ExtraAccountMetaList::size_of(new_count).map_err(|_| ProgramError::InvalidAccountData)?;
    let current_account_size = extra_meta_info.data_len();
    let rent = Rent::get()?;
    let current_minimum_balance = rent.minimum_balance(current_account_size);
    let new_minimum_balance = rent.minimum_balance(new_account_size);
    if extra_meta_info.lamports() < new_minimum_balance {
        return Err(ProgramError::AccountNotRentExempt);
    }

    if new_account_size > current_account_size {
        extra_meta_info.resize(new_account_size)?;
    }
    {
        let mut data = extra_meta_info.try_borrow_mut_data()?;
        ExtraAccountMetaList::update::<ExecuteInstruction>(&mut data, &extra_account_metas)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    } // Release borrow before realloc

    if new_account_size < current_account_size {
        extra_meta_info.resize(new_account_size)?;
        let current_lamports = extra_meta_info.lamports();
        // Return only the reduction in the rent minimum; preserve any pre-existing surplus.
        let rent_delta = current_minimum_balance.saturating_sub(new_minimum_balance);
        let refundable_balance = current_lamports.saturating_sub(new_minimum_balance);
        let lamports_to_return = rent_delta.min(refundable_balance);

        if lamports_to_return > 0 {
            *extra_meta_info.try_borrow_mut_lamports()? = current_lamports
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

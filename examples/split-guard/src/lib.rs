//! Split Guard Verification Program
//!
//! ## Problem
//!
//! Split adjusts token balances in-place without consuming them. A holder can transfer
//! their tokens to another account after splitting and split again, amplifying supply
//! indefinitely. Since mints and burns do not go through the transfer hook, only transfers
//! can be gated without interfering with the Split operation itself.
//!
//! ## Mechanism
//!
//! A "split guard" PDA account acts as a circuit breaker. The verification program is
//! registered in the Transfer VerificationConfig. During each transfer it checks whether
//! the split guard account for the mint is initialized:
//!
//! - Guard exists -> transfer rejected
//! - Guard absent -> transfer allowed
//!
//! The issuer creates the guard before initiating Split and closes it after all holders
//! have been processed, restoring normal trading.
//!
//! ## Lifecycle
//!
//! 1. Register this program in the Transfer VerificationConfig
//! 2. Register `split_guard_pda` as a PDA-based extra account in Token-2022
//!    ExtraAccountMetaList (seeds: ["split_guard", mint], owner: this program)
//! 3. Issue `ActivateHalt` → creates the guard account, blocks all transfers
//! 4. Execute Split for all holders (mints/burns are unaffected by the halt)
//! 5. Issue `DeactivateHalt` → closes the guard account, transfers resume

#![allow(unexpected_cfgs)]

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{checked_create_program_address, find_program_address, Pubkey, PUBKEY_BYTES},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_log::log;
use pinocchio_pubkey::{declare_id, pubkey};
use pinocchio_system::instructions::CreateAccount;

// Replace with the actual program ID generated
declare_id!("SGuard1111111111111111111111111111111111111");

/// SSTS MintAuthority account: [discriminator(1), mint(32), mint_creator(32), bump(1)].
/// Seeds: ["mint.authority", mint, mint_creator]. Owner: SSTS program.
const SSTS_PROGRAM_ID: Pubkey = pubkey!("SSTS8Qk2bW3aVaBEsY1Ras95YdbaaYQQx21JWHxvjap");
const SSTS_MINT_AUTHORITY_SEED: &[u8] = b"mint.authority";
const SSTS_MINT_AUTHORITY_LEN: usize = 1 + PUBKEY_BYTES + PUBKEY_BYTES + 1;

/// PDA seed for the split guard account: ["split_guard", mint]
const SPLIT_GUARD_SEED: &[u8] = b"split_guard";

/// Split guard account data: stores the authority pubkey (32 bytes).
/// Presence of this account with this length, owned by this program = halt active.
const SPLIT_GUARD_LEN: usize = 32;

/// Transfer discriminator from the Security Token Program (matches TRANSFER_DISCRIMINATOR).
const TRANSFER_DISCRIMINATOR: u8 = 12;

/// This program's own instruction discriminators.
const ACTIVATE_HALT_DISCRIMINATOR: u8 = 0;
const DEACTIVATE_HALT_DISCRIMINATOR: u8 = 1;

/// Custom error: transfers are halted because a Split operation is in progress.
pub const ERR_SPLIT_HALT_ACTIVE: u32 = 0;

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::entrypoint;
#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Program entry point.
///
/// Routes to the appropriate handler based on the first byte of instruction_data:
/// - `0` (ActivateHalt): creates the split guard PDA, blocking all transfers
/// - `1` (DeactivateHalt): closes the split guard PDA, restoring transfers
/// - `12` (Transfer): checks whether a halt is active and rejects if so
/// - anything else: passes through (Ok) - this program only enforces transfer restrictions
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let discriminator = *instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let args_data = &instruction_data[1..];

    match discriminator {
        ACTIVATE_HALT_DISCRIMINATOR => activate_halt(program_id, accounts),
        DEACTIVATE_HALT_DISCRIMINATOR => deactivate_halt(program_id, accounts),
        TRANSFER_DISCRIMINATOR => verify_transfer(program_id, accounts, args_data),
        _ => Ok(()),
    }
}

/// Activate the transfer halt for a mint.
///
/// Creates the split guard PDA account. The caller becomes the authority that can
/// later deactivate the halt. Only the SSTS mint creator may activate the halt,
/// verified via the SSTS MintAuthority PDA. Fails if the halt is already active.
///
/// Accounts:
///   0. `[signer, writable]` authority - must match the mint_creator in ssts_mint_authority
///   1. `[]`                  mint - the protected security token mint
///   2. `[writable]`          split_guard_pda - PDA ["split_guard", mint]; must not exist
///   3. `[]`                  ssts_mint_authority - SSTS MintAuthority PDA for this mint
///   4. `[]`                  system_program
fn activate_halt(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [authority, mint, split_guard_pda, ssts_mint_authority, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if system_program.key() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if split_guard_pda.data_len() > 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Only the SSTS mint creator may activate — prevents griefing by arbitrary signers.
    {
        if !ssts_mint_authority.is_owned_by(&SSTS_PROGRAM_ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let ma_data = ssts_mint_authority.try_borrow_data()?;
        if ma_data.len() != SSTS_MINT_AUTHORITY_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut offset = 1; // skip discriminator

        let stored_mint: Pubkey = ma_data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += PUBKEY_BYTES;
        if &stored_mint != mint.key() {
            return Err(ProgramError::InvalidArgument);
        }

        let mint_creator: Pubkey = ma_data[offset..offset + PUBKEY_BYTES]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        offset += PUBKEY_BYTES;
        if authority.key() != &mint_creator {
            return Err(ProgramError::InvalidArgument);
        }

        let bump = ma_data[offset];
        let expected_ma_pda = checked_create_program_address(
            &[
                SSTS_MINT_AUTHORITY_SEED,
                mint.key().as_ref(),
                mint_creator.as_ref(),
                &[bump],
            ],
            &SSTS_PROGRAM_ID,
        )?;
        if ssts_mint_authority.key() != &expected_ma_pda {
            return Err(ProgramError::InvalidSeeds);
        }
    }

    let (expected_pda, bump) =
        find_program_address(&[SPLIT_GUARD_SEED, mint.key().as_ref()], program_id);

    if split_guard_pda.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let lamports = Rent::get()?.minimum_balance(SPLIT_GUARD_LEN);
    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(SPLIT_GUARD_SEED),
        Seed::from(mint.key().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    let signer = [Signer::from(&signer_seeds)];

    CreateAccount {
        from: authority,
        to: split_guard_pda,
        lamports,
        space: SPLIT_GUARD_LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    // Store authority so only they can deactivate the halt.
    let mut data = split_guard_pda.try_borrow_mut_data()?;
    data.copy_from_slice(authority.key().as_ref());

    log!("Split halt activated for mint {}", mint.key());

    Ok(())
}

/// Deactivate the transfer halt for a mint.
///
/// Closes the split guard PDA account, restoring normal transfers.
/// Only the authority that activated the halt can deactivate it.
///
/// Accounts:
///   0. `[signer]`   authority - must match the authority stored in split_guard_pda
///   1. `[]`         mint - the protected security token mint (used to verify PDA seeds)
///   2. `[writable]` split_guard_pda - PDA ["split_guard", mint]
///   3. `[writable]` destination - receives the reclaimed rent lamports
fn deactivate_halt(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [authority, mint, split_guard_pda, destination] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if destination.key() == split_guard_pda.key() {
        return Err(ProgramError::InvalidArgument);
    }

    if split_guard_pda.data_len() != SPLIT_GUARD_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if !split_guard_pda.is_owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Verify the caller is the stored authority.
    let stored_authority: Pubkey = {
        let data = split_guard_pda.try_borrow_data()?;
        data[..SPLIT_GUARD_LEN]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?
    };
    if authority.key() != &stored_authority {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify PDA seeds match the provided mint.
    let (expected_pda, _) =
        find_program_address(&[SPLIT_GUARD_SEED, mint.key().as_ref()], program_id);
    if split_guard_pda.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Transfer all lamports to destination, then close the account.
    {
        let mut guard_lamports = split_guard_pda.try_borrow_mut_lamports()?;
        let lamports = *guard_lamports;
        *guard_lamports = 0;
        *destination.try_borrow_mut_lamports()? = destination
            .lamports()
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    split_guard_pda.resize(0)?;

    log!("Split halt deactivated");

    Ok(())
}

/// Verify a token transfer (introspection mode).
///
/// In introspection mode this instruction is placed explicitly before the Security
/// Token Transfer in the same transaction. The Security Token program then confirms
/// via the instructions sysvar that this instruction was executed with matching
/// accounts and data. Checks whether the split guard account is active for this
/// mint and rejects if so.
///
/// In CPI mode this would instead be invoked directly by the transfer hook.
///
/// Accounts must be a prefix of the Transfer instruction accounts after the
/// INSTRUCTION_ACCOUNTS_OFFSET (i.e. skipping [mint, verification_config,
/// instructions_sysvar]). split_guard_pda is appended as an extra account.
///
///   0. `[]` permanent_delegate_authority
///   1. `[]` mint
///   2. `[]` from_token_account
///   3. `[]` to_token_account
///   4. `[]` transfer_hook_program
///   5. `[]` token_program
///   6. `[]` split_guard_pda - PDA ["split_guard", mint]; checked for existence
///
/// Instruction data: amount (u64 LE, 8 bytes)
fn verify_transfer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let [_permanent_delegate_authority, mint, _from_token_account, _to_token_account, _transfer_hook_program, _token_program, split_guard_pda] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        instruction_data[..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Verify the account is actually the expected PDA, not an arbitrary same-owner account.
    let (expected_pda, _) =
        find_program_address(&[SPLIT_GUARD_SEED, mint.key().as_ref()], program_id);
    if split_guard_pda.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Halt is active when the split guard account is initialized and owned by this program.
    let halt_active =
        split_guard_pda.data_len() == SPLIT_GUARD_LEN && split_guard_pda.is_owned_by(program_id);

    if halt_active {
        log!("Transfer of {} rejected: split halt is active", amount);
        return Err(ProgramError::Custom(ERR_SPLIT_HALT_ACTIVE));
    }

    Ok(())
}

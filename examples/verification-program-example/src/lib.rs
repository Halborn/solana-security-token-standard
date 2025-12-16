//! Example Verification Program
//!
//! This program demonstrates how to implement a verification program that integrates
//! with the Security Token Program. It shows the account layout and argument parsing
//! for all supported operations.
//!
//! ## Architecture
//!
//! The Security Token Program supports two verification modes:
//!
//! ### CPI Mode (cpi_mode: true)
//! - Security Token makes CPI calls to verification programs
//! - Same accounts and instruction_data are passed via CPI
//! - Verification programs listed in VerificationConfig are called automatically
//!
//! ### Introspection Mode (cpi_mode: false)
//! - Verification programs must be called BEFORE the main operation
//! - Security Token checks Instructions Sysvar to verify the calls were made
//! - Must use identical accounts (except the verification overhead) and instruction_data as the main operation
//!
//! ## Implementation Guide
//!
//! Each operation handler demonstrates:
//! 1. Account destructuring (using array pattern matching)
//! 2. Argument parsing from instruction_data
//! 3. Where to add custom validation logic
//!
//! Use this as a template to implement your own verification logic
//! (KYC checks, compliance rules, rate limits, etc.)

use borsh::BorshDeserialize;
use pinocchio::{
    account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_log::log;

// Import argument types from the Rust client for complex argument parsing
use security_token_client::types::{
    CloseRateArgs, ConvertArgs, CreateRateArgs, InitializeVerificationConfigArgs, SplitArgs,
    TrimVerificationConfigArgs, UpdateMetadataArgs, UpdateRateArgs, UpdateVerificationConfigArgs,
};

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Program entry point
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // First byte is the operation discriminator
    let discriminator = *instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let args_data = &instruction_data[1..];

    // Route to appropriate handler based on operation type
    match discriminator {
        security_token_client::instructions::UPDATE_METADATA_DISCRIMINATOR => {
            verify_update_metadata(accounts, args_data)
        }
        security_token_client::instructions::INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR => {
            verify_initialize_verification_config(accounts, args_data)
        }
        security_token_client::instructions::UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR => {
            verify_update_verification_config(accounts, args_data)
        }
        security_token_client::instructions::TRIM_VERIFICATION_CONFIG_DISCRIMINATOR => {
            verify_trim_verification_config(accounts, args_data)
        }
        security_token_client::instructions::MINT_DISCRIMINATOR => verify_mint(accounts, args_data),
        security_token_client::instructions::BURN_DISCRIMINATOR => verify_burn(accounts, args_data),
        security_token_client::instructions::PAUSE_DISCRIMINATOR => {
            verify_pause(accounts, args_data)
        }
        security_token_client::instructions::RESUME_DISCRIMINATOR => {
            verify_resume(accounts, args_data)
        }
        security_token_client::instructions::FREEZE_DISCRIMINATOR => {
            verify_freeze(accounts, args_data)
        }
        security_token_client::instructions::THAW_DISCRIMINATOR => verify_thaw(accounts, args_data),
        security_token_client::instructions::TRANSFER_DISCRIMINATOR => {
            verify_transfer(accounts, args_data)
        }
        security_token_client::instructions::CREATE_RATE_ACCOUNT_DISCRIMINATOR => {
            verify_create_rate_account(accounts, args_data)
        }
        security_token_client::instructions::UPDATE_RATE_ACCOUNT_DISCRIMINATOR => {
            verify_update_rate_account(accounts, args_data)
        }
        security_token_client::instructions::CLOSE_RATE_ACCOUNT_DISCRIMINATOR => {
            verify_close_rate_account(accounts, args_data)
        }
        security_token_client::instructions::SPLIT_DISCRIMINATOR => {
            verify_split(accounts, args_data)
        }
        security_token_client::instructions::CONVERT_DISCRIMINATOR => {
            verify_convert(accounts, args_data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Verify UpdateMetadata operation
///
/// Instruction data: [UpdateMetadataArgs (serialized)]
///
/// Note: Complex args are serialized. You can either:
/// - Use types from security_token_client (shown here)
/// - Parse bytes manually (see program/src/instructions/*.rs for examples)
fn verify_update_metadata(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [mint_authority, payer, mint, token_program, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = UpdateMetadataArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Your validation logic here
    Ok(())
}

/// Verify InitializeVerificationConfig operation
///
/// Instruction data: [InitializeVerificationConfigArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
/// Note: transfer_hook_accounts are only present when discriminator == Transfer (12)
fn verify_initialize_verification_config(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Destructure accounts (transfer_hook_accounts @ .. only for Transfer discriminator)
    let [payer, mint_account, config_account, system_program, transfer_hook_accounts @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = InitializeVerificationConfigArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "InitializeVerificationConfig verification: cpi_mode={}",
        args.cpi_mode
    );

    // Your validation logic here

    Ok(())
}

/// Verify UpdateVerificationConfig operation
///
/// Instruction data: [UpdateVerificationConfigArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
/// Note: transfer_hook_accounts are only present when discriminator == Transfer (12)
fn verify_update_verification_config(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Destructure accounts (transfer_hook_accounts @ .. only for Transfer discriminator)
    let [payer, mint_account, config_account, system_program, transfer_hook_accounts @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = UpdateVerificationConfigArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "UpdateVerificationConfig verification: cpi_mode={}",
        args.cpi_mode
    );

    // Your validation logic here

    Ok(())
}

/// Verify TrimVerificationConfig operation
///
/// Instruction data: [TrimVerificationConfigArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
/// Note: transfer_hook_accounts are only present when discriminator == Transfer (12)
fn verify_trim_verification_config(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Destructure accounts (transfer_hook_accounts @ .. only for Transfer discriminator)
    let [mint_account, config_account, recipient, system_program, transfer_hook_accounts @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = TrimVerificationConfigArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Your validation logic here
    Ok(())
}

/// Verify Mint operation
///
/// Instruction data: [amount: u64]
fn verify_mint(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [mint_authority, mint, destination_account, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    log!(
        "Mint verification: amount={}, destination={}",
        amount,
        destination_account.key()
    );

    // Your validation logic here
    Ok(())
}

/// Verify Burn operation
///
/// Instruction data: [amount: u64]
fn verify_burn(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [permanent_delegate_authority, mint, token_account, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    log!(
        "Burn verification: amount={}, source={}",
        amount,
        token_account.key()
    );

    // Your validation logic here
    Ok(())
}

/// Verify Transfer operation
///
/// Instruction data: [amount: u64]
fn verify_transfer(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [permanent_delegate_authority, mint, from_token_account, to_token_account, transfer_hook_program, token_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    log!(
        "Transfer verification: amount={}, from={}, to={}",
        amount,
        from_token_account.key(),
        to_token_account.key()
    );

    // Your validation logic here
    Ok(())
}

/// Verify Pause operation
///
/// Instruction data: []
fn verify_pause(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [pause_authority, mint, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Pause verification: mint={}", mint.key());

    // Your validation logic here
    Ok(())
}

/// Verify Resume operation
///
/// Instruction data: []
fn verify_resume(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [pause_authority, mint, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Resume verification: mint={}", mint.key());

    // Your validation logic here
    Ok(())
}

/// Verify Freeze operation
///
/// Instruction data: []
fn verify_freeze(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [freeze_authority, mint, token_account, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Freeze verification: target={}", token_account.key());

    // Your validation logic here
    Ok(())
}

/// Verify Thaw operation
///
/// Instruction data: []
fn verify_thaw(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [freeze_authority, mint, token_account, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Thaw verification: target={}", token_account.key());
    // Your validation logic here
    Ok(())
}

/// Verify CreateRateAccount operation
///
/// Instruction data: [CreateRateArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
fn verify_create_rate_account(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [payer, rate_account, mint_from_account, mint_to_account, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = CreateRateArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "CreateRateAccount verification: action_id={}, rate={}/{}",
        args.action_id,
        args.rate.numerator,
        args.rate.denominator
    );

    // Your validation logic here
    Ok(())
}

/// Verify UpdateRateAccount operation
///
/// Instruction data: [UpdateRateArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
fn verify_update_rate_account(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [rate_account, mint_from_account, mint_to_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = UpdateRateArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "UpdateRateAccount verification: action_id={}, rate={}/{}",
        args.action_id,
        args.rate.numerator,
        args.rate.denominator
    );

    // Your validation logic here
    Ok(())
}

/// Verify CloseRateAccount operation
///
/// Instruction data: [CloseRateArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
fn verify_close_rate_account(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [rate_account, destination_account, mint_from_account, mint_to_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = CloseRateArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "CloseRateAccount verification: action_id={}",
        args.action_id
    );

    // Your validation logic here

    Ok(())
}

/// Verify Split operation
///
/// Instruction data: [SplitArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
fn verify_split(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [mint_authority, permanent_delegate, payer, mint_account, token_account, rate_account, receipt_account, token_program, system_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = SplitArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "Split verification: action_id={}, token_account={}",
        args.action_id,
        token_account.key()
    );
    // Your validation logic here
    Ok(())
}

/// Verify Convert operation
///
/// Instruction data: [ConvertArgs (serialized)]
///
/// Note: You can parse manually instead of using client types - see program/src/instructions/*.rs
fn verify_convert(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [mint_authority, permanent_delegate, payer, mint_from_account, mint_to_account, token_account_from, token_account_to, rate_account, receipt_account, token_program, system_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // Parse args using types from security_token_client
    let args = ConvertArgs::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "Convert verification: action_id={}, amount={}, from={}, to={}",
        args.action_id,
        args.amount_to_convert,
        token_account_from.key(),
        token_account_to.key()
    );
    // Your validation logic here
    Ok(())
}

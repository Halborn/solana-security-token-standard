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
//! - Must use identical accounts and instruction_data as the main operation
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

/// Operation discriminators from Security Token Program
pub mod discriminators {
    pub const UPDATE_METADATA: u8 = 1;
    pub const INITIALIZE_VERIFICATION_CONFIG: u8 = 2;
    pub const UPDATE_VERIFICATION_CONFIG: u8 = 3;
    pub const TRIM_VERIFICATION_CONFIG: u8 = 4;
    pub const MINT: u8 = 6;
    pub const BURN: u8 = 7;
    pub const PAUSE: u8 = 8;
    pub const RESUME: u8 = 9;
    pub const FREEZE: u8 = 10;
    pub const THAW: u8 = 11;
    pub const TRANSFER: u8 = 12;
    pub const CREATE_RATE_ACCOUNT: u8 = 13;
    pub const UPDATE_RATE_ACCOUNT: u8 = 14;
    pub const CLOSE_RATE_ACCOUNT: u8 = 15;
    pub const SPLIT: u8 = 16;
    pub const CONVERT: u8 = 17;
}

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
        discriminators::UPDATE_METADATA => verify_update_metadata(accounts, args_data),
        discriminators::INITIALIZE_VERIFICATION_CONFIG => {
            verify_initialize_verification_config(accounts, args_data)
        }
        discriminators::UPDATE_VERIFICATION_CONFIG => {
            verify_update_verification_config(accounts, args_data)
        }
        discriminators::TRIM_VERIFICATION_CONFIG => {
            verify_trim_verification_config(accounts, args_data)
        }
        discriminators::MINT => verify_mint(accounts, args_data),
        discriminators::BURN => verify_burn(accounts, args_data),
        discriminators::PAUSE => verify_pause(accounts, args_data),
        discriminators::RESUME => verify_resume(accounts, args_data),
        discriminators::FREEZE => verify_freeze(accounts, args_data),
        discriminators::THAW => verify_thaw(accounts, args_data),
        discriminators::TRANSFER => verify_transfer(accounts, args_data),
        discriminators::CREATE_RATE_ACCOUNT => verify_create_rate_account(accounts, args_data),
        discriminators::UPDATE_RATE_ACCOUNT => verify_update_rate_account(accounts, args_data),
        discriminators::CLOSE_RATE_ACCOUNT => verify_close_rate_account(accounts, args_data),
        discriminators::SPLIT => verify_split(accounts, args_data),
        discriminators::CONVERT => verify_convert(accounts, args_data),
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
    let [mint_authority, payer, mint_info, token_program_info, system_program_info] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<UpdateMetadataArgs>(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "UpdateMetadata verification: name={}, symbol={}, uri={}",
        args.metadata.name,
        args.metadata.symbol,
        args.metadata.uri
    );

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
    let [payer, mint_account, config_account, system_program_info, transfer_hook_accounts @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<InitializeVerificationConfigArgs>(instruction_data)
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
    let [payer, mint_account, config_account, system_program_info, transfer_hook_accounts @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<UpdateVerificationConfigArgs>(instruction_data)
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
    let [mint_account, config_account, recipient, system_program_info, transfer_hook_accounts @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<TrimVerificationConfigArgs>(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "TrimVerificationConfig verification: discriminators_count={}",
        args.discriminators.len()
    );

    // Your validation logic here

    Ok(())
}

/// Verify Mint operation
///
/// Instruction data: [amount: u64]
fn verify_mint(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [mint_authority, mint_info, destination_account_info, token_program] = accounts else {
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
        destination_account_info.key
    );

    // Your validation logic here
    Ok(())
}

/// Verify Burn operation
///
/// Instruction data: [amount: u64]
fn verify_burn(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [permanent_delegate_authority, mint_info, token_account, token_program] = accounts else {
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
        token_account.key
    );

    // Your validation logic here
    Ok(())
}

/// Verify Transfer operation
///
/// Instruction data: [amount: u64]
fn verify_transfer(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [permanent_delegate_authority, mint_info, from_token_account, to_token_account, transfer_hook_program, token_program] =
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
        from_token_account.key,
        to_token_account.key
    );

    // Your validation logic here
    Ok(())
}

/// Verify Pause operation
///
/// Instruction data: []
fn verify_pause(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [pause_authority, mint_info, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Pause verification: mint={}", mint_info.key);

    // Your validation logic here
    Ok(())
}

/// Verify Resume operation
///
/// Instruction data: []
fn verify_resume(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [pause_authority, mint_info, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Resume verification: mint={}", mint_info.key);

    // Your validation logic here
    Ok(())
}

/// Verify Freeze operation
///
/// Instruction data: []
fn verify_freeze(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [freeze_authority, mint_info, token_account, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Freeze verification: target={}", token_account.key);

    // Your validation logic here
    Ok(())
}

/// Verify Thaw operation
///
/// Instruction data: []
fn verify_thaw(accounts: &[AccountInfo], _instruction_data: &[u8]) -> ProgramResult {
    // Destructure accounts
    let [freeze_authority, mint_info, token_account, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    log!("Thaw verification: target={}", token_account.key);
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
    let [payer, rate_account, mint_from_account, mint_to_account, system_program_info] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<CreateRateArgs>(instruction_data)
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
    let [rate_account_info, mint_from_account, mint_to_info_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<UpdateRateArgs>(instruction_data)
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
    let [rate_account_info, destination_account, mint_from_account, mint_to_info_account] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse args using types from security_token_client
    let args = borsh::from_slice::<CloseRateArgs>(instruction_data)
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
    let args = borsh::from_slice::<SplitArgs>(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "Split verification: action_id={}, token_account={}",
        args.action_id,
        token_account.key
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
    let args = borsh::from_slice::<ConvertArgs>(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    log!(
        "Convert verification: action_id={}, amount={}, from={}, to={}",
        args.action_id,
        args.amount_to_convert,
        token_account_from.key,
        token_account_to.key
    );
    // Your validation logic here
    Ok(())
}

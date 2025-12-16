//! Operations Module
//!
//! Executes token operations after successful verification.
//! All operations are wrappers around SPL Token 2022 instructions.

use crate::constants::seeds;
use crate::debug_log;
use crate::instructions::TransferCheckedWithHook;
use crate::modules::{
    burn_checked, mint_to_checked, verify_account_initialized, verify_account_not_initialized,
    verify_mint_keys_match, verify_owner, verify_pda_keys_match, verify_signer,
    verify_system_program, verify_token22_program, verify_transfer_hook_program, verify_writable,
};
use crate::state::{MintAuthority, ProgramAccount, Rate, Receipt, Rounding};
use crate::token22_extensions::pausable::{Pause, Resume};
use crate::utils::{
    find_freeze_authority_pda, find_pause_authority_pda, find_permanent_delegate_pda,
    find_rate_pda, find_receipt_pda,
};
use core::cmp::Ordering;
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
use pinocchio_token_2022::instructions::{FreezeAccount, ThawAccount};
use pinocchio_token_2022::state::{Mint, TokenAccount};

/// Operations Module - executes token operations
pub struct OperationsModule;

impl OperationsModule {
    /// Mint tokens to an account
    /// Wrapper for SPL Token MintToChecked instruction
    ///
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_mint(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [mint_authority, mint_info, destination_account_info, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;

        verify_token22_program(token_program)?;
        verify_owner(mint_authority, program_id)?;
        verify_writable(mint_info)?;
        verify_writable(destination_account_info)?;

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        let mint_authority_state = MintAuthority::from_account_info(mint_authority)?;

        if mint_authority_state.mint != *mint_info.key() {
            return Err(ProgramError::InvalidAccountData);
        }

        mint_to_checked(
            amount,
            decimals,
            mint_info,
            destination_account_info,
            mint_authority,
            &mint_authority_state,
        )?;

        Ok(())
    }

    /// Burn tokens from an account  
    /// Wrapper for SPL Token BurnChecked instruction
    ///
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_burn(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [permanent_delegate_authority, mint_info, token_account, token_program] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_writable(mint_info)?;
        verify_writable(token_account)?;

        let (permanent_delegate_pda, bump) =
            crate::utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        verify_pda_keys_match(permanent_delegate_authority.key(), &permanent_delegate_pda)?;

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        burn_checked(
            amount,
            decimals,
            mint_info,
            token_account,
            permanent_delegate_authority,
            bump,
        )?;

        Ok(())
    }

    /// Pause all activity within a mint
    /// Wrapper for SPL Token Pause instruction
    ///
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_pause(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [pause_authority, mint_info, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_writable(mint_info)?;

        let (pause_authority_pda, bump) = find_pause_authority_pda(mint_info.key(), program_id);
        verify_pda_keys_match(pause_authority.key(), &pause_authority_pda)?;

        let pause_instruction = Pause {
            mint: mint_info,
            pause_authority,
        };
        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::PAUSE_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];

        let pause_authority_signer = Signer::from(&seeds);
        pause_instruction.invoke_signed(&[pause_authority_signer])?;

        Ok(())
    }

    /// Resume all activity within a mint
    /// Wrapper for SPL Token Resume instruction
    ///
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_resume(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [pause_authority, mint_info, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_writable(mint_info)?;

        let (pause_authority_pda, bump) = find_pause_authority_pda(mint_info.key(), program_id);
        verify_pda_keys_match(pause_authority.key(), &pause_authority_pda)?;

        let resume_instruction = Resume {
            mint: mint_info,
            pause_authority,
        };
        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::PAUSE_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];

        let resume_authority_signer = Signer::from(&seeds);
        resume_instruction.invoke_signed(&[resume_authority_signer])?;

        Ok(())
    }

    /// Freeze a token account
    /// Wrapper for SPL Token FreezeAccount instruction
    ///
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_freeze_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [freeze_authority, mint_info, token_account, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_writable(token_account)?;

        let (freeze_authority_pda, bump) = find_freeze_authority_pda(mint_info.key(), program_id);
        verify_pda_keys_match(freeze_authority.key(), &freeze_authority_pda)?;
        let freeze_instruction = FreezeAccount {
            account: token_account,
            mint: mint_info,
            freeze_authority,
            token_program: token_program.key(),
        };
        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::FREEZE_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];

        let freeze_authority_signer = Signer::from(&seeds);
        freeze_instruction.invoke_signed(&[freeze_authority_signer])?;
        Ok(())
    }

    /// Thaw a token account
    /// Wrapper for SPL Token ThawAccount instruction
    ///
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_thaw_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [freeze_authority, mint_info, token_account, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_writable(token_account)?;

        let (freeze_authority_pda, bump) = find_freeze_authority_pda(mint_info.key(), program_id);
        verify_pda_keys_match(freeze_authority.key(), &freeze_authority_pda)?;
        let thaw_instruction = ThawAccount {
            account: token_account,
            mint: mint_info,
            freeze_authority,
            token_program: token_program.key(),
        };
        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::FREEZE_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];

        let thaw_authority_signer = Signer::from(&seeds);
        thaw_instruction.invoke_signed(&[thaw_authority_signer])?;
        Ok(())
    }

    /// Transfer tokens between accounts
    /// Wrapper for SPL Token TransferChecked instruction
    pub fn execute_transfer(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [permanent_delegate_authority, mint_info, from_token_account, to_token_account, transfer_hook_program, token_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_transfer_hook_program(transfer_hook_program)?;
        verify_writable(from_token_account)?;
        verify_writable(to_token_account)?;

        let (permanent_delegate_pda, bump) =
            crate::utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        verify_pda_keys_match(permanent_delegate_authority.key(), &permanent_delegate_pda)?;

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        let transfer_instruction = TransferCheckedWithHook {
            mint: mint_info,
            from: from_token_account,
            to: to_token_account,
            authority: permanent_delegate_authority,
            amount,
            decimals,
            transfer_hook_program,
        };

        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::PERMANENT_DELEGATE),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let permanent_delegate_signer = Signer::from(&seeds);
        transfer_instruction.invoke_signed(&[permanent_delegate_signer])?;
        Ok(())
    }

    /// Claim distribution (dividends/coupons)
    pub fn execute_claim_distribution(
        _accounts: &[AccountInfo],
        _amount: u64,
        _action_id: u64,
        _merkle_root: &[u8],
        _merkle_proof: &[Vec<u8>],
    ) -> ProgramResult {
        // TODO: Verify merkle proof
        // TODO: Create Receipt account
        // TODO: If escrow provided, transfer distribution
        Ok(())
    }

    /// Create escrow for distributions
    pub fn execute_create_distribution_escrow(
        _accounts: &[AccountInfo],
        _action_id: u64,
        _merkle_proof: &[u8],
    ) -> ProgramResult {
        // TODO: Create escrow token account with PDA authority
        Ok(())
    }

    /// Create Rate account
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_create_rate_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        numerator: u8,
        denominator: u8,
        rounding: u8,
    ) -> ProgramResult {
        let [payer, rate_account, mint_from_account, mint_to_account, system_program_info] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Ensure Rate account is being created for target mint_to account
        // For Split operation mint_from == mint_to
        // For Convert operation mint_to is verified so we ensure correct minting of new tokens
        verify_mint_keys_match(verified_mint_info, &mint_to_account)?;

        verify_system_program(system_program_info)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_writable(rate_account)?;
        verify_account_not_initialized(rate_account)?;

        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_account.key();

        let (expected_rate_pda, bump) =
            find_rate_pda(action_id, mint_from_key, mint_to_key, program_id);

        verify_pda_keys_match(rate_account.key(), &expected_rate_pda)?;

        // Calculate rent and create Rate account
        let rounding_enum = Rounding::try_from(rounding)?;
        let rate = Rate::new(rounding_enum, numerator, denominator, bump)?;
        let action_id_seed = &action_id.to_le_bytes();
        let bump_seed = &rate.bump_seed();
        let seeds = rate.seeds(action_id_seed, mint_from_key, mint_to_key, bump_seed);
        rate.init(payer, rate_account, &seeds)?;
        rate.write_data(rate_account)?;
        Ok(())
    }

    /// Update Rate account
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_update_rate_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        numerator: u8,
        denominator: u8,
        rounding: u8,
    ) -> ProgramResult {
        let [rate_account_info, mint_from_account, mint_to_info_account] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // For Split operation mint_from == mint_to
        // If Rate was created for Convert operation, then mint_to should be verified
        verify_mint_keys_match(verified_mint_info, &mint_to_info_account)?;

        verify_writable(rate_account_info)?;
        verify_owner(rate_account_info, program_id)?;
        verify_account_initialized(rate_account_info)?;

        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_info_account.key();

        let mut rate_account = Rate::from_account_info(rate_account_info)?;
        let expected_rate_pda = rate_account.derive_pda(action_id, mint_from_key, mint_to_key)?;
        verify_pda_keys_match(rate_account_info.key(), &expected_rate_pda)?;

        let rounding_enum = Rounding::try_from(rounding)?;
        rate_account.update(rounding_enum, numerator, denominator)?;
        rate_account.write_data(rate_account_info)?;
        Ok(())
    }

    /// Close Rate account
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_close_rate_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
    ) -> ProgramResult {
        let [rate_account_info, destination_account, mint_from_account, mint_to_info_account] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // For Split operation mint_from == mint_to
        // If Rate was created for Convert operation, then mint_to should be verified
        verify_mint_keys_match(verified_mint_info, &mint_to_info_account)?;

        verify_writable(destination_account)?;
        verify_writable(rate_account_info)?;
        verify_owner(rate_account_info, program_id)?;
        verify_account_initialized(rate_account_info)?;

        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_info_account.key();

        // Deserialize to ensure it's valid Rate account, verify PDA, then close
        let rate = Rate::from_account_info(rate_account_info)?;
        let expected_rate_pda = rate.derive_pda(action_id, mint_from_key, mint_to_key)?;
        verify_pda_keys_match(rate_account_info.key(), &expected_rate_pda)?;

        Rate::close(rate_account_info, destination_account)?;
        Ok(())
    }

    /// Execute token split at predefined rate
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_split(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
    ) -> ProgramResult {
        let [mint_authority, permanent_delegate, payer, mint_account, token_account, rate_account, receipt_account, token_program, system_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        verify_token22_program(token_program)?;
        verify_system_program(system_program)?;
        verify_signer(payer)?;
        verify_writable(token_account)?;
        verify_writable(receipt_account)?;
        verify_writable(payer)?;
        verify_writable(mint_account)?;
        verify_owner(mint_authority, program_id)?;
        verify_owner(rate_account, program_id)?;
        verify_account_not_initialized(receipt_account)?;
        verify_account_initialized(rate_account)?;

        let mint_split_key = mint_account.key();

        let (permanent_delegate_pda, permanent_delegate_bump) =
            find_permanent_delegate_pda(mint_split_key, program_id);
        verify_pda_keys_match(permanent_delegate.key(), &permanent_delegate_pda)?;

        let (expected_receipt_pda, receipt_bump) =
            find_receipt_pda(mint_split_key, action_id, program_id);
        verify_pda_keys_match(receipt_account.key(), &expected_receipt_pda)?;

        // Verify Rate account with optimized derive_pda
        let rate = Rate::from_account_info(rate_account)?;
        let expected_rate_pda = rate.derive_pda(action_id, mint_split_key, mint_split_key)?;
        verify_pda_keys_match(rate_account.key(), &expected_rate_pda)?;

        let mint_split = Mint::from_account_info(mint_account)?;
        let mint_decimals = mint_split.decimals();
        drop(mint_split);

        let mint_authority_state = MintAuthority::from_account_info(mint_authority)?;
        if mint_split_key.ne(&mint_authority_state.mint) {
            return Err(ProgramError::InvalidInstructionData);
        }

        let token = TokenAccount::from_account_info(token_account)?;
        let current_amount = token.amount();
        if token.mint().ne(mint_split_key) {
            return Err(ProgramError::InvalidInstructionData);
        }
        if current_amount == 0 {
            return Err(ProgramError::InsufficientFunds);
        }
        drop(token);

        let new_amount = rate.calculate(current_amount)?;

        match new_amount.cmp(&current_amount) {
            Ordering::Equal => {
                // Just log the message but create Receipt to prevent duplicate split attempts
                debug_log!("No change in amount after split");
            }
            Ordering::Greater => {
                // Mint additional tokens
                let amount_diff = new_amount
                    .checked_sub(current_amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
                mint_to_checked(
                    amount_diff,
                    mint_decimals,
                    mint_account,
                    token_account,
                    mint_authority,
                    &mint_authority_state,
                )?;
            }
            Ordering::Less => {
                // Burn excess tokens
                let amount_diff = current_amount
                    .checked_sub(new_amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
                burn_checked(
                    amount_diff,
                    mint_decimals,
                    mint_account,
                    token_account,
                    permanent_delegate,
                    permanent_delegate_bump,
                )?;
            }
        }
        // Create Receipt PDA account for Split operation
        Receipt::issue(
            receipt_account,
            payer,
            *mint_split_key,
            action_id,
            receipt_bump,
        )?;
        Ok(())
    }

    /// Execute token conversion at predefined rate
    /// # Arguments
    /// * `verified_mint_info` - Mint account authorized by verification in processor (prevents mint substitution attacks)
    pub fn execute_convert(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        amount_to_convert: u64,
    ) -> ProgramResult {
        let [mint_authority, permanent_delegate, payer, mint_from_account, mint_to_account, token_account_from, token_account_to, rate_account, receipt_account, token_program, system_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_to_account)?;

        verify_token22_program(token_program)?;
        verify_system_program(system_program)?;
        verify_signer(payer)?;
        verify_writable(token_account_from)?;
        verify_writable(token_account_to)?;
        verify_writable(receipt_account)?;
        verify_writable(payer)?;
        verify_writable(mint_from_account)?;
        verify_writable(mint_to_account)?;
        verify_owner(rate_account, program_id)?;
        verify_owner(mint_authority, program_id)?;
        verify_account_not_initialized(receipt_account)?;
        verify_account_initialized(rate_account)?;

        let verified_mint_key = verified_mint_info.key();
        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_account.key();

        let (permanent_delegate_pda, permanent_delegate_bump) =
            find_permanent_delegate_pda(mint_from_key, program_id);
        verify_pda_keys_match(permanent_delegate.key(), &permanent_delegate_pda)?;

        let (expected_receipt_pda, receipt_bump) =
            find_receipt_pda(verified_mint_key, action_id, program_id);
        verify_pda_keys_match(receipt_account.key(), &expected_receipt_pda)?;

        // Verify Rate account with optimized derive_pda
        let rate = Rate::from_account_info(rate_account)?;
        let expected_rate_pda = rate.derive_pda(action_id, mint_from_key, mint_to_key)?;
        verify_pda_keys_match(rate_account.key(), &expected_rate_pda)?;

        let mint_from = Mint::from_account_info(mint_from_account)?;
        let mint_from_decimals = mint_from.decimals();
        drop(mint_from);

        let mint_to = Mint::from_account_info(mint_to_account)?;
        let mint_to_decimals = mint_to.decimals();
        drop(mint_to);

        let token_from = TokenAccount::from_account_info(token_account_from)?;
        let current_amount = token_from.amount();

        // Split should be used for the same mints instead
        if token_from.mint().ne(mint_from_key) {
            return Err(ProgramError::InvalidInstructionData);
        }
        if current_amount == 0 || current_amount < amount_to_convert {
            return Err(ProgramError::InsufficientFunds);
        }
        drop(token_from);

        let token_to = TokenAccount::from_account_info(token_account_to)?;
        if token_to.mint().ne(mint_to_key) {
            return Err(ProgramError::InvalidInstructionData);
        }
        drop(token_to);

        // Mint authority should be for mint_to as we are minting new tokens at conversion rate
        let mint_authority_state = MintAuthority::from_account_info(mint_authority)?;
        if mint_to_key.ne(&mint_authority_state.mint) {
            return Err(ProgramError::InvalidInstructionData);
        }

        let amount_to_mint =
            rate.convert_from_to_amount(amount_to_convert, mint_from_decimals, mint_to_decimals)?;

        if amount_to_mint.eq(&0) {
            // Conversion of small amounts or big rate delta can result in zero output when Rounding::Down is used
            return Err(ProgramError::InvalidInstructionData);
        }

        // Burn tokens from source
        burn_checked(
            amount_to_convert,
            mint_from_decimals,
            mint_from_account,
            token_account_from,
            permanent_delegate,
            permanent_delegate_bump,
        )?;

        // Mint tokens to target
        mint_to_checked(
            amount_to_mint,
            mint_to_decimals,
            mint_to_account,
            token_account_to,
            mint_authority,
            &mint_authority_state,
        )?;

        // Create Receipt PDA account for Convert operation
        Receipt::issue(
            receipt_account,
            payer,
            *verified_mint_key,
            action_id,
            receipt_bump,
        )?;

        Ok(())
    }
}

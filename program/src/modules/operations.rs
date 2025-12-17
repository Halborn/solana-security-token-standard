//! Operations Module
//!
//! Executes token operations after successful verification.
//! All operations are wrappers around SPL Token 2022 instructions.

use crate::constants::seeds;
use crate::debug_log;
use crate::merkle_tree_utils::{
    create_merkle_tree_leaf_node, verify_merkle_proof, MerkleTreeRoot, ProofData, ProofNode,
};
use crate::modules::{
    burn_checked, mint_to_checked, transfer_checked, verify_account_initialized,
    verify_account_not_initialized, verify_associated_token_program, verify_mint_keys_match,
    verify_owner, verify_pda_keys_match, verify_signer, verify_system_program,
    verify_token22_program, verify_transfer_hook_program, verify_writable,
};
use crate::state::{
    DistributionEscrowAuthority, MintAuthority, ProgramAccount, Proof, Rate, Receipt, Rounding,
};
use crate::token22_extensions::pausable::{Pause, Resume};
use crate::utils::{
    find_associated_token_address, find_distribution_escrow_authority_pda,
    find_freeze_authority_pda, find_pause_authority_pda, find_permanent_delegate_pda,
    find_proof_pda, find_rate_pda,
};
use core::cmp::Ordering;
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
use pinocchio_associated_token_account::instructions::Create as CreateTokenAccount;
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

        let (permanent_delegate_pda, permanent_delegate_bump) =
            crate::utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        verify_pda_keys_match(permanent_delegate_authority.key(), &permanent_delegate_pda)?;

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        transfer_checked(
            amount,
            decimals,
            mint_info,
            from_token_account,
            to_token_account,
            transfer_hook_program,
            permanent_delegate_authority,
            permanent_delegate_bump,
        )?;
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
            Receipt::find_common_action_pda(mint_split_key, action_id);
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
        let action_id_seed = action_id.to_le_bytes();
        let bump_seed = [receipt_bump];
        let seeds = Receipt::common_action_seeds(mint_split_key, &action_id_seed, &bump_seed);
        Receipt::issue(receipt_account, payer, &seeds)?;

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
            Receipt::find_common_action_pda(verified_mint_key, action_id);
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
        let action_id_seed = action_id.to_le_bytes();
        let bump_seed = [receipt_bump];
        let seeds = Receipt::common_action_seeds(verified_mint_key, &action_id_seed, &bump_seed);
        Receipt::issue(receipt_account, payer, &seeds)?;

        Ok(())
    }

    /// Execute proof account creation
    pub fn execute_create_proof_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        proof_data: ProofData,
    ) -> ProgramResult {
        let [payer, mint_account, proof_account, token_account, system_program_info] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        verify_system_program(system_program_info)?;
        verify_writable(payer)?;
        verify_writable(proof_account)?;
        verify_signer(payer)?;
        verify_account_not_initialized(proof_account)?;

        let token = TokenAccount::from_account_info(token_account)?;
        // Verify token account belongs to the mint
        let token_account_key = token_account.key();
        if token.mint().ne(mint_account.key()) {
            return Err(ProgramError::InvalidInstructionData);
        }

        let (expected_proof_pda, bump) = find_proof_pda(token_account_key, action_id, program_id);
        verify_pda_keys_match(proof_account.key(), &expected_proof_pda)?;

        // Create Proof account
        let proof = Proof::new(&proof_data, bump)?;
        let action_id_seed = &action_id.to_le_bytes();
        let bump_seed = &proof.bump_seed();
        let seeds = proof.seeds(token_account_key, action_id_seed, bump_seed);
        proof.init(payer, proof_account, &seeds)?;
        proof.write_data(proof_account)?;

        Ok(())
    }

    /// Execute proof account update
    pub fn execute_update_proof_account(
        _program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        proof_node: ProofNode,
        offset: u32,
    ) -> ProgramResult {
        let [payer, mint_account, proof_account, token_account, system_program_info] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        verify_system_program(system_program_info)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_writable(proof_account)?;
        verify_account_initialized(proof_account)?;

        let token = TokenAccount::from_account_info(token_account)?;
        // Verify token account belongs to the mint
        let token_account_key = token_account.key();
        if token.mint().ne(mint_account.key()) {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut proof = Proof::from_account_info(proof_account)?;
        let expected_proof_pda = proof.derive_pda(token_account_key, action_id)?;
        verify_pda_keys_match(proof_account.key(), &expected_proof_pda)?;

        // Update Proof account
        let current_proof_account_len = proof_account.data_len();
        proof.update_data_at_offset(proof_node, offset as usize)?;
        let new_proof_account_len = proof.serialized_len();
        // Update account size and pay rent difference
        if new_proof_account_len != current_proof_account_len {
            Proof::resize_account_and_rent(proof_account, new_proof_account_len, payer)?;
        }
        proof.write_data(proof_account)?;

        Ok(())
    }

    /// Create escrow for distributions
    pub fn execute_create_distribution_escrow(
        _program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        merkle_root: &MerkleTreeRoot,
    ) -> ProgramResult {
        let [distribution_escrow_authority, payer, distribution_token_account, distribution_mint, token_program, associated_token_account_program, system_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Verify mint is valid
        verify_mint_keys_match(verified_mint_info, &distribution_mint)?;
        // Verify programs
        verify_token22_program(token_program)?;
        verify_associated_token_program(associated_token_account_program)?;
        verify_system_program(system_program)?;

        verify_writable(distribution_token_account)?;
        verify_writable(payer)?;
        verify_signer(payer)?;

        verify_account_not_initialized(distribution_token_account)?;

        let mint_pubkey = distribution_mint.key();
        let (distribution_escrow_authority_pda, _) =
            DistributionEscrowAuthority::find_pda(mint_pubkey, action_id, merkle_root);
        verify_pda_keys_match(
            distribution_escrow_authority.key(),
            &distribution_escrow_authority_pda,
        )?;

        let (expected_ata, _) = find_associated_token_address(
            &distribution_escrow_authority_pda,
            mint_pubkey,
            token_program.key(),
        );
        verify_pda_keys_match(distribution_token_account.key(), &expected_ata)?;

        CreateTokenAccount {
            funding_account: payer,
            account: distribution_token_account,
            wallet: distribution_escrow_authority,
            mint: distribution_mint,
            system_program,
            token_program,
        }
        .invoke()?;

        Ok(())
    }

    /// Claim distribution (dividends/coupons)
    #[allow(clippy::too_many_arguments)]
    pub fn execute_claim_distribution(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        amount: u64,
        action_id: u64,
        merkle_root: &MerkleTreeRoot,
        leaf_index: u32,
        merkle_proof: Option<ProofData>,
    ) -> ProgramResult {
        let [permanent_delegate_authority, payer, mint_account, eligible_token_account, escrow_token_account, receipt_account, proof_account, transfer_hook_program, token_program, system_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Verify mint
        verify_mint_keys_match(verified_mint_info, &mint_account)?;

        // Verify programs
        verify_transfer_hook_program(transfer_hook_program)?;
        verify_token22_program(token_program)?;
        verify_system_program(system_program)?;

        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_writable(receipt_account)?;

        // With external settlement the escrow_token_account is not provided
        let is_external_settlement = escrow_token_account.key().eq(program_id);
        verify_writable(eligible_token_account)?;
        // escrow_token_account only needs writable check if it's not external settlement
        if !is_external_settlement {
            verify_writable(escrow_token_account)?;
        }

        verify_account_not_initialized(receipt_account)?;
        // Retrieve proof data either from argument or from account and verify proof account
        let proof = Proof::get_proof_data_from_instruction(
            eligible_token_account.key(),
            action_id,
            proof_account,
            merkle_proof,
        )?;
        let mint_pubkey = mint_account.key();
        let (expected_receipt_pda, receipt_bump) = Receipt::find_claim_action_pda(
            mint_pubkey,
            eligible_token_account.key(),
            action_id,
            &proof,
        );
        verify_pda_keys_match(receipt_account.key(), &expected_receipt_pda)?;

        // Verify claimer node belongs to merkle tree
        let node = create_merkle_tree_leaf_node(
            eligible_token_account.key(),
            mint_pubkey,
            action_id,
            amount,
        );
        if !verify_merkle_proof(&node, merkle_root, &proof, leaf_index) {
            return Err(ProgramError::InvalidInstructionData);
        }

        // With internal settlement tokens are transferred and Receipt is issued
        if !is_external_settlement {
            let (distribution_escrow_authority, _bump) = find_distribution_escrow_authority_pda(
                mint_pubkey,
                action_id,
                merkle_root,
                program_id,
            );
            let (expected_escrow_ata, _ata_bump) = find_associated_token_address(
                &distribution_escrow_authority,
                mint_pubkey,
                &pinocchio_token_2022::ID,
            );
            verify_pda_keys_match(escrow_token_account.key(), &expected_escrow_ata)?;

            let (permanent_delegate_pda, permanent_delegate_bump) =
                find_permanent_delegate_pda(mint_pubkey, program_id);
            verify_pda_keys_match(permanent_delegate_authority.key(), &permanent_delegate_pda)?;

            let mint = Mint::from_account_info(mint_account)?;
            let escrow_token = TokenAccount::from_account_info(escrow_token_account)?;
            let eligible_token = TokenAccount::from_account_info(eligible_token_account)?;
            let decimals = mint.decimals();

            if escrow_token.mint() != mint_pubkey || eligible_token.mint() != mint_pubkey {
                return Err(ProgramError::InvalidAccountData);
            }
            if escrow_token.amount() < amount {
                return Err(ProgramError::InsufficientFunds);
            }
            drop(mint);
            drop(escrow_token);
            drop(eligible_token);

            // Transfer tokens from distribution escrow to eligible token account
            transfer_checked(
                amount,
                decimals,
                mint_account,
                escrow_token_account,
                eligible_token_account,
                transfer_hook_program,
                permanent_delegate_authority,
                permanent_delegate_bump,
            )?;
        }

        // Issue Receipt
        let action_id_seed = action_id.to_le_bytes();
        let bump_seed = [receipt_bump];
        let proof_seed = Receipt::proof_seed(&proof);
        let receipt_seeds = Receipt::claim_action_seeds(
            mint_pubkey,
            eligible_token_account.key(),
            &action_id_seed,
            &proof_seed,
            &bump_seed,
        );
        Receipt::issue(receipt_account, payer, &receipt_seeds)?;
        Ok(())
    }

    /// Close Receipt account of operation tied to the action_id (e.g. split, convert)
    pub fn execute_close_action_receipt_account(
        _program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
    ) -> ProgramResult {
        let [receipt_account, destination_account, mint_account] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;
        verify_writable(destination_account)?;
        verify_writable(receipt_account)?;

        // Validate Receipt
        verify_account_initialized(receipt_account)?;
        // Deserialize to ensure it's valid Receipt account (checks discriminator and ownership)
        Receipt::from_account_info(receipt_account)?;
        let (expected_receipt_pda, _bump) =
            Receipt::find_common_action_pda(mint_account.key(), action_id);
        verify_pda_keys_match(receipt_account.key(), &expected_receipt_pda)?;

        Receipt::close(receipt_account, destination_account)?;
        Ok(())
    }

    /// Close Receipt account of claim_distribution action
    pub fn execute_close_claim_receipt_account(
        _program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        merkle_proof: Option<ProofData>,
    ) -> ProgramResult {
        let [receipt_account, destination_account, mint_account, eligible_token_account, proof_account] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;
        verify_writable(destination_account)?;
        verify_writable(receipt_account)?;
        verify_account_initialized(receipt_account)?;
        // Deserialize to ensure it's valid Receipt account (checks discriminator and ownership)
        Receipt::from_account_info(receipt_account)?;

        // Retrieve proof data either from argument or from account. Verify proof account
        let proof = Proof::get_proof_data_from_instruction(
            eligible_token_account.key(),
            action_id,
            proof_account,
            merkle_proof,
        )?;
        let (expected_receipt_pda, _bump) = Receipt::find_claim_action_pda(
            mint_account.key(),
            eligible_token_account.key(),
            action_id,
            &proof,
        );
        verify_pda_keys_match(receipt_account.key(), &expected_receipt_pda)?;

        Receipt::close(receipt_account, destination_account)?;
        Ok(())
    }
}

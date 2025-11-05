//! Operations Module
//!
//! Executes token operations after successful verification.
//! All operations are wrappers around SPL Token 2022 instructions.

use crate::constants::seeds;
use crate::instructions::{CustomPause, CustomResume};
use crate::modules::{
    verify_account_initialized, verify_account_not_initialized, verify_operation_mint_info,
    verify_owner, verify_pda, verify_signer, verify_system_program, verify_token22_program,
    verify_writable,
};
use crate::state::{MintAuthority, ProgramAccount, Rate, Rounding};
use crate::utils::{find_freeze_authority_pda, find_pause_authority_pda, find_rate_pda};
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
use pinocchio_log::log;
use pinocchio_token_2022::instructions::{BurnChecked, FreezeAccount, MintToChecked, ThawAccount};
use pinocchio_token_2022::state::Mint;

/// Operations Module - executes token operations
pub struct OperationsModule;

impl OperationsModule {
    /// Mint tokens to an account
    /// Wrapper for SPL Token MintToChecked instruction
    pub fn execute_mint(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [mint_info, mint_authority, destination_account_info, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;
        verify_owner(mint_authority, program_id)?;

        log!("All checks passed, proceeding to mint {} tokens", amount);

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        let instruction = MintToChecked {
            mint: mint_info,
            account: destination_account_info,
            mint_authority,
            amount,
            decimals,
        };

        let mint_authority_state = MintAuthority::from_account_info(mint_authority)?;

        let bump_seed = [mint_authority_state.bump];
        let seeds = [
            Seed::from(seeds::MINT_AUTHORITY),
            Seed::from(mint_authority_state.mint.as_ref()),
            Seed::from(mint_authority_state.mint_creator.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];

        let mint_authority_signer = Signer::from(&seeds);

        instruction.invoke_signed(&[mint_authority_signer])?;
        Ok(())
    }

    /// Burn tokens from an account  
    /// Wrapper for SPL Token BurnChecked instruction
    pub fn execute_burn(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [mint_info, permanent_delegate_authority, token_account, token_program] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;

        let (permanent_delegate_pda, bump) =
            crate::utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        if permanent_delegate_authority.key() != &permanent_delegate_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        log!("All checks passed, proceeding to burn {} tokens", amount);

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        let instruction = BurnChecked {
            mint: mint_info,
            account: token_account,
            authority: permanent_delegate_authority,
            amount,
            decimals,
        };
        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::PERMANENT_DELEGATE),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let permanent_delegate_signer = Signer::from(&seeds);
        instruction.invoke_signed(&[permanent_delegate_signer])?;
        Ok(())
    }

    /// Pause all activity within a mint
    /// Wrapper for SPL Token Pause instruction
    pub fn execute_pause(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [mint_info, pause_authority, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;

        let (pause_authority_pda, bump) = find_pause_authority_pda(mint_info.key(), program_id);
        if pause_authority.key() != &pause_authority_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        log!("All checks passed, proceeding to pause");
        let pause_instruction = CustomPause {
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
    pub fn execute_resume(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [mint_info, pause_authority, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_operation_mint_info(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;

        let (pause_authority_pda, bump) = find_pause_authority_pda(mint_info.key(), program_id);
        if pause_authority.key() != &pause_authority_pda {
            return Err(ProgramError::InvalidSeeds);
        }
        log!("All checks passed, proceeding to resume");
        let resume_instruction = CustomResume {
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
    pub fn execute_freeze_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [mint_info, freeze_authority, token_account, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;

        let (freeze_authority_pda, bump) = find_freeze_authority_pda(mint_info.key(), program_id);
        if freeze_authority.key() != &freeze_authority_pda {
            return Err(ProgramError::InvalidSeeds);
        }
        log!("All checks passed, proceeding to freeze");
        let freeze_instruction = FreezeAccount {
            account: token_account,
            mint: mint_info,
            freeze_authority,
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
    pub fn execute_thaw_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let [mint_info, freeze_authority, token_account, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program)?;

        let (freeze_authority_pda, bump) = find_freeze_authority_pda(mint_info.key(), program_id);
        if freeze_authority.key() != &freeze_authority_pda {
            return Err(ProgramError::InvalidSeeds);
        }
        log!("All checks passed, proceeding to thaw");
        let thaw_instruction = ThawAccount {
            account: token_account,
            mint: mint_info,
            freeze_authority,
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
    pub fn execute_transfer(_accounts: &[AccountInfo], _amount: u64) -> ProgramResult {
        // TODO: Execute SPL Token2022 transfer CPI with Permanent Delegate PDA
        Ok(())
    }

    /// Execute token conversion at predefined rate
    pub fn execute_convert(
        _accounts: &[AccountInfo],
        _amount_to_convert: u64,
        _action_id: u64,
    ) -> ProgramResult {
        // TODO: Load Rate account
        // TODO: Calculate target amount (amount * numerator / denominator)
        // TODO: Burn source tokens, mint target tokens
        // TODO: Create Receipt account
        Ok(())
    }

    /// Execute token split at predefined rate
    pub fn execute_split(_accounts: &[AccountInfo], _action_id: u64) -> ProgramResult {
        // TODO: Load Rate account
        // TODO: Calculate new balance (balance * numerator / denominator)
        // TODO: Burn or mint delta amount
        // TODO: Create Receipt account
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
    pub fn execute_create_rate_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
        numerator: u8,
        denominator: u8,
        rounding: u8,
    ) -> ProgramResult {
        let [rate_account, mint_from_account, mint_to_account, payer, system_program_info] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_from_account)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_system_program(system_program_info)?;
        verify_writable(rate_account)?;
        verify_account_not_initialized(rate_account)?;

        let mint_from = Mint::from_account_info(mint_from_account)?;
        let mint_to = Mint::from_account_info(mint_to_account)?;
        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_account.key();
        drop(mint_from);
        drop(mint_to);

        let (expected_rate_pda, bump) =
            find_rate_pda(action_id, mint_from_key, mint_to_key, program_id);

        verify_pda(rate_account.key(), &expected_rate_pda)?;

        // Calculate rent and create Rate account
        let rounding_enum = Rounding::try_from(rounding)?;
        let rate = Rate::new(rounding_enum, numerator, denominator, bump)?;
        let action_id_seed = &action_id.to_le_bytes();
        let bump_seed = &rate.bump_seed();
        let seeds = rate.seeds(action_id_seed, mint_from_key, mint_to_key, bump_seed);
        rate.init(payer, rate_account, &seeds)?;

        log!("Rate PDA account created successfully");
        rate.write_data(rate_account)?;

        log!("Rate PDA account created: {}", rate_account.key());
        Ok(())
    }

    /// Update Rate account
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

        verify_operation_mint_info(verified_mint_info, &mint_from_account)?;
        verify_writable(rate_account_info)?;
        verify_owner(rate_account_info, program_id)?;
        verify_account_initialized(rate_account_info)?;

        Mint::from_account_info(mint_from_account)?;
        Mint::from_account_info(mint_to_info_account)?;
        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_info_account.key();

        let mut rate_account = Rate::from_account_info(rate_account_info)?;
        let expected_rate_pda = rate_account.derive_pda(action_id, mint_from_key, mint_to_key)?;
        verify_pda(rate_account_info.key(), &expected_rate_pda)?;

        let rounding_enum = Rounding::try_from(rounding)?;
        rate_account.update(rounding_enum, numerator, denominator)?;
        rate_account.write_data(rate_account_info)?;

        log!(
            "Rate account {} updated successfully",
            rate_account_info.key()
        );
        Ok(())
    }

    /// Close Rate account
    pub fn execute_close_rate_account(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        action_id: u64,
    ) -> ProgramResult {
        let [rate_account_info, mint_from_account, mint_to_info_account, destination_account] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_operation_mint_info(verified_mint_info, &mint_from_account)?;
        verify_writable(destination_account)?;
        verify_writable(rate_account_info)?;
        verify_account_initialized(rate_account_info)?;
        verify_owner(rate_account_info, program_id)?;

        Mint::from_account_info(mint_from_account)?;
        Mint::from_account_info(mint_to_info_account)?;
        let mint_from_key = mint_from_account.key();
        let mint_to_key = mint_to_info_account.key();

        // Deserialize to ensure it's valid Rate account before closing
        let rate = Rate::from_account_info(rate_account_info)?;
        let expected_rate_pda = rate.derive_pda(action_id, mint_from_key, mint_to_key)?;
        verify_pda(rate_account_info.key(), &expected_rate_pda)?;

        Rate::close(rate_account_info, destination_account)?;

        log!("Rate Account {} closed successfully", &expected_rate_pda);
        Ok(())
    }
}

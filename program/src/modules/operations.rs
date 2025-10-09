//! Operations Module
//!
//! Executes token operations after successful verification.
//! All operations are wrappers around SPL Token 2022 instructions.

use crate::constants::seeds;
use crate::instructions::{CustomPause, CustomResume};
use crate::modules::{verify_initial_mint_authority, verify_signer, verify_token22_program};
use crate::modules::{verify_owner, verify_system_program};
use crate::utils::find_pause_authority_pda;
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::ProgramResult;
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey};
use pinocchio_log::log;
use pinocchio_token_2022::instructions::{BurnChecked, MintToChecked};
use pinocchio_token_2022::state::{Mint, TokenAccount};

/// Operations Module - executes token operations
pub struct OperationsModule;

impl OperationsModule {
    /// Mint tokens to an account
    /// Wrapper for SPL Token MintToChecked instruction
    pub fn execute_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [creator_signer, mint_info, mint_authority, destination_account_info, system_program, token_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_system_program(system_program)?;
        verify_token22_program(token_program)?;
        let mint_authority_state = verify_initial_mint_authority(
            program_id,
            mint_info,
            mint_authority,
            creator_signer,
            true,
        )?;

        log!("All checks passed, proceeding to mint {} tokens", amount);

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        let instruction = MintToChecked {
            mint: &mint_info,
            account: &destination_account_info,
            mint_authority: &mint_authority,
            amount,
            decimals,
        };

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
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [creator_signer, mint_info, mint_authority, token_account, system_program, token_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_system_program(system_program)?;
        verify_token22_program(token_program)?;
        let _mint_authority_state = verify_initial_mint_authority(
            program_id,
            mint_info,
            mint_authority,
            creator_signer,
            true,
        )?;
        verify_owner(token_account, token_program.key())?;
        {
            let token_account_state = TokenAccount::from_account_info(token_account)?;
            if token_account_state.mint() != mint_info.key() {
                return Err(ProgramError::InvalidAccountData);
            }

            if token_account_state.owner() != creator_signer.key() {
                return Err(ProgramError::InvalidAccountOwner);
            }
        }

        log!("All checks passed, proceeding to burn {} tokens", amount);

        let mint_account = Mint::from_account_info(mint_info)?;
        let decimals = mint_account.decimals();
        drop(mint_account);

        let instruction = BurnChecked {
            mint: &mint_info,
            account: &token_account,
            authority: &creator_signer,
            amount,
            decimals,
        };
        instruction.invoke()?;
        Ok(())
    }

    /// Pause all activity within a mint
    /// Wrapper for SPL Token Pause instruction
    pub fn execute_pause(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let [creator_signer, mint_info, mint_authority, pause_authority, token_program] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_token22_program(token_program)?;
        verify_signer(creator_signer, false)?;
        let mint_authority_state = verify_initial_mint_authority(
            program_id,
            mint_info,
            mint_authority,
            creator_signer,
            false,
        )?;
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
    pub fn execute_resume(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let [creator_signer, mint_info, mint_authority, pause_authority, token_program] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        // TODO: Almost the same, might be splitted
        verify_token22_program(token_program)?;
        verify_signer(creator_signer, false)?;
        let mint_authority_state = verify_initial_mint_authority(
            program_id,
            mint_info,
            mint_authority,
            creator_signer,
            false,
        )?;
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
            Seed::from(mint_authority_state.mint.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];

        let resume_authority_signer = Signer::from(&seeds);
        resume_instruction.invoke_signed(&[resume_authority_signer])?;

        Ok(())
    }

    /// Freeze a token account
    /// Wrapper for SPL Token FreezeAccount instruction
    pub fn execute_freeze_account(_accounts: &[AccountInfo]) -> ProgramResult {
        // TODO: Execute SPL Token2022 freeze CPI with freeze authority PDA
        Ok(())
    }

    /// Thaw a token account
    /// Wrapper for SPL Token ThawAccount instruction
    pub fn execute_thaw_account(_accounts: &[AccountInfo]) -> ProgramResult {
        // TODO: Execute SPL Token2022 thaw CPI with freeze authority PDA
        Ok(())
    }

    /// Close a token account
    /// Wrapper for SPL Token CloseAccount instruction
    pub fn execute_close_account(_accounts: &[AccountInfo]) -> ProgramResult {
        // TODO: Execute SPL Token2022 close CPI
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
}

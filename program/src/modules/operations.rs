//! Operations Module
//!
//! Executes token operations after successful verification.
//! All operations are wrappers around SPL Token 2022 instructions.

use crate::constants::seeds;
use crate::instructions::{CustomPause, CustomResume};
use crate::modules::{verify_owner, verify_signer, verify_token22_program};
use crate::state::MintAuthority;
use crate::utils::{find_freeze_authority_pda, find_pause_authority_pda};
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
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [creator_signer, mint_info, mint_authority, destination_account_info, token_program] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_token22_program(token_program)?;
        verify_owner(mint_authority, program_id)?;
        verify_signer(creator_signer)?;

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
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let [mint_info, permanent_delegate_authority, token_account, token_program] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

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
    pub fn execute_pause(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let [mint_info, pause_authority, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
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
    pub fn execute_resume(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let [mint_info, pause_authority, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
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
    pub fn execute_freeze_account(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let [mint_info, freeze_authority, token_account, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
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
    pub fn execute_thaw_account(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let [mint_info, freeze_authority, token_account, token_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
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
}

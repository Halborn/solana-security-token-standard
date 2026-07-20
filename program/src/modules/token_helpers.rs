use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    ProgramResult,
};
use pinocchio_token_2022::instructions::{BurnChecked, MintToChecked};

use crate::{
    constants::seeds,
    error::SecurityTokenError,
    instructions::TransferCheckedWithHook,
    state::MintAuthority,
    token22_extensions::permissioned_burn::{
        get_permissioned_burn_state, PermissionedBurnChecked, PermissionedBurnState,
    },
};

/// Burn tokens from token account using permanent delegate authority
pub fn burn_checked(
    amount: u64,
    decimals: u8,
    mint: &AccountInfo,
    token_account: &AccountInfo,
    permanent_delegate_authority: &AccountInfo,
    permanent_delegate_bump: u8,
) -> ProgramResult {
    let bump_seed = [permanent_delegate_bump];
    let seeds = [
        Seed::from(seeds::PERMANENT_DELEGATE),
        Seed::from(mint.key().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    let permanent_delegate_signer = Signer::from(&seeds);
    // Scope the mint-data borrow so it is released before the Token-2022 CPI,
    // which needs mutable access to the mint account.
    let permissioned_burn_state = {
        let mint_data = mint.try_borrow_data()?;
        get_permissioned_burn_state(&mint_data)
    };

    match permissioned_burn_state {
        // Legacy mints do not have the extension. SSTS cannot clear a configured
        // Permissioned Burn authority, but if it is cleared externally, Token-2022
        // already permits native burns. Falling back to BurnChecked keeps SSTS
        // burn, split, and convert usable because there is no recovery path.
        PermissionedBurnState::NotPresent | PermissionedBurnState::PresentWithoutAuthority => {
            BurnChecked {
                mint,
                account: token_account,
                authority: permanent_delegate_authority,
                amount,
                decimals,
                token_program: &pinocchio_token_2022::ID,
            }
            .invoke_signed(&[permanent_delegate_signer])
        }
        PermissionedBurnState::PresentWithAuthority(authority)
            if authority == *permanent_delegate_authority.key() =>
        {
            // The SSTS Permanent Delegate PDA fulfills both Token-2022 signer roles:
            // the configured Permissioned Burn authority and the token burn authority.
            PermissionedBurnChecked {
                account: token_account,
                mint,
                permissioned_burn_authority: permanent_delegate_authority,
                authority: permanent_delegate_authority,
                amount,
                decimals,
            }
            .invoke_signed(&[permanent_delegate_signer])
        }
        PermissionedBurnState::PresentWithAuthority(_) => {
            Err(SecurityTokenError::PermissionedBurnAuthorityMismatch.into())
        }
        PermissionedBurnState::Malformed => {
            Err(SecurityTokenError::MalformedPermissionedBurn.into())
        }
    }
}

/// Mint tokens to token account using mint authority PDA
pub fn mint_to_checked(
    amount: u64,
    decimals: u8,
    mint: &AccountInfo,
    token_account: &AccountInfo,
    mint_authority: &AccountInfo,
    mint_authority_state: &MintAuthority,
) -> ProgramResult {
    let bump_seed = &mint_authority_state.bump_seed();
    let seeds = &mint_authority_state.seeds(bump_seed);
    let mint_authority_signer = Signer::from(seeds);
    MintToChecked {
        mint,
        account: token_account,
        mint_authority,
        amount,
        decimals,
        token_program: &pinocchio_token_2022::ID,
    }
    .invoke_signed(&[mint_authority_signer])
}

/// Transfer tokens using permanent delegate authority
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked(
    amount: u64,
    decimals: u8,
    mint_info: &AccountInfo,
    from_token_account: &AccountInfo,
    to_token_account: &AccountInfo,
    transfer_hook_program: &AccountInfo,
    permanent_delegate_authority: &AccountInfo,
    permanent_delegate_bump: u8,
) -> ProgramResult {
    let bump_seed = [permanent_delegate_bump];
    let seeds = [
        Seed::from(seeds::PERMANENT_DELEGATE),
        Seed::from(mint_info.key().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    let permanent_delegate_signer = Signer::from(&seeds);

    TransferCheckedWithHook {
        mint: mint_info,
        from: from_token_account,
        to: to_token_account,
        authority: permanent_delegate_authority,
        amount,
        decimals,
        transfer_hook_program,
    }
    .invoke_signed(&[permanent_delegate_signer])
}

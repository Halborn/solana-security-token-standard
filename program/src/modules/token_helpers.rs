use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    ProgramResult,
};
use pinocchio_token_2022::instructions::{BurnChecked, MintToChecked};

use crate::{constants::seeds, instructions::TransferCheckedWithHook, state::MintAuthority};

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

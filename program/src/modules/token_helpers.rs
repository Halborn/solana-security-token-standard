use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    ProgramResult,
};
use pinocchio_token_2022::instructions::{BurnChecked, MintToChecked};

use crate::{constants::seeds, state::MintAuthority};

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
    }
    .invoke_signed(&[mint_authority_signer])
}

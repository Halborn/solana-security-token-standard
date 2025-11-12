use security_token_client::{
    instructions::{CreateDistributionEscrow, CreateDistributionEscrowInstructionArgs},
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::CreateDistributionEscrowArgs,
};
use solana_program_test::{BanksClient, BanksClientError};
use solana_pubkey::Pubkey;
use solana_sdk::{signature::Keypair, signer::Signer};
use spl_associated_token_account::ID as ASSOCIATED_TOKEN_PROGRAM_ID;
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;

use crate::helpers::send_tx;

pub async fn execute_create_distribution_escrow_account(
    banks_client: &BanksClient,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    distribution_escrow_authority: Pubkey,
    distribution_mint: Pubkey,
    distribution_token_account: Pubkey,
    create_distribution_escrow_args: CreateDistributionEscrowArgs,
    payer: &Keypair,
) -> Result<(), BanksClientError> {
    let payer_pubkey = payer.pubkey();

    let ix = CreateDistributionEscrow {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        distribution_escrow_authority,
        distribution_mint,
        distribution_token_account,
        payer: payer_pubkey,
        token_program: TOKEN_22_PROGRAM_ID,
        associated_token_account_program: ASSOCIATED_TOKEN_PROGRAM_ID,
        system_program: solana_program::system_program::id(),
    }
    .instruction(CreateDistributionEscrowInstructionArgs {
        create_distribution_escrow_args,
    });

    send_tx(&banks_client, vec![ix], &payer_pubkey, vec![payer]).await
}

pub fn find_distribution_escrow_authority_pda(
    mint: &Pubkey,
    action_id: u64,
    merkle_root: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"distribution_escrow_authority",
            mint.as_ref(),
            action_id.to_le_bytes().as_ref(),
            merkle_root.as_ref(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

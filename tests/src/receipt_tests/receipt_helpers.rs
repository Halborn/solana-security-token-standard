use security_token_client::{
    instructions::{
        CloseClaimReceiptAccount, CloseClaimReceiptAccountInstructionArgs,
        CloseActionReceiptAccount, CloseActionReceiptAccountInstructionArgs,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{CloseClaimReceiptArgs, CloseActionReceiptArgs},
};
use solana_keccak_hasher::hashv;
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::helpers::send_tx;

pub async fn close_action_receipt_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    receipt_account: Pubkey,
    mint_account: Pubkey,
    destination: &Keypair,
    close_action_receipt_args: CloseActionReceiptArgs,
) -> Result<(), BanksClientError> {
    let close_rate_ix = CloseActionReceiptAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        receipt_account,
        mint_account,
        destination: destination.pubkey(),
    }
    .instruction(CloseActionReceiptAccountInstructionArgs {
        close_action_receipt_args,
    });

    send_tx(
        &context.banks_client,
        vec![close_rate_ix],
        &destination.pubkey(),
        vec![destination],
    )
    .await
}

pub async fn close_claim_receipt_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    receipt_account: Pubkey,
    mint_account: Pubkey,
    eligible_token_account: Pubkey,
    proof_account: Option<Pubkey>,
    destination: &Keypair,
    close_claim_receipt_args: CloseClaimReceiptArgs,
) -> Result<(), BanksClientError> {
    let close_rate_ix = CloseClaimReceiptAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        receipt_account,
        mint_account,
        eligible_token_account,
        proof_account,
        destination: destination.pubkey(),
    }
    .instruction(CloseClaimReceiptAccountInstructionArgs {
        close_claim_receipt_args,
    });

    send_tx(
        &context.banks_client,
        vec![close_rate_ix],
        &destination.pubkey(),
        vec![destination],
    )
    .await
}

pub fn find_common_action_receipt_pda(mint: &Pubkey, action_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"receipt", &mint.as_ref(), &action_id.to_le_bytes()],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

pub fn find_claim_action_receipt_pda(
    mint: &Pubkey,
    token_account: &Pubkey,
    action_id: u64,
    proof: &Vec<[u8; 32]>,
) -> (Pubkey, u8) {
    let proof_data = proof
        .iter()
        .flat_map(|proof_node| *proof_node)
        .collect::<Vec<u8>>();
    let proof_hash = hashv(&[&proof_data]).to_bytes();

    Pubkey::find_program_address(
        &[
            b"receipt",
            mint.as_ref(),
            token_account.as_ref(),
            action_id.to_le_bytes().as_ref(),
            proof_hash.as_ref(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

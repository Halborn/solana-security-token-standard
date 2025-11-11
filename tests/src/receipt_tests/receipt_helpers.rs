use security_token_client::{
    instructions::{CloseReceiptAccount, CloseReceiptAccountInstructionArgs},
    types::CloseReceiptArgs,
};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

use crate::helpers::send_tx;

pub async fn close_receipt_account(
    context: &mut solana_program_test::ProgramTestContext,
    security_token_mint: Pubkey,
    verification_config_or_mint_authority: Pubkey,
    instructions_sysvar_or_creator: Pubkey,
    receipt_account: Pubkey,
    rate_account: Pubkey,
    mint_account: Pubkey,
    destination: &Keypair,
    close_receipt_args: CloseReceiptArgs,
) -> Result<(), BanksClientError> {
    let close_rate_ix = CloseReceiptAccount {
        mint: security_token_mint,
        verification_config_or_mint_authority,
        instructions_sysvar_or_creator,
        receipt_account,
        rate_account,
        mint_account,
        destination: destination.pubkey(),
    }
    .instruction(CloseReceiptAccountInstructionArgs { close_receipt_args });

    send_tx(
        &context.banks_client,
        vec![close_rate_ix],
        &destination.pubkey(),
        vec![destination],
    )
    .await
}

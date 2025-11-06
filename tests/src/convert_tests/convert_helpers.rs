use security_token_client::{
    instructions::{CONVERT_DISCRIMINATOR, Convert, ConvertInstructionArgs},
    types::ConvertArgs,
};
use solana_program_test::*;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use crate::helpers::{create_verification_config, send_tx};

/// Build and send Convert instruction
pub async fn execute_convert(
    banks_client: &BanksClient,
    verification_config_pda: Pubkey,
    mint_from: Pubkey,
    mint_to: Pubkey,
    token_account_from: Pubkey,
    token_account_to: Pubkey,
    mint_authority: Pubkey,
    permanent_delegate: Pubkey,
    rate_account: Pubkey,
    receipt_account: Pubkey,
    payer: &Keypair,
    action_id: u64,
    amount_to_convert: u64,
) -> Result<(), BanksClientError> {
    let convert_args = ConvertArgs { action_id, amount_to_convert };
    let convert_ix = Convert {
        mint: mint_from,
        verification_config: verification_config_pda,
        instructions_sysvar: solana_program::sysvar::instructions::id(),
        mint_from,
        mint_to,
        token_account_from,
        token_account_to,
        mint_authority,
        permanent_delegate,
        rate_account,
        receipt_account,
        token_program: Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
        system_program: solana_program::system_program::id(),
        payer: payer.pubkey(),
    }
    .instruction(ConvertInstructionArgs { convert_args });

    send_tx(banks_client, vec![convert_ix], &payer.pubkey(), vec![payer]).await
}

pub async fn create_convert_verification_config(
    context: &mut ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
    owner: Option<&Keypair>,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        CONVERT_DISCRIMINATOR,
        program_addresses,
        owner,
    )
    .await
}
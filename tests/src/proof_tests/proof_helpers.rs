use security_token_client::{
    instructions::{
        CreateProofAccount, CreateProofAccountInstructionArgs, UpdateProofAccount,
        UpdateProofAccountInstructionArgs, CREATE_PROOF_ACCOUNT_DISCRIMINATOR,
        UPDATE_PROOF_ACCOUNT_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{CreateProofArgs, UpdateProofArgs},
};
use solana_program_test::{BanksClient, BanksClientError};
use solana_pubkey::Pubkey;
use solana_sdk::{signature::Keypair, signer::Signer};

use crate::helpers::{create_verification_config, send_tx};

pub async fn execute_create_proof_account(
    banks_client: &BanksClient,
    security_token_mint: Pubkey,
    verification_config: Pubkey,
    proof_account: Pubkey,
    mint_account: Pubkey,
    token_account: Pubkey,
    create_proof_args: CreateProofArgs,
    payer: &Keypair,
) -> Result<(), BanksClientError> {
    let payer_pubkey = payer.pubkey();

    let ix = CreateProofAccount {
        verification_config,
        instructions_sysvar: solana_program::sysvar::instructions::id(),
        mint: security_token_mint,
        token_account,
        mint_account,
        proof_account,
        payer: payer_pubkey,
        system_program: solana_program::system_program::id(),
    }
    .instruction(CreateProofAccountInstructionArgs { create_proof_args });

    send_tx(&banks_client, vec![ix], &payer_pubkey, vec![payer]).await
}

pub async fn execute_update_proof_account(
    banks_client: &BanksClient,
    security_token_mint: Pubkey,
    verification_config: Pubkey,
    proof_account: Pubkey,
    mint_account: Pubkey,
    token_account: Pubkey,
    update_proof_args: UpdateProofArgs,
    payer: &Keypair,
) -> Result<(), BanksClientError> {
    let payer_pubkey = payer.pubkey();

    let ix = UpdateProofAccount {
        verification_config,
        instructions_sysvar: solana_program::sysvar::instructions::id(),
        mint: security_token_mint,
        token_account,
        mint_account,
        proof_account,
        payer: payer_pubkey,
        system_program: solana_program::system_program::id(),
    }
    .instruction(UpdateProofAccountInstructionArgs { update_proof_args });

    send_tx(&banks_client, vec![ix], &payer_pubkey, vec![payer]).await
}

pub fn find_proof_pda(token_account: &Pubkey, action_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"proof",
            token_account.as_ref(),
            action_id.to_le_bytes().as_ref(),
        ],
        &SECURITY_TOKEN_PROGRAM_ID,
    )
}

pub async fn create_create_proof_account_verification_config(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
    owner: Option<&Keypair>,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        CREATE_PROOF_ACCOUNT_DISCRIMINATOR,
        program_addresses,
        owner,
    )
    .await
}

pub async fn create_update_proof_account_verification_config(
    context: &mut solana_program_test::ProgramTestContext,
    mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    program_addresses: Vec<Pubkey>,
    owner: Option<&Keypair>,
) -> Pubkey {
    create_verification_config(
        context,
        mint_keypair,
        mint_authority_pda,
        UPDATE_PROOF_ACCOUNT_DISCRIMINATOR,
        program_addresses,
        owner,
    )
    .await
}

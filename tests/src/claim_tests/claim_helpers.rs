use security_token_client::{
    instructions::{
        ClaimDistribution, ClaimDistributionInstructionArgs, CreateDistributionEscrow,
        CreateDistributionEscrowInstructionArgs, CLAIM_DISTRIBUTION_DISCRIMINATOR,
    },
    programs::SECURITY_TOKEN_PROGRAM_ID,
    types::{ClaimDistributionArgs, CreateDistributionEscrowArgs},
};
use solana_program_test::{BanksClient, BanksClientError, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_sdk::{signature::Keypair, signer::Signer, sysvar};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, ID as ASSOCIATED_TOKEN_PROGRAM_ID,
};
use spl_merkle_tree_reference::MerkleTree;
use spl_token_2022::ID as TOKEN_22_PROGRAM_ID;

use crate::{
    claim_tests::merkle_tree_helpers::{create_merkle_tree, Leaf},
    helpers::{
        add_dummy_verification_program, assert_transaction_success,
        create_dummy_verification_from_instruction, create_mint_verification_config,
        create_spl_account, create_verification_config, find_permanent_delegate_pda,
        from_ui_amount, get_default_verification_programs, initialize_program, mint_tokens_to,
        send_tx,
    },
};

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

    let dummy_ix = create_dummy_verification_from_instruction(&ix);

    send_tx(
        &banks_client,
        vec![dummy_ix, ix],
        &payer_pubkey,
        vec![payer],
    )
    .await
}

pub async fn execute_claim_distribution(
    banks_client: &mut BanksClient,
    mint: Pubkey,
    verification_config: Pubkey,
    permanent_delegate_authority: Pubkey,
    distribution_mint: Pubkey,
    eligible_token_account: Pubkey,
    escrow_token_account: Option<Pubkey>,
    receipt_account: Pubkey,
    proof_account: Option<Pubkey>,
    claim_distribution_args: ClaimDistributionArgs,
    payer: &Keypair,
) -> Result<(), BanksClientError> {
    let payer_pubkey = payer.pubkey();

    let ix = ClaimDistribution {
        mint,
        verification_config,
        instructions_sysvar: sysvar::instructions::ID,
        // ix accounts
        payer: payer_pubkey,
        permanent_delegate_authority,
        mint_account: distribution_mint,
        eligible_token_account,
        escrow_token_account,
        receipt_account,
        proof_account,
        transfer_hook_program: Pubkey::from(security_token_transfer_hook::id()),
        token_program: TOKEN_22_PROGRAM_ID,
        system_program: solana_program::system_program::id(),
    }
    .instruction(ClaimDistributionInstructionArgs {
        claim_distribution_args,
    });

    let dummy_ix = create_dummy_verification_from_instruction(&ix);

    send_tx(
        &banks_client,
        vec![dummy_ix, ix],
        &payer_pubkey,
        vec![payer],
    )
    .await
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

pub async fn create_claim_distribution_verification_config(
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
        CLAIM_DISTRIBUTION_DISCRIMINATOR,
        program_addresses,
        owner,
    )
    .await
}

pub async fn create_distribution_for_users(
    context: &mut ProgramTestContext,
    distribution_mint_keypair: &Keypair,
    mint_authority_pda: Pubkey,
    mint_creator: &Keypair,
    action_id: u64,
    distribution_ui_amount: u64,
    decimals: u8,
    leaves: &[Leaf],
) -> (MerkleTree, Pubkey, Pubkey, Pubkey) {
    let distribution_mint = &distribution_mint_keypair.pubkey();
    let tree = create_merkle_tree(&leaves);
    let merkle_root = tree.get_root();

    let (distribution_escrow_authority, _) =
        find_distribution_escrow_authority_pda(distribution_mint, action_id, &merkle_root);

    let distribution_escrow_token_account = get_associated_token_address_with_program_id(
        &distribution_escrow_authority,
        distribution_mint,
        &spl_token_2022::ID,
    );

    let create_distribution_escrow_args = CreateDistributionEscrowArgs {
        action_id,
        merkle_root,
    };

    let result = execute_create_distribution_escrow_account(
        &context.banks_client,
        distribution_mint.clone(),
        mint_authority_pda,
        mint_creator.pubkey(),
        distribution_escrow_authority,
        distribution_mint.clone(),
        distribution_escrow_token_account,
        create_distribution_escrow_args,
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    // Verification config for pre-minting tokens to the distribution escrow account
    let mint_verification_config_pda = create_mint_verification_config(
        context,
        &distribution_mint_keypair,
        mint_authority_pda.clone(),
        get_default_verification_programs(),
        Some(mint_creator),
    )
    .await;

    // Mint some tokens to the distribution escrow token account
    let total_distribution_amount = from_ui_amount(distribution_ui_amount, decimals);
    let result = mint_tokens_to(
        &mut context.banks_client,
        total_distribution_amount,
        distribution_mint.clone(),
        distribution_escrow_token_account.clone(),
        mint_authority_pda.clone(),
        mint_verification_config_pda.clone(),
        &mint_creator,
    )
    .await;
    assert_transaction_success(result);

    let claim_distribution_verification_config = create_claim_distribution_verification_config(
        context,
        &distribution_mint_keypair,
        mint_authority_pda,
        get_default_verification_programs(),
        Some(&mint_creator),
    )
    .await;

    let (permanent_delegate_authority, _) = find_permanent_delegate_pda(&distribution_mint);

    (
        tree,
        permanent_delegate_authority,
        distribution_escrow_token_account,
        claim_distribution_verification_config,
    )
}

pub async fn create_token_accounts_for_owners(
    context: &mut ProgramTestContext,
    owners: &[Keypair],
    mint_keypair: &Keypair,
) -> Vec<Pubkey> {
    let mut token_accounts = Vec::new();
    for owner in owners {
        let token_account_pubkey = create_spl_account(context, mint_keypair, owner).await;

        token_accounts.push(token_account_pubkey);
    }
    token_accounts
}

type EligibleTokenAccount = Pubkey;
type EligibleUiAmount = u64;
pub fn create_leaves(
    owners: &[(&EligibleTokenAccount, EligibleUiAmount)],
    mint_pubkey: &Pubkey,
    decimals: u8,
    action_id: u64,
) -> Vec<Leaf> {
    let mut leaves = Vec::new();
    for (token_account_pubkey, ui_amount) in owners {
        let leaf = Leaf::new(
            **token_account_pubkey,
            mint_pubkey.clone(),
            action_id,
            from_ui_amount(*ui_amount, decimals),
        );
        leaves.push(leaf);
    }
    leaves
}

pub async fn start_with_context_and_transfer_hook() -> ProgramTestContext {
    let mut pt = initialize_program();

    pt.add_program(
        "security_token_transfer_hook",
        Pubkey::from(security_token_transfer_hook::id()),
        None,
    );

    pt.prefer_bpf(false);
    add_dummy_verification_program(&mut pt);
    pt.start_with_context().await
}

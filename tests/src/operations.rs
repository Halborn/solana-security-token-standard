use security_token_client::{MINT_DISCRIMINATOR, SECURITY_TOKEN_ID};
use solana_program_test::*;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::{signature::Keypair, sysvar};
use spl_token_2022::extension::StateWithExtensionsOwned;
use spl_token_2022::state::{Account as TokenAccount, Mint as TokenMint};

use crate::helpers::assert_transaction_success;

#[tokio::test]
async fn test_basic_operations() {
    std::env::set_var("SBF_OUT_DIR", "../target/deploy");

    let mut pt = ProgramTest::new("security_token_program", SECURITY_TOKEN_ID, None);
    pt.prefer_bpf(true);

    let mint_keypair = Keypair::new();

    let context: solana_program_test::ProgramTestContext = pt.start_with_context().await;
    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let (mint_authority_pda, _bump) = Pubkey::find_program_address(
        &[
            b"mint.authority",
            &mint_keypair.pubkey().to_bytes(),
            &context.payer.pubkey().to_bytes(),
        ],
        &SECURITY_TOKEN_ID,
    );

    let spl_token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse::<Pubkey>()
        .unwrap();

    let destination_account =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            &context.payer.pubkey(),
            &mint_keypair.pubkey(),
            &spl_token_2022_program,
        );

    let initialize_mint_ix = security_token_client::InitializeMint {
        mint: mint_keypair.pubkey(),
        payer: context.payer.pubkey(),
        mint_authority_account: mint_authority_pda,
        token_program: spl_token_2022_program,
        system_program: solana_system_interface::program::ID,
        rent: sysvar::rent::ID,
    }
    .instruction(security_token_client::InitializeMintInstructionArgs {
        args: security_token_client::InitializeArgs {
            ix_mint: security_token_client::InitializeMintArgs {
                decimals: 6,
                mint_authority: context.payer.pubkey(),
                freeze_authority: None,
            },
            ix_metadata_pointer: None,
            ix_metadata: None,
            ix_scaled_ui_amount: None,
        },
    });

    let initialize_mint_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[initialize_mint_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint_keypair],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(initialize_mint_transaction)
        .await;
    assert_transaction_success(result);

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let create_destination_account_ix =
        spl_associated_token_account::instruction::create_associated_token_account_idempotent(
            &context.payer.pubkey(),
            &context.payer.pubkey(),
            &mint_keypair.pubkey(),
            &spl_token_2022_program,
        );

    let create_destination_account_tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[create_destination_account_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(create_destination_account_tx)
        .await;
    assert_transaction_success(result);

    let (verification_config_pda, _bump) = Pubkey::find_program_address(
        &[
            b"verification_config",
            mint_keypair.pubkey().as_ref(),
            &[MINT_DISCRIMINATOR],
        ],
        &SECURITY_TOKEN_ID,
    );

    let mint_account_before = context
        .banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .expect("mint account fetch before mint")
        .expect("mint account must exist");
    let mint_state_before =
        StateWithExtensionsOwned::<TokenMint>::unpack(mint_account_before.data.clone())
            .expect("mint state should deserialize before mint");
    assert_eq!(mint_state_before.base.supply, 0);

    let mint_ix = security_token_client::Mint {
        mint: mint_keypair.pubkey(),
        verification_config: verification_config_pda,
        instructions_sysvar: sysvar::instructions::ID,
        creator: context.payer.pubkey(),
        mint_info: mint_keypair.pubkey(),
        mint_authority: mint_authority_pda,
        destination_account,
        system_program: solana_system_interface::program::ID,
        token_program: spl_token_2022_program,
    }
    .instruction(security_token_client::MintInstructionArgs { amount: 1_000_000 });

    let recent_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

    let mint_transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[mint_ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        recent_blockhash,
    );

    let result = context
        .banks_client
        .process_transaction(mint_transaction)
        .await;
    assert_transaction_success(result);

    let mint_account_after = context
        .banks_client
        .get_account(mint_keypair.pubkey())
        .await
        .expect("mint account fetch after mint")
        .expect("mint account missing after mint");
    let mint_state_after =
        StateWithExtensionsOwned::<TokenMint>::unpack(mint_account_after.data.clone())
            .expect("mint state should deserialize");
    assert_eq!(mint_state_after.base.supply, 1_000_000);

    let destination_account_state = context
        .banks_client
        .get_account(destination_account)
        .await
        .expect("destination account fetch")
        .expect("destination ATA should exist");
    let token_account_after =
        StateWithExtensionsOwned::<TokenAccount>::unpack(destination_account_state.data.clone())
            .expect("token account should deserialize");
    assert_eq!(token_account_after.base.amount, 1_000_000);
}

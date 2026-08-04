use crate::helpers::find_transfer_hook_pda;
use security_token_client::{
    instructions::{
        InitializeVerificationConfigBuilder, UpdateVerificationConfigBuilder,
        INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR, MINT_DISCRIMINATOR, TRANSFER_DISCRIMINATOR,
        UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR,
    },
    types::{
        InitializeVerificationConfigArgs as ClientInitializeArgs,
        UpdateVerificationConfigArgs as ClientUpdateArgs,
        VerificationAccountMeta as ClientVerificationAccountMeta,
        VerificationProgramConfig as ClientVerificationProgramConfig,
    },
};
use security_token_program::instructions::{
    InitializeVerificationConfigArgs, UpdateVerificationConfigArgs, VerificationProgramConfig,
};
use solana_pubkey::Pubkey;
use solana_sdk::{
    account_info::AccountInfo, entrypoint::ProgramResult, instruction::Instruction, msg,
    program_error::ProgramError,
};
use spl_tlv_account_resolution::account::ExtraAccountMeta;
use spl_transfer_hook_interface::get_extra_account_metas_address;

// Simple dummy program processor
pub fn dummy_program_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Dummy program called with {} bytes", instruction_data.len());
    msg!("Dummy program: success");
    Ok(())
}

pub fn failing_dummy_program_processor(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Failing dummy program called");
    Err(ProgramError::Custom(0x1111))
}

pub fn mint_seed_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(accounts.len(), 5);
    assert_eq!(instruction_data[0], MINT_DISCRIMINATOR);
    let expected = Pubkey::find_program_address(&[accounts[1].key.as_ref()], program_id).0;
    assert_eq!(accounts[4].key, &expected);
    Ok(())
}

pub fn dynamic_meta(
    meta: ExtraAccountMeta,
) -> security_token_program::instructions::VerificationAccountMeta {
    security_token_program::instructions::VerificationAccountMeta {
        discriminator: meta.discriminator,
        address_config: meta.address_config,
        is_signer: meta.is_signer.into(),
        is_writable: meta.is_writable.into(),
    }
}

pub fn client_programs(
    programs: &[VerificationProgramConfig],
) -> Vec<ClientVerificationProgramConfig> {
    programs
        .iter()
        .map(|program| ClientVerificationProgramConfig {
            program_id: Pubkey::from(program.program_id),
            extra_accounts: program
                .extra_accounts
                .iter()
                .map(|meta| ClientVerificationAccountMeta {
                    discriminator: meta.discriminator,
                    address_config: meta.address_config,
                    is_signer: meta.is_signer,
                    is_writable: meta.is_writable,
                })
                .collect(),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn dynamic_initialize_config_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    instruction_discriminator: u8,
    programs: Vec<VerificationProgramConfig>,
) -> Instruction {
    dynamic_initialize_config_instruction_with_mode(
        payer,
        mint,
        mint_authority,
        config,
        instruction_discriminator,
        true,
        programs,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn dynamic_initialize_config_instruction_with_mode(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    instruction_discriminator: u8,
    cpi_mode: bool,
    programs: Vec<VerificationProgramConfig>,
) -> Instruction {
    let mut builder = InitializeVerificationConfigBuilder::new();
    builder
        .mint(mint)
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(payer)
        .payer(payer)
        .mint_account(mint)
        .config_account(config)
        .initialize_verification_config_args(ClientInitializeArgs {
            instruction_discriminator,
            cpi_mode,
            programs: client_programs(&programs),
        });
    if instruction_discriminator == TRANSFER_DISCRIMINATOR {
        builder
            .account_metas_pda(Some(get_extra_account_metas_address(
                &mint,
                &Pubkey::from(security_token_transfer_hook::id()),
            )))
            .transfer_hook_pda(Some(find_transfer_hook_pda(&mint).0))
            .transfer_hook_program(Some(Pubkey::from(security_token_transfer_hook::id())));
    }
    let mut instruction = builder.instruction();
    let args = InitializeVerificationConfigArgs {
        instruction_discriminator,
        cpi_mode,
        programs,
    };
    instruction.data = vec![INITIALIZE_VERIFICATION_CONFIG_DISCRIMINATOR];
    instruction.data.extend_from_slice(&args.to_bytes_inner());
    instruction
}

#[allow(clippy::too_many_arguments)]
pub fn dynamic_update_config_instruction(
    payer: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    config: Pubkey,
    instruction_discriminator: u8,
    cpi_mode: bool,
    offset: u8,
    programs: Vec<VerificationProgramConfig>,
) -> Instruction {
    let mut builder = UpdateVerificationConfigBuilder::new();
    builder
        .mint(mint)
        .verification_config_or_mint_authority(mint_authority)
        .instructions_sysvar_or_creator(payer)
        .payer(payer)
        .mint_account(mint)
        .config_account(config)
        .update_verification_config_args(ClientUpdateArgs {
            instruction_discriminator,
            cpi_mode,
            offset,
            programs: client_programs(&programs),
        });
    if instruction_discriminator == TRANSFER_DISCRIMINATOR {
        builder
            .account_metas_pda(Some(get_extra_account_metas_address(
                &mint,
                &Pubkey::from(security_token_transfer_hook::id()),
            )))
            .transfer_hook_pda(Some(find_transfer_hook_pda(&mint).0))
            .transfer_hook_program(Some(Pubkey::from(security_token_transfer_hook::id())));
    }
    let mut instruction = builder.instruction();
    let args = UpdateVerificationConfigArgs {
        instruction_discriminator,
        cpi_mode,
        offset,
        programs,
    };
    instruction.data = vec![UPDATE_VERIFICATION_CONFIG_DISCRIMINATOR];
    instruction.data.extend_from_slice(&args.to_bytes_inner());
    instruction
}

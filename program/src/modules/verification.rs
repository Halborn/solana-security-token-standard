//! Verification Module
//!
//! Handles authorization checks, compliance verification, and instruction validation
//! according to the Security Token specification.

use crate::token22_extensions::metadata::{Field, UpdateField};
use crate::token22_extensions::pausable::InitializePausable;
use crate::token22_extensions::permanent_delegate::InitializePermanentDelegate;
use crate::token22_extensions::scaled_ui_amount::InitializeScaledUiAmount;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use pinocchio::sysvars::Sysvar;
use pinocchio::sysvars::{instructions::Instructions, rent::Rent};
use pinocchio::ProgramResult;
use pinocchio_system::instructions::{CreateAccount, Transfer};
use pinocchio_token_2022::instructions::{AuthorityType, InitializeMint2, SetAuthority};
use pinocchio_token_2022::state::Mint;
use spl_pod::primitives::PodBool;
use spl_tlv_account_resolution::state::ExtraAccountMetaList;

use super::utils as verification_utils;
use crate::constants::{seeds, INSTRUCTION_ACCOUNTS_OFFSET, TRANSFER_HOOK_PROGRAM_ID};
use crate::error::SecurityTokenError;
use crate::instruction::SecurityTokenInstruction;
use crate::instructions::verification_config::TrimVerificationConfigArgs;
use crate::instructions::{InitializeMintArgs, UpdateMetadataArgs, VerifyArgs};
use crate::modules::{
    verify_instructions_sysvar, verify_mint_keys_match, verify_owner, verify_pda_keys_match,
    verify_rent_sysvar, verify_signer, verify_system_program, verify_token22_program,
    verify_transfer_hook_program, verify_writable,
};
use crate::state::{
    AccountDeserialize, AccountSerialize, MintAuthority, SecurityTokenDiscriminators,
    VerificationConfig,
};
use crate::token22_extensions::metadata::{InitializeTokenMetadata, RemoveKey, TokenMetadata};
use crate::token22_extensions::metadata_pointer::{InitializeMetadataPointer, MetadataPointer};
use crate::token22_extensions::transfer_hook::{
    InitializeExtraAccountMetaList, InitializeTransferHook, UpdateExtraAccountMetaList,
};
use crate::token22_extensions::{
    get_extension_data_bytes_for_variable_pack, get_extension_from_bytes, ExtensionType,
};
use crate::utils::find_extra_account_metas_pda;
use crate::{debug_log, utils};
use spl_tlv_account_resolution::account::ExtraAccountMeta;
use std::collections::{HashMap, HashSet, VecDeque};

/// Verification Module - handles all authorization and compliance checks
pub struct VerificationModule;

impl VerificationModule {
    /// Initialize mint with all extensions and metadata
    /// Creates initial configuration of the verification module  
    pub fn initialize_mint(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &InitializeMintArgs,
    ) -> ProgramResult {
        let decimals = args.ix_mint.decimals;
        let client_mint_authority = args.ix_mint.mint_authority;
        let freeze_authority = args.ix_mint.freeze_authority;
        let metadata_pointer_opt = &args.ix_metadata_pointer;
        let metadata_opt = &args.ix_metadata;
        let scaled_ui_amount_opt = &args.ix_scaled_ui_amount;

        let [mint_info, mint_authority_account, creator_info, token_program_info, system_program_info, rent_info] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_signer(creator_info)?;
        verify_signer(mint_info)?;
        verify_writable(creator_info)?;
        verify_writable(mint_info)?;
        verify_token22_program(token_program_info)?;
        verify_system_program(system_program_info)?;
        verify_rent_sysvar(rent_info)?;

        let (freeze_authority_pda, _bump) =
            utils::find_freeze_authority_pda(mint_info.key(), program_id);

        if freeze_authority != freeze_authority_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        let mut extensions_buf: [ExtensionType; 5] = [ExtensionType::Pausable; 5];
        let mut ext_count: usize = 0;
        let required_extensions: &[ExtensionType] = &[
            ExtensionType::PermanentDelegate,
            ExtensionType::TransferHook,
            ExtensionType::Pausable,
        ];
        for &ext in required_extensions {
            extensions_buf[ext_count] = ext;
            ext_count += 1;
        }

        // Add MetadataPointer if metadata is provided
        if metadata_opt.is_some() || metadata_pointer_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::MetadataPointer;
            ext_count += 1;
        }

        // Add ScaledUiAmount if provided by client
        if scaled_ui_amount_opt.is_some() {
            extensions_buf[ext_count] = ExtensionType::ScaledUiAmount;
            ext_count += 1;
        }

        // Calculate mint size with extensions (but without metadata TLV data)
        let mint_size = if ext_count == 0 {
            Mint::BASE_LEN
        } else {
            utils::calculate_mint_size_with_extensions(&extensions_buf[..ext_count])
        };

        let metadata_size = if let Some(metadata) = &metadata_opt {
            utils::calculate_metadata_tlv_size(metadata)?
        } else {
            0
        };

        let total_size = mint_size + metadata_size;
        let rent = Rent::from_account_info(rent_info)?;
        let required_lamports = rent.minimum_balance(total_size);
        let create_account_instruction = CreateAccount {
            from: creator_info,              // from (payer)
            to: mint_info,                   // to (new account)
            lamports: required_lamports,     // amount
            space: mint_size as u64,         // space (full size including metadata)
            owner: token_program_info.key(), // owner (SPL Token 2022 program)
        };

        create_account_instruction.invoke()?;

        // Calculate all PDAs that will be used for extensions and mint initialization
        let (transfer_hook_pda, _bump) = utils::find_transfer_hook_pda(mint_info.key(), program_id);
        let (permanent_delegate_pda, _bump) =
            utils::find_permanent_delegate_pda(mint_info.key(), program_id);
        let (pause_authority_pda, _bump) =
            utils::find_pause_authority_pda(mint_info.key(), program_id);

        let permanent_delegate_initialize = InitializePermanentDelegate {
            mint: mint_info,
            delegate: permanent_delegate_pda,
        };

        permanent_delegate_initialize.invoke()?;

        let transfer_hook_initialize = InitializeTransferHook {
            mint: mint_info,
            authority: transfer_hook_pda.into(),
            // TODO: A direct import of security_token_transfer_hook::id() causes build issues with the allocator, investigate later
            program_id: Some(TRANSFER_HOOK_PROGRAM_ID),
        };

        transfer_hook_initialize.invoke()?;

        let pausable_initialize = InitializePausable {
            mint: mint_info,
            authority: pause_authority_pda,
        };

        pausable_initialize.invoke()?;

        // Initialize MetadataPointer extension if needed and store metadata address for later use
        let metadata_account_address = if metadata_opt.is_some() || metadata_pointer_opt.is_some() {
            let (metadata_authority, metadata_address) =
                if let Some(client_metadata_pointer) = &metadata_pointer_opt {
                    // Use client-provided MetadataPointer configuration
                    let authority = client_metadata_pointer.authority.into();
                    let address = client_metadata_pointer.metadata_address.into();
                    (authority, address)
                } else {
                    // Fallback to default: creator as authority, mint as metadata storage
                    (Some(*creator_info.key()), Some(*mint_info.key()))
                };

            let metadata_pointer_initialize = InitializeMetadataPointer {
                mint: mint_info,
                authority: metadata_authority,
                metadata_address,
            };

            metadata_pointer_initialize.invoke()?;
            // Return the metadata address for later use
            metadata_address
        } else {
            None
        };

        // Initialize ScaledUiAmount extension if provided by client
        if let Some(scaled_ui_amount_config) = &scaled_ui_amount_opt {
            let scaled_ui_amount_initialize = InitializeScaledUiAmount {
                mint: mint_info,
                authority: scaled_ui_amount_config.authority.into(),
                multiplier: f64::from_le_bytes(scaled_ui_amount_config.multiplier),
            };

            scaled_ui_amount_initialize.invoke()?;
        }

        // Use client-provided authorities for base initialize to match client expectations/tests
        let initialize_mint_instruction = InitializeMint2 {
            mint: mint_info,
            decimals,
            mint_authority: &client_mint_authority,
            freeze_authority: Some(&freeze_authority),
            token_program: token_program_info.key(),
        };

        initialize_mint_instruction.invoke()?;

        // NOTE: Transfer mint authority to PDA, review it
        // Get mint authority PDA - this will be the mint authority for the token
        let (mint_authority_pda, mint_authority_bump) =
            utils::find_mint_authority_pda(mint_info.key(), creator_info.key(), program_id);

        if mint_authority_account.key() != &mint_authority_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        if !mint_authority_account.data_is_empty() || mint_authority_account.lamports() > 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        let mint_authority_config =
            MintAuthority::new(*mint_info.key(), *creator_info.key(), mint_authority_bump)?;

        let authority_account_required_lamports = rent.minimum_balance(MintAuthority::LEN);
        let create_mint_authority_instruction = CreateAccount {
            from: creator_info,                            // from (payer)
            to: mint_authority_account,                    // to (new PDA account)
            lamports: authority_account_required_lamports, // amount
            space: MintAuthority::LEN as u64,              // space (serialized state size)
            owner: program_id,                             // owner (program-owned account)
        };

        let bump_seed = [mint_authority_bump];
        let mint_authority_seeds = [
            Seed::from(seeds::MINT_AUTHORITY),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(creator_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let mint_authority_signer = Signer::from(&mint_authority_seeds);

        create_mint_authority_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
        {
            let mut data = mint_authority_account.try_borrow_mut_data()?;
            let config_bytes = mint_authority_config.to_bytes();
            data[..config_bytes.len()].copy_from_slice(&config_bytes);
        }

        let set_authority_instruction = SetAuthority {
            account: mint_info,
            authority: creator_info,
            authority_type: AuthorityType::MintTokens,
            new_authority: Some(&mint_authority_pda),
            token_program: token_program_info.key(),
        };

        set_authority_instruction.invoke()?;

        let Some(metadata) = metadata_opt else {
            return Ok(());
        };

        // Determine which account to use for metadata
        let metadata_account_info = if let Some(metadata_addr) = metadata_account_address {
            if metadata_addr == *mint_info.key() {
                // Metadata is stored in mint account (in-mint storage)
                mint_info
            } else {
                // Metadata is stored in external account - find it in accounts list
                accounts
                    .iter()
                    .find(|acc| acc.key() == &metadata_addr)
                    .ok_or(ProgramError::InvalidAccountData)?
            }
        } else {
            // No metadata pointer, shouldn't happen if we have metadata
            return Err(ProgramError::InvalidInstructionData);
        };

        let metadata_init_instruction = InitializeTokenMetadata {
            metadata: metadata_account_info,
            update_authority: mint_authority_account,
            mint: mint_info,
            mint_authority: mint_authority_account,
            name: &metadata.name,
            symbol: &metadata.symbol,
            uri: &metadata.uri,
        };

        metadata_init_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Add additional metadata fields if present - each field requires separate instruction
        if !metadata.additional_metadata.is_empty() {
            // Parse additional metadata from raw bytes and process each field
            utils::parse_additional_metadata(
                metadata.additional_metadata.as_slice(),
                |key, value| {
                    let update_field_instruction = UpdateField {
                        metadata: metadata_account_info,
                        update_authority: mint_authority_account,
                        field: Field::Key(key),
                        value,
                    };
                    update_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    /// Update metadata for existing mint
    /// Wrapper for Metadata token program extension
    pub fn update_metadata(
        _program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &UpdateMetadataArgs,
    ) -> ProgramResult {
        // Validate arguments
        args.validate()?;

        let [mint_authority, payer, mint_info, token_program_info, system_program_info] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_info)?;
        verify_token22_program(token_program_info)?;
        verify_system_program(system_program_info)?;
        verify_signer(payer)?;

        let mint_authority_data = MintAuthority::from_account_info(mint_authority)?;
        if &mint_authority_data.mint != mint_info.key() {
            return Err(ProgramError::InvalidAccountData);
        }

        // Get metadata account address from MetadataPointer extension
        let metadata_address: Option<Pubkey> = {
            let mint_data = mint_info.try_borrow_data()?;

            // Use pinocchio's get_extension_from_bytes instead of StateWithExtensions
            let metadata_pointer = get_extension_from_bytes::<MetadataPointer>(&mint_data)
                .ok_or(ProgramError::InvalidAccountData)?;

            metadata_pointer.metadata_address.into()
        }; // Borrow is released here
        let metadata_address = metadata_address.ok_or(ProgramError::InvalidAccountData)?;

        // Determine metadata account (could be mint itself or external account)
        let metadata_account_info = if metadata_address == *mint_info.key() {
            // Metadata is stored in mint account (in-mint storage)
            mint_info
        } else {
            // Metadata is stored in external account - would need to be passed in accounts
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Calculate current and new metadata sizes
        let new_metadata_size = utils::calculate_metadata_tlv_size(&args.metadata)?;
        // Get current metadata size to calculate the difference
        let current_metadata_size = {
            let mint_data = metadata_account_info.try_borrow_data()?;

            // Use pinocchio's get_extension_data_bytes_for_variable_pack to get current metadata
            if let Some(metadata_bytes) =
                get_extension_data_bytes_for_variable_pack::<TokenMetadata>(&mint_data)
            {
                // The length of the raw extension data includes TLV headers
                // For simplification, use the raw byte length as the current size
                metadata_bytes.len() + 4 // Add 4 bytes for TLV header (type + length)
            } else {
                // No metadata currently, so current size is 0
                0
            }
        };

        if new_metadata_size > current_metadata_size {
            let additional_metadata_space = new_metadata_size - current_metadata_size;
            let rent = Rent::get()?;
            let additional_rent = rent.minimum_balance(additional_metadata_space);
            let transfer = Transfer {
                from: payer,               // from (authority pays)
                to: metadata_account_info, // to (metadata account)
                lamports: additional_rent, // amount
            };
            transfer.invoke()?;
        }

        let bump_seed = [mint_authority_data.bump];
        let mint_authority_seeds = [
            Seed::from(seeds::MINT_AUTHORITY),
            Seed::from(mint_authority_data.mint.as_ref()),
            Seed::from(mint_authority_data.mint_creator.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let mint_authority_signer = Signer::from(&mint_authority_seeds);

        let update_field_instruction = UpdateField {
            metadata: metadata_account_info,
            update_authority: mint_authority,
            field: Field::Name,
            value: &args.metadata.name,
        };

        update_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Update symbol
        let update_symbol_instruction = UpdateField {
            metadata: metadata_account_info,
            update_authority: mint_authority,
            field: Field::Symbol,
            value: &args.metadata.symbol,
        };

        update_symbol_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Update URI
        let update_uri_instruction = UpdateField {
            metadata: metadata_account_info,
            update_authority: mint_authority,
            field: Field::Uri,
            value: &args.metadata.uri,
        };

        update_uri_instruction.invoke_signed(&[mint_authority_signer.clone()])?;

        // Handle additional metadata fields atomically
        let existing_additional_fields = {
            // Try to parse existing metadata using pinocchio's from_account_info
            if let Ok(existing_metadata) = TokenMetadata::from_account_info(metadata_account_info) {
                let mut fields_buffer: [[u8; 64]; 16] = [[0u8; 64]; 16]; // Static buffer for field names
                let mut field_lengths: [usize; 16] = [0; 16];
                let mut field_count = 0;

                // Parse existing additional metadata to extract all field keys
                let parse_result = utils::parse_additional_metadata(
                    existing_metadata.additional_metadata,
                    |key, _value| {
                        if field_count < 16 && key.len() <= 64 {
                            // Copy key bytes to static buffer
                            let key_bytes = key.as_bytes();
                            fields_buffer[field_count][..key_bytes.len()]
                                .copy_from_slice(key_bytes);
                            field_lengths[field_count] = key_bytes.len();
                            field_count += 1;
                        }
                        Ok(())
                    },
                );

                if parse_result.is_err() {
                    field_count = 0; // Reset to 0 if parsing failed
                }

                (fields_buffer, field_lengths, field_count)
            } else {
                let fields_buffer: [[u8; 64]; 16] = [[0u8; 64]; 16];
                let field_lengths: [usize; 16] = [0; 16];
                let field_count = 0;
                (fields_buffer, field_lengths, field_count)
            }
        };

        let (fields_buffer, field_lengths, field_count) = existing_additional_fields;

        // Step 2: Remove only existing fields that are NOT in the new metadata
        if field_count > 0 {
            for i in 0..field_count {
                let key_bytes = &fields_buffer[i][..field_lengths[i]];
                if let Ok(existing_key) = core::str::from_utf8(key_bytes) {
                    // Check if this existing field is in the new metadata by parsing new metadata
                    let mut found_in_new = false;

                    if !args.metadata.additional_metadata.is_empty() {
                        let _check_result = utils::parse_additional_metadata(
                            args.metadata.additional_metadata.as_slice(),
                            |new_key, _value| {
                                if existing_key == new_key {
                                    found_in_new = true;
                                }
                                Ok(())
                            },
                        );
                    }

                    if !found_in_new {
                        let remove_field_instruction = RemoveKey {
                            metadata: metadata_account_info,
                            update_authority: mint_authority,
                            key: existing_key,
                            idempotent: true, // don't error if key doesn't exist
                        };

                        remove_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
                        // Ignore errors since we're using idempotent flag
                    }
                }
            }
        }

        // Step 4: Add/update new additional metadata fields
        if args.metadata.additional_metadata.is_empty() {
            return Ok(());
        }
        let result = utils::parse_additional_metadata(
            args.metadata.additional_metadata.as_slice(),
            |key, value| {
                let update_field_instruction = UpdateField {
                    metadata: metadata_account_info,
                    update_authority: mint_authority,
                    field: Field::Key(key),
                    value,
                };
                update_field_instruction.invoke_signed(&[mint_authority_signer.clone()])?;
                Ok(())
            },
        );
        result.map_err(|_e| ProgramError::InvalidInstructionData)?;
        Ok(())
    }

    /// Verify specific operation against configured verification programs
    ///
    /// Client is responsible for deriving and providing the correct VerificationConfig PDA
    /// based on mint and instruction discriminator they want to verify.
    ///
    /// Accounts from index 3+ will be compared with accounts from verification program calls.
    /// Verification programs should be called with at least a full set of accounts in the exact order.
    pub fn verify_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        args: &VerifyArgs,
    ) -> ProgramResult {
        let mut instruction_data = Vec::with_capacity(1 + args.instruction_data.len());
        instruction_data.push(args.ix);
        instruction_data.extend_from_slice(&args.instruction_data);
        Self::verify_by_programs(program_id, accounts, args.ix, &instruction_data)?;
        Ok(())
    }

    /// Verify specific operation either through configured verification programs or mint authority
    /// Decides which method to use based on the PDA account provided in accounts[1]
    ///
    /// # Returns
    /// * `verified_mint_info` - The authorized Mint account (prevents mint substitution attacks in operations)
    /// * `cleaned_accounts` - Remaining instruction accounts after verification overhead
    pub fn verify_by_strategy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo],
        ix_discriminator: u8,
        instruction_data: &[u8],
    ) -> Result<(&'a AccountInfo, &'a [AccountInfo]), ProgramError> {
        let [mint_info, verification_config_or_mint_authority, instructions_sysvar_or_signer, _instruction_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        let config_data = verification_config_or_mint_authority.try_borrow_data()?;
        let state_discriminator = config_data
            .first()
            .ok_or(ProgramError::InvalidAccountData)?;
        let disc = SecurityTokenDiscriminators::try_from(*state_discriminator)?;
        match disc {
            SecurityTokenDiscriminators::VerificationConfigDiscriminator => {
                let (mint_info, cleaned_accounts) = Self::verify_by_programs(
                    program_id,
                    accounts,
                    ix_discriminator,
                    instruction_data,
                )?;
                Ok((mint_info, cleaned_accounts))
            }
            SecurityTokenDiscriminators::MintAuthorityDiscriminator => {
                let mint_authority_account = verification_config_or_mint_authority;
                let mint_creator_info = instructions_sysvar_or_signer;
                let mint_info = Self::verify_by_mint_authority(
                    program_id,
                    mint_info,
                    mint_authority_account,
                    mint_creator_info,
                )?;
                Ok((mint_info, &accounts[INSTRUCTION_ACCOUNTS_OFFSET..]))
            }
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    /// Verify that the provided signer corresponds to the original mint authority PDA.
    ///
    /// # Returns
    /// * `verified_mint_info` - The authorized Mint account (prevents mint substitution attacks in operations)
    pub fn verify_by_mint_authority<'a>(
        program_id: &Pubkey,
        mint_info: &'a AccountInfo,
        mint_authority: &'a AccountInfo,
        candidate_authority: &'a AccountInfo,
    ) -> Result<&'a AccountInfo, ProgramError> {
        verify_signer(candidate_authority)?;
        verify_owner(mint_authority, program_id)?;
        verify_owner(mint_info, &pinocchio_token_2022::ID)?;

        let data = mint_authority.try_borrow_data()?;
        if data.len() < MintAuthority::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let mint_authority_state = MintAuthority::try_from_bytes(&data)?;

        // CRITICAL: Verify that the authority is for the correct mint and signed by correct creator
        // These checks prevent using a valid MintAuthority PDA for a different mint/creator combination
        if mint_authority_state.mint != *mint_info.key() {
            return Err(ProgramError::InvalidAccountData);
        }

        if mint_authority_state.mint_creator != *candidate_authority.key() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Use stored bump with derive_pda for optimized PDA verification
        let expected_pda = mint_authority_state.derive_pda()?;

        if mint_authority.key() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        Ok(mint_info)
    }

    /// Verify specific operation against configured verification programs
    ///
    /// # Returns
    /// * `verified_mint_info` - The authorized Mint account (prevents mint substitution attacks in operations)
    /// * `cleaned_accounts` - Remaining instruction accounts after verification overhead
    pub fn verify_by_programs<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo],
        ix_discriminator: u8,
        instruction_data: &[u8],
    ) -> Result<(&'a AccountInfo, &'a [AccountInfo]), ProgramError> {
        let [mint_info, verification_config, instructions_sysvar, instruction_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // The data_is_empty verification config doesn't exist
        if verification_config.data_is_empty() {
            return Err(ProgramError::UninitializedAccount);
        }

        verify_instructions_sysvar(instructions_sysvar)?;
        verify_owner(verification_config, program_id)?;
        verify_owner(mint_info, &pinocchio_token_2022::ID)?;

        let config_data = VerificationConfig::from_account_info(verification_config)?;

        // CRITICAL: Verify that the config is for the expected instruction discriminator
        // This prevents instruction substitution attacks where attacker provides
        // a valid VerificationConfig PDA for instruction X when code expects instruction Y
        if config_data.instruction_discriminator != ix_discriminator {
            return Err(ProgramError::InvalidAccountData);
        }

        // Use stored bump with derive_pda for optimized PDA verification
        // PDA derivation includes mint and instruction_discriminator in seeds,
        // so successful verification cryptographically guarantees this config
        // is for the correct mint and instruction type
        let expected_config_pda = config_data.derive_pda(mint_info.key())?;

        if verification_config.key().ne(&expected_config_pda) {
            return Err(SecurityTokenError::InvalidVerificationConfigPda.into());
        }

        if config_data.verification_programs.is_empty() {
            // If no verification programs configured, allow
            return Ok((mint_info, instruction_accounts));
        }

        let cleaned_accounts = if config_data.cpi_mode {
            Self::execute_cpi_mode_verification(
                &config_data,
                instruction_accounts,
                instruction_data,
            )?
        } else {
            Self::execute_introspection_verification(
                &config_data,
                instructions_sysvar,
                instruction_accounts,
                instruction_data,
            )?;
            instruction_accounts
        };

        Ok((mint_info, cleaned_accounts))
    }

    fn execute_cpi_mode_verification<'a>(
        config: &VerificationConfig,
        instruction_accounts: &'a [AccountInfo],
        target_instruction_data: &[u8],
    ) -> Result<&'a [AccountInfo], ProgramError> {
        let verification_programs_count = config.verification_programs.len();
        if verification_programs_count > instruction_accounts.len() {
            debug_log!(
                "ERROR: Not enough instruction accounts provided for CPI mode verification. Expected at least {}, got {}",
                verification_programs_count,
                instruction_accounts.len()
            );
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        // NOTE: Remove verification program accounts from the end to the explicit instruction accounts
        // As a side effect it will help in verification programs implementations
        let target_accounts =
            &instruction_accounts[..instruction_accounts.len() - verification_programs_count];

        let target_account_metas: Vec<pinocchio::instruction::AccountMeta> = target_accounts
            .iter()
            .map(|acc| pinocchio::instruction::AccountMeta {
                pubkey: acc.key(),
                is_signer: acc.is_signer(),
                is_writable: acc.is_writable(),
            })
            .collect();

        let account_refs: Vec<_> = target_accounts.iter().collect();

        for program_id in config.verification_programs.iter() {
            let verification_instruction = pinocchio::instruction::Instruction {
                program_id,
                accounts: &target_account_metas,
                data: target_instruction_data,
            };
            pinocchio::program::slice_invoke(&verification_instruction, &account_refs)?;
        }

        Ok(target_accounts)
    }

    /// Execute introspection-based verification
    /// Validates that required verification programs were called before the current instruction
    /// by examining the instructions sysvar and comparing their accounts and arguments with current instruction accounts
    fn execute_introspection_verification(
        config: &VerificationConfig,
        instructions_sysvar: &AccountInfo,
        instruction_accounts: &[AccountInfo],
        target_instruction_data: &[u8],
    ) -> ProgramResult {
        // Get current instruction index
        let instructions = Instructions::try_from(instructions_sysvar)?;
        let current_index = instructions.load_current_index() as usize;

        let mut collected_accounts: Vec<Option<Vec<Pubkey>>> =
            vec![None; config.verification_programs.len()];
        let mut remaining_indices: HashSet<usize> =
            (0..config.verification_programs.len()).collect();
        let mut program_index_map: HashMap<Pubkey, VecDeque<usize>> = HashMap::new();

        for (idx, program) in config.verification_programs.iter().enumerate() {
            program_index_map
                .entry(*program)
                .or_default()
                .push_back(idx);
        }
        let mut verified_programs: Vec<(Pubkey, usize)> = Vec::new();

        if current_index > 0 {
            for instr_idx in (0..current_index).rev() {
                if remaining_indices.is_empty() {
                    break;
                }

                if let Ok(instruction) = instructions.load_instruction_at(instr_idx) {
                    let program_id = instruction.get_program_id();
                    if let Some(config_idx) =
                        program_index_map.get_mut(program_id).and_then(|indices| {
                            while let Some(&candidate_idx) = indices.front() {
                                if remaining_indices.contains(&candidate_idx) {
                                    return Some(candidate_idx);
                                }
                                indices.pop_front();
                            }
                            None
                        })
                    {
                        let instruction_data = instruction.get_instruction_data();
                        if instruction_data != target_instruction_data {
                            continue;
                        }

                        let mut accounts = Vec::new();
                        let mut account_idx = 0;

                        while let Ok(account_meta) = instruction.get_account_meta_at(account_idx) {
                            accounts.push(account_meta.key);
                            account_idx += 1;
                        }

                        collected_accounts[config_idx] = Some(accounts);
                        verified_programs.push((*program_id, instr_idx));
                        remaining_indices.remove(&config_idx);
                    }
                } else {
                    debug_log!("Could not load instruction at index {}", instr_idx);
                }
            }
        }

        #[cfg_attr(not(feature = "debug-logs"), allow(unused_variables))]
        if let Some(&missing_idx) = remaining_indices.iter().next() {
            debug_log!(
                "ERROR: Required verification program {} not found",
                crate::key_as_str!(config.verification_programs[missing_idx])
            );
            return Err(SecurityTokenError::VerificationProgramNotFound.into());
        }

        let all_verification_accounts: Vec<Vec<Pubkey>> = collected_accounts
            .into_iter()
            .map(|entry| entry.expect("missing verification program accounted above"))
            .collect();

        if !all_verification_accounts.is_empty() {
            let instruction_account_keys: Vec<Pubkey> =
                instruction_accounts.iter().map(|acc| *acc.key()).collect();
            verification_utils::validate_account_verification(
                &all_verification_accounts,
                &instruction_account_keys,
            )?;
        }
        Ok(())
    }

    /// Initialize verification configuration for an instruction
    ///
    /// Creates a VerificationConfig PDA for a specific instruction type.
    /// Each instruction (burn, transfer, mint, etc.) gets its own config.
    pub fn initialize_verification_config(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &crate::instructions::InitializeVerificationConfigArgs,
    ) -> ProgramResult {
        let [payer, mint_account, config_account, system_program_info, transfer_hook_accounts @ ..] =
            &accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        verify_mint_keys_match(verified_mint_info, &mint_account)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_owner(mint_account, &pinocchio_token_2022::ID)?;
        verify_system_program(system_program_info)?;

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        // Derive expected PDA address
        let (expected_config_pda, bump) =
            utils::find_verification_config_pda(mint_account.key(), discriminator, program_id);

        // Verify that the provided config account matches the expected PDA
        if *config_account.key() != expected_config_pda {
            return Err(ProgramError::InvalidAccountData);
        }

        // Check if account already exists
        if config_account.data_len() > 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // Create the VerificationConfig data first to calculate exact size
        let config =
            VerificationConfig::new(discriminator, args.cpi_mode, bump, args.program_addresses())?;

        let account_size = config.serialized_size();

        // Calculate rent for the account
        let rent = Rent::get()?;
        let required_lamports = rent.minimum_balance(account_size);

        // Create the PDA account
        let create_account_instruction = CreateAccount {
            from: payer,
            to: config_account,
            lamports: required_lamports,
            space: account_size as u64,
            owner: program_id,
        };

        // Create seeds for PDA signing
        let bump_seed = [bump];
        let discriminator_seed = [discriminator];
        let seeds = [
            Seed::from(seeds::VERIFICATION_CONFIG),
            Seed::from(mint_account.key().as_ref()),
            Seed::from(discriminator_seed.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let signer = Signer::from(&seeds);

        create_account_instruction.invoke_signed(&[signer])?;

        // Write data to the account using manual serialization
        let mut data = config_account.try_borrow_mut_data()?;
        let config_bytes = config.to_bytes();
        data[..config_bytes.len()].copy_from_slice(&config_bytes);

        if discriminator == SecurityTokenInstruction::Transfer as u8 {
            // Initialize transfer hook extra account metas
            Self::initialize_transfer_hook_account_metas(
                program_id,
                payer,
                mint_account,
                system_program_info,
                transfer_hook_accounts,
                *config_account.key(),
                args.program_addresses(),
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sync_transfer_hook_account_metas(
        program_id: &Pubkey,
        payer: &AccountInfo,
        mint_info: &AccountInfo,
        system_program_info: &AccountInfo,
        transfer_hook_accounts: &[AccountInfo],
        verification_config_pda: Pubkey,
        program_addresses: &[Pubkey],
        is_initialization: bool,
    ) -> ProgramResult {
        let [account_metas_pda_info, transfer_hook_pda_info, transfer_hook_program] =
            transfer_hook_accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_transfer_hook_program(transfer_hook_program)?;
        let (transfer_hook_pda, bump) = utils::find_transfer_hook_pda(mint_info.key(), program_id);
        verify_pda_keys_match(&transfer_hook_pda, transfer_hook_pda_info.key())?;
        let (account_metas_pda, _bump) = find_extra_account_metas_pda(mint_info.key());
        verify_pda_keys_match(&account_metas_pda, account_metas_pda_info.key())?;

        let mut account_metas: Vec<ExtraAccountMeta> = Vec::new();
        account_metas.push(ExtraAccountMeta {
            discriminator: 0,
            address_config: verification_config_pda,
            is_signer: PodBool(0),
            is_writable: PodBool(0),
        });

        for program_address in program_addresses {
            account_metas.push(ExtraAccountMeta {
                discriminator: 0,
                address_config: *program_address,
                is_signer: PodBool(0),
                is_writable: PodBool(0),
            });
        }

        let new_account_size = ExtraAccountMetaList::size_of(account_metas.len())
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let rent = Rent::get()?;

        if is_initialization {
            // Initialize: transfer full rent amount
            let required_lamports = rent.minimum_balance(new_account_size);
            let transfer = Transfer {
                from: payer,
                to: account_metas_pda_info,
                lamports: required_lamports,
            };
            transfer.invoke()?;
        } else {
            let current_account_size = account_metas_pda_info.data_len();
            if new_account_size > current_account_size {
                let old_rent = rent.minimum_balance(current_account_size);
                let new_rent = rent.minimum_balance(new_account_size);
                let additional_rent = new_rent - old_rent;
                let transfer = Transfer {
                    from: payer,
                    to: account_metas_pda_info,
                    lamports: additional_rent,
                };
                transfer.invoke()?;
            }
        }

        let bump_seed = [bump];
        let seeds = [
            Seed::from(seeds::TRANSFER_HOOK),
            Seed::from(mint_info.key().as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let signer = Signer::from(&seeds);
        if is_initialization {
            let instruction = InitializeExtraAccountMetaList {
                program_id: &TRANSFER_HOOK_PROGRAM_ID,
                extra_account_metas_pda: account_metas_pda_info,
                mint: mint_info,
                authority: transfer_hook_pda_info,
                system_program: system_program_info,
                metas: &account_metas,
            };
            instruction.invoke_signed(&[signer])?;
        } else {
            let instruction = UpdateExtraAccountMetaList {
                program_id: &TRANSFER_HOOK_PROGRAM_ID,
                extra_account_metas_pda: account_metas_pda_info,
                mint: mint_info,
                authority: transfer_hook_pda_info,
                system_program: system_program_info,
                recipient: Some(payer),
                metas: &account_metas,
            };
            instruction.invoke_signed(&[signer])?;
        }
        Ok(())
    }

    fn update_transfer_hook_account_metas(
        program_id: &Pubkey,
        payer: &AccountInfo,
        mint_info: &AccountInfo,
        system_program_info: &AccountInfo,
        transfer_hook_accounts: &[AccountInfo],
        verification_config_pda: Pubkey,
        new_program_addresses: &[Pubkey],
    ) -> ProgramResult {
        Self::sync_transfer_hook_account_metas(
            program_id,
            payer,
            mint_info,
            system_program_info,
            transfer_hook_accounts,
            verification_config_pda,
            new_program_addresses,
            false,
        )
    }

    fn initialize_transfer_hook_account_metas(
        program_id: &Pubkey,
        payer: &AccountInfo,
        mint_info: &AccountInfo,
        system_program_info: &AccountInfo,
        transfer_hook_accounts: &[AccountInfo],
        verification_config_pda: Pubkey,
        program_addresses: &[Pubkey],
    ) -> ProgramResult {
        Self::sync_transfer_hook_account_metas(
            program_id,
            payer,
            mint_info,
            system_program_info,
            transfer_hook_accounts,
            verification_config_pda,
            program_addresses,
            true,
        )
    }

    /// Update verification configuration for an instruction
    pub fn update_verification_config(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &crate::instructions::UpdateVerificationConfigArgs,
    ) -> ProgramResult {
        let [payer, mint_account, config_account, system_program_info, transfer_hook_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;
        verify_owner(config_account, program_id)?;
        verify_signer(payer)?;
        verify_writable(payer)?;
        verify_owner(mint_account, &pinocchio_token_2022::ID)?;
        verify_system_program(system_program_info)?;

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        let config = VerificationConfig::from_account_info(config_account)?;

        let expected_config_pda = config.derive_pda(mint_account.key())?;

        // Verify that the provided config account matches the expected PDA
        if *config_account.key() != expected_config_pda {
            return Err(ProgramError::InvalidAccountData);
        }

        // Check if account exists
        if config_account.data_len() == 0 {
            return Err(ProgramError::UninitializedAccount);
        }

        // Load existing config
        let mut existing_config = {
            let data = config_account.try_borrow_data()?;
            VerificationConfig::try_from_bytes(&data)
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Verify discriminator matches
        if existing_config.instruction_discriminator != discriminator {
            return Err(ProgramError::InvalidAccountData);
        }

        // Update cpi_mode
        existing_config.cpi_mode = args.cpi_mode;

        // Update verification programs starting at the specified offset
        let offset = args.offset() as usize;
        let new_programs = args.program_addresses();

        if offset + new_programs.len() > existing_config.verification_programs.len() {
            existing_config
                .verification_programs
                .resize(offset + new_programs.len(), Pubkey::default());
        }

        // Replace programs starting at offset
        for (i, &new_program) in new_programs.iter().enumerate() {
            existing_config.verification_programs[offset + i] = new_program;
        }

        existing_config.validate()?;

        let new_size = existing_config.serialized_size();
        let current_size = config_account.data_len();

        if new_size > current_size {
            let rent = Rent::get()?;
            let old_rent = rent.minimum_balance(current_size);
            let new_rent = rent.minimum_balance(new_size);
            let additional_rent = new_rent - old_rent;
            let transfer = Transfer {
                from: payer,
                to: config_account,
                lamports: additional_rent,
            };
            transfer.invoke()?;
            config_account.resize(new_size)?;
        }

        let config_bytes = existing_config.to_bytes();

        {
            let mut data = config_account.try_borrow_mut_data()?;
            data[..config_bytes.len()].copy_from_slice(&config_bytes);
        }

        if discriminator == SecurityTokenInstruction::Transfer as u8 {
            Self::update_transfer_hook_account_metas(
                program_id,
                payer,
                mint_account,
                system_program_info,
                transfer_hook_accounts,
                *config_account.key(),
                existing_config.verification_programs.as_slice(),
            )?;
        }
        Ok(())
    }

    /// Trim verification configuration to recover rent
    pub fn trim_verification_config(
        program_id: &Pubkey,
        verified_mint_info: &AccountInfo,
        accounts: &[AccountInfo],
        args: &TrimVerificationConfigArgs,
    ) -> ProgramResult {
        let [mint_account, config_account, recipient, system_program_info, transfer_hook_accounts @ ..] =
            accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        verify_mint_keys_match(verified_mint_info, &mint_account)?;
        verify_owner(config_account, program_id)?;
        verify_owner(mint_account, &pinocchio_token_2022::ID)?;
        verify_system_program(system_program_info)?;
        verify_writable(recipient)?;

        // Get instruction discriminator
        let discriminator = args.instruction_discriminator;

        let config = VerificationConfig::from_account_info(config_account)?;

        let expected_config_pda = config.derive_pda(mint_account.key())?;

        // Verify that the provided config account matches the expected PDA
        if *config_account.key() != expected_config_pda {
            return Err(ProgramError::InvalidAccountData);
        }

        // Check if account exists
        if config_account.data_len() == 0 {
            return Err(ProgramError::UninitializedAccount);
        }

        // Load existing config
        let mut existing_config = {
            let data = config_account.try_borrow_data()?;
            VerificationConfig::try_from_bytes(&data)
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Verify discriminator matches
        if existing_config.instruction_discriminator != discriminator {
            return Err(ProgramError::InvalidAccountData);
        }

        let current_program_count = existing_config.verification_programs.len();
        let new_size = args.size as usize;

        // Validate new size
        if new_size > current_program_count {
            return Err(ProgramError::InvalidArgument);
        }

        let (new_program_list, recovered_rent) = if args.close {
            let config_lamports = config_account.lamports();
            (&[][..], config_lamports)
        } else if new_size < current_program_count {
            // Trim: truncate program list, calculate recovered rent
            existing_config.verification_programs.truncate(new_size);
            existing_config.validate()?;

            let new_account_size = existing_config.serialized_size();
            let current_account_size = config_account.data_len();

            if new_account_size < current_account_size {
                let rent = Rent::get()?;
                let old_rent = rent.minimum_balance(current_account_size);
                let new_rent = rent.minimum_balance(new_account_size);
                let recovered = old_rent - new_rent;
                (existing_config.verification_programs.as_slice(), recovered)
            } else {
                // No size change, just update data
                let config_bytes = existing_config.to_bytes();
                let mut data = config_account.try_borrow_mut_data()?;
                data[..config_bytes.len()].copy_from_slice(&config_bytes);
                return Ok(());
            }
        } else {
            return Ok(());
        };

        // Update transfer hook BEFORE any balance changes
        if discriminator == SecurityTokenInstruction::Transfer as u8 {
            Self::update_transfer_hook_account_metas(
                program_id,
                recipient,
                mint_account,
                system_program_info,
                transfer_hook_accounts,
                *config_account.key(),
                new_program_list,
            )?;
        }

        if args.close {
            // Close the account completely
            *config_account.try_borrow_mut_lamports()? = 0;
            *recipient.try_borrow_mut_lamports()? = recipient
                .lamports()
                .checked_add(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;
            config_account.resize(0)?;
        } else {
            let new_account_size = existing_config.serialized_size();
            config_account.resize(new_account_size)?;

            let config_bytes = existing_config.to_bytes();
            {
                let mut data = config_account.try_borrow_mut_data()?;
                data[..config_bytes.len()].copy_from_slice(&config_bytes);
            }

            *config_account.try_borrow_mut_lamports()? = config_account
                .lamports()
                .checked_sub(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;

            *recipient.try_borrow_mut_lamports()? = recipient
                .lamports()
                .checked_add(recovered_rent)
                .ok_or(ProgramError::InsufficientFunds)?;
        }
        Ok(())
    }
}

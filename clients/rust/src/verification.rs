use crate::{accounts::VerificationConfig, types::VerificationAccountMeta};
use borsh::BorshDeserialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use spl_tlv_account_resolution::account::ExtraAccountMeta;

pub const MAX_V0_TRANSACTION_SIZE: usize = 1232;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedVerificationGroup {
    pub program_id: Pubkey,
    pub extra_accounts: Vec<AccountMeta>,
}

pub fn decode_verification_config(data: &[u8]) -> Result<VerificationConfig, std::io::Error> {
    VerificationConfig::try_from_slice(data)
}

#[cfg(feature = "fetch")]
pub fn fetch_verification_config_strict(
    rpc: &solana_client::rpc_client::RpcClient,
    address: &Pubkey,
) -> Result<crate::shared::DecodedAccount<VerificationConfig>, std::io::Error> {
    let account = rpc
        .get_account(address)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;
    let data = decode_verification_config(&account.data)?;
    Ok(crate::shared::DecodedAccount {
        address: *address,
        account,
        data,
    })
}

pub fn resolve_verification_accounts<F>(
    config: &VerificationConfig,
    canonical_accounts: &[(AccountMeta, Option<Vec<u8>>)],
    instruction_data: &[u8],
    mut fetch_account_data: F,
) -> Result<Vec<ResolvedVerificationGroup>, ProgramError>
where
    F: FnMut(Pubkey) -> Result<Option<Vec<u8>>, ProgramError>,
{
    let mut groups = Vec::with_capacity(config.programs.len());
    for program in &config.programs {
        let mut local_accounts = canonical_accounts.to_vec();
        let mut extra_accounts = Vec::with_capacity(program.extra_accounts.len());
        for declaration in &program.extra_accounts {
            let extra_meta = to_extra_account_meta(declaration);
            let resolved = extra_meta.resolve(instruction_data, &program.program_id, |index| {
                local_accounts
                    .get(index)
                    .map(|(meta, data)| (&meta.pubkey, data.as_deref()))
            })?;
            let data = fetch_account_data(resolved.pubkey)?;
            local_accounts.push((resolved.clone(), data));
            extra_accounts.push(resolved);
        }
        groups.push(ResolvedVerificationGroup {
            program_id: program.program_id,
            extra_accounts,
        });
    }
    Ok(groups)
}

pub fn append_verification_accounts(
    instruction: &Instruction,
    groups: &[ResolvedVerificationGroup],
) -> Instruction {
    let mut instruction = instruction.clone();
    for group in groups {
        instruction
            .accounts
            .push(AccountMeta::new_readonly(group.program_id, false));
        instruction
            .accounts
            .extend_from_slice(&group.extra_accounts);
    }
    instruction
}

pub fn build_introspection_instructions(
    canonical_accounts: &[AccountMeta],
    instruction_data: &[u8],
    groups: &[ResolvedVerificationGroup],
) -> Vec<Instruction> {
    groups
        .iter()
        .map(|group| {
            let mut accounts = canonical_accounts.to_vec();
            accounts.extend_from_slice(&group.extra_accounts);
            Instruction {
                program_id: group.program_id,
                accounts,
                data: instruction_data.to_vec(),
            }
        })
        .collect()
}

pub fn validate_v0_transaction_size(serialized_transaction: &[u8]) -> Result<(), ProgramError> {
    if serialized_transaction.len() > MAX_V0_TRANSACTION_SIZE {
        Err(ProgramError::InvalidInstructionData)
    } else {
        Ok(())
    }
}

fn to_extra_account_meta(meta: &VerificationAccountMeta) -> ExtraAccountMeta {
    ExtraAccountMeta {
        discriminator: meta.discriminator,
        address_config: meta.address_config,
        is_signer: meta.is_signer.into(),
        is_writable: meta.is_writable.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VerificationProgramConfig;
    use spl_tlv_account_resolution::{account::ExtraAccountMeta, seeds::Seed};

    fn generated_meta(meta: ExtraAccountMeta) -> VerificationAccountMeta {
        VerificationAccountMeta {
            discriminator: meta.discriminator,
            address_config: meta.address_config,
            is_signer: meta.is_signer.into(),
            is_writable: meta.is_writable.into(),
        }
    }

    #[test]
    fn resolves_previous_extra_and_builds_instructions() {
        let program_id = Pubkey::new_unique();
        let fixed = Pubkey::new_unique();
        let pda = ExtraAccountMeta::new_with_seeds(&[Seed::AccountKey { index: 1 }], false, true)
            .unwrap();
        let config = VerificationConfig {
            discriminator: 1,
            instruction_discriminator: 12,
            cpi_mode: false,
            bump: 1,
            programs: vec![VerificationProgramConfig {
                program_id,
                extra_accounts: vec![
                    VerificationAccountMeta {
                        discriminator: 0,
                        address_config: fixed.to_bytes(),
                        is_signer: false,
                        is_writable: false,
                    },
                    generated_meta(pda),
                ],
            }],
        };
        let canonical = vec![(AccountMeta::new_readonly(Pubkey::new_unique(), false), None)];
        let groups = resolve_verification_accounts(&config, &canonical, &[12], |_| Ok(None))
            .expect("routing resolves");
        let expected_pda = Pubkey::find_program_address(&[fixed.as_ref()], &program_id).0;
        assert_eq!(groups[0].extra_accounts[0].pubkey, fixed);
        assert_eq!(groups[0].extra_accounts[1].pubkey, expected_pda);

        let target = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![12],
        };
        let appended = append_verification_accounts(&target, &groups);
        assert_eq!(appended.accounts.len(), 3);
        assert!(target.accounts.is_empty());
        let introspection =
            build_introspection_instructions(&[canonical[0].0.clone()], &target.data, &groups);
        assert_eq!(introspection[0].program_id, program_id);
        assert_eq!(introspection[0].accounts.len(), 3);
    }

    #[test]
    fn rejects_trailing_config_and_oversized_v0_transaction() {
        let config = VerificationConfig {
            discriminator: 1,
            instruction_discriminator: 12,
            cpi_mode: false,
            bump: 1,
            programs: vec![],
        };
        let mut bytes = borsh::to_vec(&config).unwrap();
        bytes.push(1);
        assert!(decode_verification_config(&bytes).is_err());
        assert!(validate_v0_transaction_size(&[0; MAX_V0_TRANSACTION_SIZE]).is_ok());
        assert!(validate_v0_transaction_size(&[0; MAX_V0_TRANSACTION_SIZE + 1]).is_err());
    }

    #[test]
    fn nested_config_matches_wire_fixture() {
        let config = VerificationConfig {
            discriminator: 1,
            instruction_discriminator: 12,
            cpi_mode: false,
            bump: 1,
            programs: vec![VerificationProgramConfig {
                program_id: Pubkey::new_from_array([7; 32]),
                extra_accounts: vec![VerificationAccountMeta {
                    discriminator: 0,
                    address_config: [9; 32],
                    is_signer: false,
                    is_writable: true,
                }],
            }],
        };
        let mut expected = vec![1, 12, 0, 1];
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&[0, 1]);
        assert_eq!(borsh::to_vec(&config).unwrap(), expected);
        assert_eq!(decode_verification_config(&expected).unwrap(), config);
    }
}

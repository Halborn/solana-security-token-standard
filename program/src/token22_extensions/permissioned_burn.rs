//! Permissioned Burn extension.

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_token_2022::state::Mint;

use crate::token22_extensions::{
    write_bytes, BaseState, Extension, ExtensionType, EXTENSIONS_PADDING, EXTENSION_LENGTH_LEN,
    EXTENSION_START_OFFSET, EXTENSION_TYPE_LEN, UNINIT_BYTE,
};

// The instruction discriminator for the Token-2022 `PermissionedBurn` extension.
pub const PERMISSIONED_BURN_INSTRUCTION: u8 = 46;

#[repr(u8)]
enum PermissionedBurnIx {
    Initialize = 0,
    /// Part of the Token-2022 ABI, but intentionally unsupported by SSTS:
    /// all burns use `BurnChecked` to validate mint decimals.
    #[allow(dead_code)]
    Burn = 1,
    BurnChecked = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PermissionedBurnConfig {
    pub authority: Pubkey,
}

impl Extension for PermissionedBurnConfig {
    const TYPE: ExtensionType = ExtensionType::PermissionedBurn;
    const LEN: usize = 32;
    const BASE_STATE: BaseState = BaseState::Mint;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PermissionedBurnState {
    NotPresent,
    PresentWithoutAuthority,
    PresentWithAuthority(Pubkey),
    Malformed,
}

pub fn get_permissioned_burn_state(mint_data: &[u8]) -> PermissionedBurnState {
    let extension_offset = Mint::BASE_LEN + EXTENSIONS_PADDING + EXTENSION_START_OFFSET;
    // No extensions
    if mint_data.len() == Mint::BASE_LEN {
        return PermissionedBurnState::NotPresent;
    }
    // Not enough data for extensions
    let Some(mut extensions) = mint_data.get(extension_offset..) else {
        return PermissionedBurnState::Malformed;
    };
    let mut state = PermissionedBurnState::NotPresent;

    while !extensions.is_empty() {
        // Each extension entry is a TLV (type-length-value) structure:
        // - [0..2]: extension type (2 bytes, u16)
        // - [2..4]: extension length (2 bytes, u16)
        let Some(header) = extensions.get(..EXTENSION_TYPE_LEN + EXTENSION_LENGTH_LEN) else {
            return PermissionedBurnState::Malformed;
        };
        let extension_type = u16::from_le_bytes([header[0], header[1]]);
        let extension_len = u16::from_le_bytes([header[2], header[3]]) as usize;

        if extension_type == ExtensionType::Uninitialized as u16 && extension_len == 0 {
            break;
        }

        let Some(entry_len) = header.len().checked_add(extension_len) else {
            return PermissionedBurnState::Malformed;
        };
        let Some(entry) = extensions.get(header.len()..entry_len) else {
            return PermissionedBurnState::Malformed;
        };

        // If the extension is a permissioned burn extension, check its state
        if extension_type == ExtensionType::PermissionedBurn as u16 {
            if !matches!(state, PermissionedBurnState::NotPresent) {
                // Multiple Permissioned Burn extensions are not allowed.
                return PermissionedBurnState::Malformed;
            }

            let Ok(authority): Result<Pubkey, _> = entry.try_into() else {
                // Permissioned Burn authority must be exactly 32 bytes.
                return PermissionedBurnState::Malformed;
            };

            state = if authority == [0; 32] {
                PermissionedBurnState::PresentWithoutAuthority
            } else {
                PermissionedBurnState::PresentWithAuthority(authority)
            };
        }

        // Move to the next extension entry
        extensions = &extensions[entry_len..];
    }

    state
}

pub struct InitializePermissionedBurn<'a> {
    /// The mint to initialize the permissioned burn config
    pub mint: &'a AccountInfo,
    /// The public key for the account that can burn tokens from any account
    pub authority: Pubkey,
}

impl InitializePermissionedBurn<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas = [AccountMeta::writable(self.mint.key())];
        // Instruction data layout:
        // - [0]: Token-2022 instruction discriminator (46 = Permissioned Burn)
        // - [1]: Permissioned Burn sub-instruction (0 = Initialize)
        // - [2..34]: permissioned burn authority (32-byte Pubkey)
        let mut instruction_data = [UNINIT_BYTE; 34];
        write_bytes(
            &mut instruction_data[..2],
            &[
                PERMISSIONED_BURN_INSTRUCTION,
                PermissionedBurnIx::Initialize as u8,
            ],
        );
        write_bytes(&mut instruction_data[2..], &self.authority);
        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: unsafe { core::slice::from_raw_parts(instruction_data.as_ptr() as _, 34) },
        };

        invoke_signed(&instruction, &[self.mint], signers)
    }
}

pub struct PermissionedBurnChecked<'a> {
    /// Source token account from which tokens will be burned.
    pub account: &'a AccountInfo,
    /// Mint associated with the source token account.
    pub mint: &'a AccountInfo,
    /// Authority configured by the mint's Permissioned Burn extension.
    pub permissioned_burn_authority: &'a AccountInfo,
    /// Owner, delegate, or permanent delegate authorized to burn tokens
    /// from the source token account.
    ///
    /// Must sign the CPI. This account may be the same account as
    /// `permissioned_burn_authority`.
    pub authority: &'a AccountInfo,
    /// Number of tokens to burn, expressed in the mint's base units.
    pub amount: u64,
    /// Expected number of decimals configured on the mint.
    pub decimals: u8,
}

impl PermissionedBurnChecked<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let account_metas = burn_checked_account_metas(
            self.account.key(),
            self.mint.key(),
            self.permissioned_burn_authority.key(),
            self.authority.key(),
        );

        let account_infos = [
            self.account,
            self.mint,
            self.permissioned_burn_authority,
            self.authority,
        ];

        // Token-2022 `PermissionedBurnChecked` instruction data layout:
        //
        // - [0]: Permissioned Burn instruction discriminator
        // - [1]: `BurnChecked` sub-instruction discriminator
        // - [2..10]: amount as a little-endian `u64`
        // - [10]: expected mint decimals

        // TODO: Benchmark a `MaybeUninit` implementation and use it only if it
        // provides a measurable CU reduction.
        let mut instruction_data = [0u8; 11];
        instruction_data[0] = PERMISSIONED_BURN_INSTRUCTION;
        instruction_data[1] = PermissionedBurnIx::BurnChecked as u8;
        instruction_data[2..10].copy_from_slice(&self.amount.to_le_bytes());
        instruction_data[10] = self.decimals;
        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(&instruction, &account_infos, signers)
    }
}

#[inline(always)]
fn burn_checked_account_metas<'a>(
    account: &'a Pubkey,
    mint: &'a Pubkey,
    permissioned_burn_authority: &'a Pubkey,
    authority: &'a Pubkey,
) -> [AccountMeta<'a>; 4] {
    [
        AccountMeta::writable(account),
        AccountMeta::writable(mint),
        AccountMeta::readonly_signer(permissioned_burn_authority),
        AccountMeta::readonly_signer(authority),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_constants_match_token_2022_v11() {
        assert_eq!(
            ExtensionType::PermissionedBurn.to_bytes(),
            28u16.to_le_bytes(),
        );

        assert_eq!(PERMISSIONED_BURN_INSTRUCTION, 46);

        assert_eq!(PermissionedBurnIx::Initialize as u8, 0);
        assert_eq!(PermissionedBurnIx::Burn as u8, 1);
        assert_eq!(PermissionedBurnIx::BurnChecked as u8, 2);

        assert_eq!(core::mem::size_of::<PermissionedBurnConfig>(), 32,);
    }

    #[test]
    fn initialize_data_matches_token_2022_v11_abi() {
        // Token-2022 v11 wire format for initializing Permissioned Burn:
        //
        // - byte 0: 46 — `PermissionedBurnExtension` discriminator;
        // - byte 1: 0  — `Initialize` sub-instruction;
        // - bytes 2..34: 32-byte permissioned burn authority.
        let authority = [7u8; 32];
        let mut data = [0u8; 34];

        data[..2].copy_from_slice(&[
            PERMISSIONED_BURN_INSTRUCTION,
            PermissionedBurnIx::Initialize as u8,
        ]);
        data[2..].copy_from_slice(&authority);

        assert_eq!(&data[..2], &[46, 0]);
        assert_eq!(&data[2..], &authority);
    }

    #[test]
    fn burn_checked_data_matches_token_2022_v11_abi() {
        // Token-2022 v11 wire format for Permissioned BurnChecked:
        //
        // - byte 0: 46 — `PermissionedBurnExtension` discriminator;
        // - byte 1: 2  — `BurnChecked` sub-instruction;
        // - bytes 2..10: amount encoded as a little-endian u64;
        // - byte 10: expected mint decimals.

        // le bytes: [1, 2, 3, 4, 5, 6, 7, 8]
        let amount = 0x0807_0605_0403_0201u64;
        let mut data = [0u8; 11];

        data[..2].copy_from_slice(&[
            PERMISSIONED_BURN_INSTRUCTION,
            PermissionedBurnIx::BurnChecked as u8,
        ]);
        data[2..10].copy_from_slice(&amount.to_le_bytes());
        data[10] = 9;

        assert_eq!(data, [46, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9],);
    }

    #[test]
    fn burn_checked_accounts_match_abi_and_allow_duplicate_signer() {
        let account = [1u8; 32];
        let mint = [2u8; 32];
        let authority = [3u8; 32];
        let metas = burn_checked_account_metas(&account, &mint, &authority, &authority);

        assert_eq!(metas[0].pubkey, &account);
        assert!(metas[0].is_writable && !metas[0].is_signer);
        assert_eq!(metas[1].pubkey, &mint);
        assert!(metas[1].is_writable && !metas[1].is_signer);
        assert_eq!(metas[2].pubkey, &authority);
        assert!(!metas[2].is_writable && metas[2].is_signer);
        assert_eq!(metas[3].pubkey, &authority);
        assert!(!metas[3].is_writable && metas[3].is_signer);
    }

    fn mint_with_tlv(tlv: &[u8]) -> Vec<u8> {
        let mut mint = vec![0; Mint::BASE_LEN + EXTENSIONS_PADDING + EXTENSION_START_OFFSET];
        mint.extend_from_slice(tlv);
        mint
    }

    fn entry(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut entry = Vec::with_capacity(4 + data.len());
        entry.extend_from_slice(&extension_type.to_le_bytes());
        entry.extend_from_slice(&(data.len() as u16).to_le_bytes());
        entry.extend_from_slice(data);
        entry
    }

    #[test]
    fn parser_handles_absent_and_optional_authority() {
        assert_eq!(
            get_permissioned_burn_state(&[0; Mint::BASE_LEN]),
            PermissionedBurnState::NotPresent
        );
        assert_eq!(
            get_permissioned_burn_state(&mint_with_tlv(&entry(28, &[0; 32]))),
            PermissionedBurnState::PresentWithoutAuthority
        );

        let authority = [9u8; 32];
        assert_eq!(
            get_permissioned_burn_state(&mint_with_tlv(&entry(28, &authority))),
            PermissionedBurnState::PresentWithAuthority(authority)
        );
    }

    #[test]
    fn parser_skips_known_and_unknown_extensions() {
        let authority = [9u8; 32];
        let tlv = [
            entry(ExtensionType::PermanentDelegate as u16, &[1; 32]),
            entry(99, &[2; 7]),
            entry(28, &authority),
        ]
        .concat();
        assert_eq!(
            get_permissioned_burn_state(&mint_with_tlv(&tlv)),
            PermissionedBurnState::PresentWithAuthority(authority)
        );
    }

    #[test]
    fn parser_fails_closed_for_malformed_tlv() {
        let cases = [
            vec![28],
            vec![28, 0, 32, 0, 1],
            entry(28, &[1; 31]),
            [entry(28, &[1; 32]), entry(28, &[2; 32])].concat(),
        ];
        for tlv in cases {
            assert_eq!(
                get_permissioned_burn_state(&mint_with_tlv(&tlv)),
                PermissionedBurnState::Malformed
            );
        }
    }
}

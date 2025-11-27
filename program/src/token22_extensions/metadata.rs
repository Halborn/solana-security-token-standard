extern crate alloc;

use alloc::vec::Vec;
use core::str;

use pinocchio::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction, Signer},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::token22_extensions::{
    get_extension_data_bytes_for_variable_pack, BaseState, Extension, ExtensionType,
};

/// State for Metadata for a token
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct TokenMetadata<'a> {
    /// The authority that can sign to update the metadata
    pub update_authority: Pubkey,
    /// The associated mint, used to counter spoofing to be sure that metadata
    /// belongs to a particular mint
    pub mint: Pubkey,
    /// The length of the name
    pub name_len: u32,
    /// The longer name of the token
    pub name: &'a str,
    /// The length of the symbol
    pub symbol_len: u32,
    /// The shortened symbol for the token
    pub symbol: &'a str,
    /// The length of the URI
    pub uri_len: u32,
    /// The URI pointing to richer metadata
    pub uri: &'a str,
    /// The length of the additional metadata
    pub additional_metadata_len: u32,
    /// The additional metadata about the token as key-value pairs. The program
    /// must avoid storing the same key twice.
    pub additional_metadata: &'a [u8],
}

impl TokenMetadata<'_> {
    /// The fixed size of the metadata account: 80 bytes
    /// [32 (update_authority) + 32 (mint) + 4 (size of name ) + 4 (size of symbol) + 4 (size of uri) + 4 (size of additional_metadata)]
    pub const SIZE_METADATA_LEN: usize = 80;

    /// Return a `TokenMetadata` from the given account info.
    ///
    /// This method performs owner and length validation on `AccountInfo`, safe borrowing
    /// the account data.
    #[inline(always)]
    pub fn from_account_info<'a>(
        account_info: &AccountInfo,
    ) -> Result<TokenMetadata<'a>, ProgramError> {
        if account_info.data_len() < Self::SIZE_METADATA_LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        if !account_info.is_owned_by(&pinocchio_token_2022::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        let account_data = account_info.try_borrow_data()?;

        let metadata_bytes =
            get_extension_data_bytes_for_variable_pack::<TokenMetadata>(account_data.as_ref())
                .ok_or(ProgramError::InvalidAccountData)?;

        Self::from_bytes(metadata_bytes)
    }

    pub(crate) fn from_bytes<'a>(data: &[u8]) -> Result<TokenMetadata<'a>, ProgramError> {
        if data.len() < Self::SIZE_METADATA_LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let mut offset: usize = 0;

        let update_authority = unsafe { &*(data.as_ptr() as *const [u8; 32]) };

        offset += 32;

        let mint = unsafe { &*(data.as_ptr().add(offset) as *const [u8; 32]) };

        offset += 32;

        let name_len =
            &u32::from_le_bytes(unsafe { *(data.as_ptr().add(offset) as *const [u8; 4]) });

        offset += 4;

        let name_bytes =
            unsafe { core::slice::from_raw_parts(data.as_ptr().add(offset), *name_len as usize) };
        let name =
            core::str::from_utf8(name_bytes).map_err(|_| ProgramError::InvalidAccountData)?;

        offset += *name_len as usize;

        let symbol_len =
            &u32::from_le_bytes(unsafe { *(data.as_ptr().add(offset) as *const [u8; 4]) });

        offset += 4;

        let symbol_bytes =
            unsafe { core::slice::from_raw_parts(data.as_ptr().add(offset), *symbol_len as usize) };
        let symbol =
            core::str::from_utf8(symbol_bytes).map_err(|_| ProgramError::InvalidAccountData)?;

        offset += *symbol_len as usize;

        let uri_len =
            &u32::from_le_bytes(unsafe { *(data.as_ptr().add(offset) as *const [u8; 4]) });

        offset += 4;

        let uri_bytes =
            unsafe { core::slice::from_raw_parts(data.as_ptr().add(offset), *uri_len as usize) };
        let uri = core::str::from_utf8(uri_bytes).map_err(|_| ProgramError::InvalidAccountData)?;

        offset += *uri_len as usize;

        let additional_metadata_len =
            &u32::from_le_bytes(unsafe { *(data.as_ptr().add(offset) as *const [u8; 4]) });

        offset += 4;

        let additional_metadata =
            unsafe { core::slice::from_raw_parts(data.as_ptr().add(offset), data.len() - offset) };

        Ok(TokenMetadata {
            update_authority: *update_authority,
            mint: *mint,
            name_len: *name_len,
            name,
            symbol_len: *symbol_len,
            symbol,
            uri_len: *uri_len,
            uri,
            additional_metadata_len: *additional_metadata_len,
            additional_metadata,
        })
    }
}

impl Extension for TokenMetadata<'_> {
    const TYPE: ExtensionType = ExtensionType::TokenMetadata;
    const LEN: usize = Self::SIZE_METADATA_LEN;
    const BASE_STATE: BaseState = BaseState::Mint;
}

/// Field type for metadata updates
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Field<'a> {
    /// The name field, corresponding to `TokenMetadata.name`
    Name = 0,
    /// The symbol field, corresponding to `TokenMetadata.symbol`
    Symbol = 1,
    /// The uri field, corresponding to `TokenMetadata.uri`
    Uri = 2,
    /// A user field, whose key is given by the associated string
    Key(&'a str) = 3,
}

impl Field<'_> {
    pub fn to_u8(&self) -> u8 {
        match self {
            Field::Name => 0,
            Field::Symbol => 1,
            Field::Uri => 2,
            Field::Key(_) => 3,
        }
    }
}

/// Wrapper for InitializeTokenMetadata instruction
pub struct InitializeTokenMetadata<'a> {
    /// The metadata account to initialize
    pub metadata: &'a AccountInfo,
    /// The authority that can update the metadata
    pub update_authority: &'a AccountInfo,
    /// The mint account
    pub mint: &'a AccountInfo,
    /// The mint authority (must sign)
    pub mint_authority: &'a AccountInfo,
    /// Token name
    pub name: &'a str,
    /// Token symbol
    pub symbol: &'a str,
    /// URI to token metadata
    pub uri: &'a str,
}

impl<'a> InitializeTokenMetadata<'a> {
    /// Invoke the InitializeTokenMetadata instruction
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the InitializeTokenMetadata instruction with signers
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let ix_len = 8 // instruction discriminator
                + 4 // name length
                + self.name.len()
                + 4 // symbol length
                + self.symbol.len()
                + 4 // uri length
                + self.uri.len();
        let mut ix_data: Vec<u8> = Vec::with_capacity(ix_len);

        // Set 8-byte discriminator for InitializeTokenMetadata
        let discriminator: [u8; 8] = [210, 225, 30, 162, 88, 184, 77, 141];
        ix_data.extend(discriminator);

        // Set name length and name data bytes
        let name_len = self.name.len() as u32;
        ix_data.extend(&name_len.to_le_bytes());
        ix_data.extend(self.name.as_bytes());

        // Set symbol length and symbol data bytes
        let symbol_len = self.symbol.len() as u32;
        ix_data.extend(&symbol_len.to_le_bytes());
        ix_data.extend(self.symbol.as_bytes());

        // Set uri length and uri data bytes
        let uri_len = self.uri.len() as u32;
        ix_data.extend(&uri_len.to_le_bytes());
        ix_data.extend(self.uri.as_bytes());

        let account_metas: [AccountMeta; 4] = [
            AccountMeta::writable(self.metadata.key()),
            AccountMeta::readonly(self.update_authority.key()),
            AccountMeta::readonly(self.mint.key()),
            AccountMeta::readonly_signer(self.mint_authority.key()),
        ];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &ix_data[..ix_len],
        };

        invoke_signed(
            &instruction,
            &[
                self.metadata,
                self.update_authority,
                self.mint,
                self.mint_authority,
            ],
            signers,
        )
    }
}

/// Wrapper for RemoveKey instruction
pub struct RemoveKey<'a> {
    /// The metadata account to update
    pub metadata: &'a AccountInfo,
    /// The account authorized to update the metadata
    pub update_authority: &'a AccountInfo,
    /// The key to remove from the metadata
    pub key: &'a str,
    /// Whether the operation should be idempotent
    pub idempotent: bool,
}

impl<'a> RemoveKey<'a> {
    /// Invoke the RemoveKey instruction
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the RemoveKey instruction with signers
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Calculate instruction length for RemoveKey
        let ix_len = 8 // instruction discriminator
            + 1 // idempotent flag
            + 4 // key length
            + self.key.len(); // key data

        let mut ix_data: Vec<u8> = Vec::with_capacity(ix_len);

        // Set 8-byte discriminator for RemoveKey
        // Based on spl_token_metadata_interface:remove_key_ix hash
        let discriminator: [u8; 8] = [234, 18, 32, 56, 89, 141, 37, 181];
        ix_data.extend(discriminator);

        // Set idempotent flag
        ix_data.push(self.idempotent as u8);

        // Set serialized key data
        let key_len = self.key.len() as u32;
        ix_data.extend(&key_len.to_le_bytes());
        ix_data.extend(self.key.as_bytes());

        // Create account metas
        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.metadata.key()),
            AccountMeta::readonly_signer(self.update_authority.key()),
        ];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &ix_data,
        };

        invoke_signed(
            &instruction,
            &[self.metadata, self.update_authority],
            signers,
        )
    }
}

/// Wrapper for UpdateField instruction
pub struct UpdateField<'a> {
    /// The metadata account to update
    pub metadata: &'a AccountInfo,
    /// The authority that can sign to update the metadata
    pub update_authority: &'a AccountInfo,
    /// Field to update in the metadata
    pub field: Field<'a>,
    /// Value to write for the field
    pub value: &'a str,
}

impl UpdateField<'_> {
    /// Invoke the UpdateField instruction
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the UpdateField instruction with signers
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Instruction data layout (if Field type is Key):
        // -  [0..8] [u8]: instruction discriminator
        // -  [8..9] u8: field enum type
        // -  [9..13] u32: key length (x1)
        // -  [13..13+x1] [u8]: key string
        // -  [13+x1..17+x1] u32: value length (x2)
        // -  [17+x1..17+x1+x2] [u8]: value string
        // Instruction data layout (if Field type is not Key):
        // -  [0..8] [u8]: instruction discriminator
        // -  [8..9] u8: field enum type
        // -  [9..13] u32: value length (x1)
        // -  [13..13+x1] [u8]: value string

        let ix_len = 8 // instruction discriminator
            + 1 // field type
            + if let Field::Key(key) = self.field {
                4 + key.len()
            } else {
                0
            }
            + 4 // value length
            + self.value.len();

        let mut ix_data: Vec<u8> = Vec::with_capacity(ix_len);

        // Set 8-byte discriminator for UpdateField
        let discriminator: [u8; 8] = [221, 233, 49, 45, 181, 202, 220, 200];
        ix_data.extend(&discriminator);
        ix_data.push(self.field.to_u8());

        // Set serialized key data in buffer if Field is Key type
        if let Field::Key(key) = self.field {
            let key_len = key.len() as u32;
            ix_data.extend(key_len.to_le_bytes());
            ix_data.extend(key.as_bytes());
        }

        // Set serialized value data in buffer
        let value_len = self.value.len() as u32;
        ix_data.extend(value_len.to_le_bytes());
        ix_data.extend(self.value.as_bytes());

        let account_metas: [AccountMeta; 2] = [
            AccountMeta::writable(self.metadata.key()),
            AccountMeta::readonly_signer(self.update_authority.key()),
        ];

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &ix_data,
        };

        invoke_signed(
            &instruction,
            &[self.metadata, self.update_authority],
            signers,
        )
    }
}

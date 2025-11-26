//! Token extension wrappers

use pinocchio::account_info::AccountInfo;
use pinocchio::cpi::invoke_signed;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::ProgramResult;

/// Wrapper for the TransferChecked instruction that supports passing remaining accounts.
pub struct TransferCheckedWithHook<'a> {
    /// The mint whose tokens are being transferred.
    pub mint: &'a AccountInfo,
    /// The source token account.
    pub from: &'a AccountInfo,
    /// The destination token account.
    pub to: &'a AccountInfo,
    /// Authority allowed to transfer tokens.
    pub authority: &'a AccountInfo,
    /// Amount of tokens to transfer (raw units).
    pub amount: u64,
    /// Mint decimals needed for checked transfer.
    pub decimals: u8,
    pub transfer_hook_program: &'a AccountInfo,
}

impl<'a> TransferCheckedWithHook<'a> {
    /// Invoke the TransferChecked instruction.
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Invoke the TransferChecked instruction with signer seeds.
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // account metadata
        let account_metas: [AccountMeta; 5] = [
            AccountMeta::writable(self.from.key()),
            AccountMeta::readonly(self.mint.key()),
            AccountMeta::writable(self.to.key()),
            AccountMeta::readonly_signer(self.authority.key()),
            AccountMeta::readonly(self.transfer_hook_program.key()),
        ];

        // Instruction data layout:
        // -  [0]: instruction discriminator (1 byte, u8)
        // -  [1..9]: amount (8 bytes, u64)
        // -  [9]: decimals (1 byte, u8)
        let mut instruction_data = [0u8; 10];

        // Set discriminator at offset [0]
        instruction_data[0] = 12;
        // Set amount at offset [1..9]
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());
        // Set decimals at offset [9]
        instruction_data[9] = self.decimals;

        let instruction = Instruction {
            program_id: &pinocchio_token_2022::ID,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(
            &instruction,
            &[
                self.from,
                self.mint,
                self.to,
                self.authority,
                self.transfer_hook_program,
            ],
            signers,
        )
    }
}

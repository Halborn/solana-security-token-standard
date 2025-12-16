use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

use crate::state::{AccountDeserialize, AccountSerialize};

pub trait ProgramAccount: AccountDeserialize + AccountSerialize {
    /// Calculate and return space for Account initialization
    fn space(&self) -> u64;

    /// Cpi call to create new Program Account
    fn init<'a>(
        &self,
        payer: &AccountInfo,
        account_info: &AccountInfo,
        seeds: &[Seed<'a>],
    ) -> ProgramResult {
        let lamports = Rent::get()?.minimum_balance(self.space() as usize);
        let signer = [Signer::from(seeds)];

        CreateAccount {
            from: payer,
            to: account_info,
            lamports,
            space: self.space(),
            owner: &crate::ID,
        }
        .invoke_signed(&signer)?;

        Ok(())
    }

    /// Close Program Account
    fn close(account: &AccountInfo, destination_account: &AccountInfo) -> ProgramResult {
        {
            let account_lamports = account.try_borrow_mut_lamports()?;
            let mut destination_lamports = destination_account.try_borrow_mut_lamports()?;
            // Transfer all lamports to destination account
            *destination_lamports = destination_lamports
                .checked_add(*account_lamports)
                .ok_or(ProgramError::ArithmeticOverflow)?;

            let mut data = account.try_borrow_mut_data()?;
            data[0] = 0xff;
        }

        account.resize(1)?;
        account.close()
    }

    /// Write serialized bytes to account data. Uses [AccountSerialize::to_bytes]
    fn write_data(&self, to_account: &AccountInfo) -> ProgramResult {
        let mut data = to_account.try_borrow_mut_data()?;
        let account_bytes = self.to_bytes();
        data[..account_bytes.len()].copy_from_slice(&account_bytes);

        Ok(())
    }
}

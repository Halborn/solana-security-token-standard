use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{CreateAccount, Transfer};

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

    /// Resize account data and adjust lamports for rent-exemption
    fn resize_account_and_rent(
        account: &AccountInfo,
        new_size: usize,
        payer: &AccountInfo,
    ) -> ProgramResult {
        if new_size == account.data_len() {
            return Ok(());
        }

        let account_current_lamports = account.lamports();
        let rent = Rent::get()?;
        let account_new_lamports = rent.minimum_balance(new_size);

        // Adjust lamports for rent-exemption
        match account_new_lamports.cmp(&account_current_lamports) {
            core::cmp::Ordering::Greater => {
                // Payer transfers more lamports for rent exemption
                let lamports_diff = account_new_lamports.saturating_sub(account_current_lamports);
                Transfer {
                    from: payer,
                    to: account,
                    lamports: lamports_diff,
                }
                .invoke()?;
            }
            core::cmp::Ordering::Less => {
                // Payer gets excess lamports
                let lamports_diff = account_current_lamports.saturating_sub(account_new_lamports);
                // Lamports can be reduced directly for Program Account
                *account.try_borrow_mut_lamports()? -= lamports_diff;
                *payer.try_borrow_mut_lamports()? += lamports_diff;
            }
            core::cmp::Ordering::Equal => {
                // No lamport transfer needed
            }
        }

        account.resize(new_size)?;

        Ok(())
    }
}

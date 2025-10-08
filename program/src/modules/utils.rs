use crate::error::SecurityTokenError;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

/// Validates that the required accounts for verification are correctly passed between
/// the verification programs and the Security Token instruction.
///
/// Specifically, it ensures that all accounts that require verification appear at the beginning
/// of the account list passed to the verification program, in the **same order** as expected
/// by the Security Token instruction.
///
/// Any additional accounts passed to the verification program are allowed, as long as they
/// come **after** the accounts to be verified.
///
/// Returns `Ok(())` if validation succeeds; otherwise, returns an appropriate error.
pub fn validate_account_verification(
    verification_program_accounts: &[Vec<Pubkey>],
    instruction_accounts: &[Pubkey],
) -> Result<(), ProgramError> {
    for verification_program in verification_program_accounts {
        if verification_program.is_empty()
            || !verification_program.starts_with(instruction_accounts)
        {
            return Err(SecurityTokenError::AccountIntersectionMismatch.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Helper to create Pubkeys for testing
    fn pubkey(byte: u8) -> Pubkey {
        [byte; 32]
    }

    // Helper to create Vec<Pubkey> from bytes
    fn accounts(bytes: &[u8]) -> Vec<Pubkey> {
        bytes.iter().map(|&b| pubkey(b)).collect()
    }

    #[rstest]
    // Test: VALID - no account to verify
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2])],
        accounts(&[]),
        true,
        "no account to verify"
    )]
    // Test: VALID - no programs to verify against
    #[case(
        vec![],
        accounts(&[1, 2, 3]),
        true,
        "no verification programs to verify against"
    )]
    // Test: VALID - single verified account
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2])],
        accounts(&[1]),
        true,
        "acc1 verified by all programs"
    )]
    // Test: VALID - multiple verified accounts
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2])],
        accounts(&[1, 2]),
        true,
        "acc1,2 verified by all programs"
    )]
    // Test: VALID - multiple verified accounts with extra accounts for verification programs
    #[case(
        vec![accounts(&[1, 2, 3, 4]), accounts(&[1, 2, 5])],
        accounts(&[1, 2]),
        true,
        "acc1,2 verified by all programs"
    )]
    // Test: INVALID - acc 2 is not included in all verification programs
    #[case(
        vec![accounts(&[1, 2]), accounts(&[1])],
        accounts(&[1, 2]),
        false,
        "acc2 is not verified by the second program"
    )]
    // Test: INVALID - order is important, acc2 appears after acc1 in the second program
    #[case(
        vec![accounts(&[1, 2]), accounts(&[2, 1])],
        accounts(&[1, 2]),
        false,
        "acc2 appears after acc1 in the second verification program"
    )]
    // Test: INVALID - additional account in the first verification program
    #[case(
        vec![accounts(&[3, 1, 2]), accounts(&[1, 2])],
        accounts(&[1, 2]),
        false,
        "not verified by the first program due to additional account at the start"
    )]

    fn test_cross_set_verification_cases(
        #[case] verification_programs: Vec<Vec<Pubkey>>,
        #[case] security_token_accounts: Vec<Pubkey>,
        #[case] expected_valid: bool,
        #[case] description: &str,
    ) {
        let result =
            validate_account_verification(&verification_programs, &security_token_accounts);
        assert_eq!(result.is_ok(), expected_valid, "{}", description);
    }

    #[test]
    fn test_empty_verification_programs() {
        // No verification programs - should pass
        let verification_programs = vec![];
        let security_token = accounts(&[1, 2]);

        let result = validate_account_verification(&verification_programs, &security_token);
        assert!(
            result.is_ok(),
            "Should be valid when no verification programs"
        );
    }
}

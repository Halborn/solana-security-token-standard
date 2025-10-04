use crate::error::SecurityTokenError;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use std::collections::HashSet;

/// Validates cross-set verification between verification programs and security token instruction.
/// Returns `Ok(())` when validation passes.
pub fn validate_cross_set_verification(
    verification_program_accounts: &[Vec<Pubkey>],
    security_token_accounts: &[Pubkey],
) -> Result<(), ProgramError> {
    if verification_program_accounts.is_empty() {
        return Ok(()); // No verification programs - pass
    }

    let mut verification_sets = verification_program_accounts.iter();
    let first_set = verification_sets
        .next()
        .expect("verification_program_accounts is not empty");

    let mut intersection: HashSet<Pubkey> = first_set.iter().copied().collect();
    let mut union_accounts: HashSet<Pubkey> = intersection.clone();

    for accounts in verification_sets {
        let current_set: HashSet<Pubkey> = accounts.iter().copied().collect();
        union_accounts.extend(&current_set);
        intersection.retain(|account| current_set.contains(account));
    }

    let mut encountered_non_verified_tail = false;
    let mut saw_verified_account = false;
    for st_account in security_token_accounts {
        if intersection.contains(st_account) {
            if encountered_non_verified_tail {
                return Err(SecurityTokenError::AccountIntersectionMismatch.into());
            }
            saw_verified_account = true;
        } else if union_accounts.contains(st_account) {
            return Err(SecurityTokenError::AccountIntersectionMismatch.into());
        } else {
            encountered_non_verified_tail = true;
        }
    }

    if !saw_verified_account {
        return Err(SecurityTokenError::AccountIntersectionMismatch.into());
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
    // Test: INVALID - acc4 non-verified account between verified accounts breaks order
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2])], 
        accounts(&[1, 4, 2]), 
        false,
    "acc4 breaks order - non-verified accounts must come after verified accounts"
    )]
    // Test: VALID - verified accounts first, then non-verified accounts
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2])], 
        accounts(&[1, 2, 4]), 
        true,
    "acc1,2 verified by all programs, acc4 as non-verified account at end"
    )]
    // Test: VALID - single verified account
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2])], 
        accounts(&[1]), 
        true,
        "acc1 verified by all programs"
    )]
    // Test: INVALID - acc1 not in second program
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[2])], 
        accounts(&[1, 2, 4]), 
        false,
        "acc1 not available in second program"
    )]
    // Test: VALID - only intersection accounts used
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[2])], 
        accounts(&[2]), 
        true,
        "acc2 verified by all programs"
    )]
    // Test: INVALID - no intersection and no verified accounts used
    #[case(
        vec![accounts(&[1, 2]), accounts(&[3, 4])], 
        accounts(&[5, 6]), 
        false,
    "no accounts verified by all programs"
    )]
    // Test: INVALID - trying to use acc1 when it's not in all programs
    #[case(
        vec![accounts(&[1, 2]), accounts(&[3, 4])], 
        accounts(&[1, 5]), 
        false,
        "acc1 not in intersection but used in ST instruction"
    )]
    // Test: VALID - all three programs verify acc1,2
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2, 5]), accounts(&[1, 2, 6])], 
        accounts(&[1, 2]), 
        true,
        "acc1 and acc2 verified by all three programs"
    )]
    // Test: VALID - intersection accounts first, non-verified accounts after
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2, 5]), accounts(&[1, 2, 6])], 
        accounts(&[1, 2, 7, 8, 9]), 
        true,
    "acc1,2 verified by all programs, acc7,8,9 as non-verified accounts at end"
    )]
    // Test: INVALID - verified account after system account breaks order
    #[case(
        vec![accounts(&[1, 2, 3]), accounts(&[1, 2, 5]), accounts(&[1, 2, 6])], 
        accounts(&[1, 7, 2, 8]), 
        false,
        "acc2 appears after account acc7 - violates order requirement"
    )]
    // Test: INVALID - accounts not presented in any verification program
    #[case(
        vec![accounts(&[7, 8]), accounts(&[7, 8]), accounts(&[7,8])], 
        accounts(&[1, 2]), 
        false,
        "no accounts verified by all programs"
    )]

    fn test_cross_set_verification_cases(
        #[case] verification_programs: Vec<Vec<Pubkey>>,
        #[case] security_token_accounts: Vec<Pubkey>,
        #[case] expected_valid: bool,
        #[case] description: &str,
    ) {
        let result =
            validate_cross_set_verification(&verification_programs, &security_token_accounts);
        assert_eq!(result.is_ok(), expected_valid, "{}", description);
    }

    #[test]
    fn test_empty_verification_programs() {
        // No verification programs - should pass
        let verification_programs = vec![];
        let security_token = accounts(&[1, 2]);

        let result = validate_cross_set_verification(&verification_programs, &security_token);
        assert!(
            result.is_ok(),
            "Should be valid when no verification programs"
        );
    }
}

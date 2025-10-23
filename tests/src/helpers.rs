use security_token_client::errors::SecurityTokenProgramError;
use solana_program_test::BanksClientError;
use solana_sdk::{instruction::InstructionError, transaction::TransactionError};

/// Helper function to assert that a transaction failed with a specific SecurityTokenError
pub fn assert_security_token_error(
    result: Result<(), BanksClientError>,
    expected_error: SecurityTokenProgramError,
) {
    match result {
        Err(e) => match e {
            BanksClientError::TransactionError(transaction_error) => match transaction_error {
                TransactionError::InstructionError(_, instruction_error) => match instruction_error
                {
                    InstructionError::Custom(error_code) => {
                        let expected_code = expected_error as u32;
                        assert_eq!(
                            error_code, expected_code,
                            "Expected error code {}, but got error code {}",
                            expected_code, error_code
                        );
                        println!("Test passed: Got expected error code {}", expected_code);
                    }
                    _ => panic!(
                        "Expected custom instruction error, got: {:?}",
                        instruction_error
                    ),
                },
                _ => panic!("Expected instruction error, got: {:?}", transaction_error),
            },
            _ => panic!("Expected transaction error, got: {:?}", e),
        },
        Ok(_) => panic!("Expected transaction to fail, but it succeeded"),
    }
}

pub fn assert_transaction_success(result: Result<(), BanksClientError>) {
    match result {
        Ok(_) => {
            println!("Test passed: Transaction succeeded as expected");
        }
        Err(e) => panic!(
            "Expected transaction to succeed, but it failed with: {:?}",
            e
        ),
    }
}

pub fn assert_transaction_failure(result: Result<(), BanksClientError>) {
    match result {
        Err(_) => {
            println!("Test passed: Transaction failed as expected");
        }
        Ok(_) => panic!("Expected transaction to fail, but it succeeded"),
    }
}

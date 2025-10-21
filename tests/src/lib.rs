//! Security Token Standard Test Suite

#[cfg(test)]
pub mod integration_tests;

#[cfg(test)]
pub mod verify_workflow_test;

#[cfg(test)]
pub mod helpers;

#[cfg(test)]
pub mod operations;

// TODO: To avoid passing default values like token_program, rent_sysvar and etc we must use 
// a builder pattern for instruction construction.

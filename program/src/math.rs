use pinocchio::program_error::ProgramError;

/// Compute 10^n with overflow check.
pub fn pow10_u64(n: u8) -> Result<u64, ProgramError> {
    let mut v: u64 = 1;
    for _ in 0..n {
        v = v.checked_mul(10).ok_or(ProgramError::ArithmeticOverflow)?;
    }
    Ok(v)
}

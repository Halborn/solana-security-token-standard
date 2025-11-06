/// Converts an account's public key to a base58 string slice.
#[macro_export]
macro_rules! acc_info_as_str {
    ($info:expr) => {
        bs58::encode($info.key()).into_string().as_str()
    };
}

/// Converts a public key to a base58 string slice.
#[macro_export]
macro_rules! key_as_str {
    ($key:expr) => {
        bs58::encode($key).into_string().as_str()
    };
}

/// Debug logging macro that only compiles when debug-logs feature is enabled.
/// Usage: debug_log!("message: {}", value);
#[cfg(feature = "debug-logs")]
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        pinocchio_log::log!($($arg)*);
    };
}

/// No-op version when debug-logs feature is disabled.
#[cfg(not(feature = "debug-logs"))]
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {};
}

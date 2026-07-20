# Security Token Client

Rust client for the Solana Security Token Standard (SSTS). This crate exposes
instructions, account types, errors, and program IDs for the SSTS program.

## Installation

```toml
[dependencies]
ssts-org-client = "1.0.0"
```

## Usage

```rust
use security_token_client::{instructions, types};
```

The library crate name is `security_token_client`.

When creating a security-token mint, set
`InitializeMintArgs::ix_permissioned_burn` to `true`. Set it to `false` only for
an intentionally legacy-compatible mint whose holders may burn directly through
Token-2022.

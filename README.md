# Solana Security Token Standard

A comprehensive security token implementation on Solana using Token-2022 extensions, providing KYC/AML compliance, transfer restrictions, and corporate actions support.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Building](#building)
- [Testing](#testing)
- [Deployment](#deployment)
- [Documentation](#documentation)
- [Development](#development)

## Requirements

Before you begin, ensure you have the following installed:

- **Rust** 1.87.0 (pinned via `rust-toolchain.toml`)
  - Install from [https://rustup.rs/](https://rustup.rs/)
  - Required components: `rustfmt`, `clippy`
  - Note: This repository includes a `rust-toolchain.toml` file; when using `rustup`, the correct Rust version (1.87.0) will be selected automatically. Newer Rust versions are not guaranteed to be compatible.
- **Solana CLI** (recommended: v2.2.0)
  - Install (pinned): `sh -c "$(curl -sSfL https://release.anza.xyz/v2.2.0/install)"`
  - Verify: `solana --version`
  - Warning: Newer Solana CLI versions (e.g., 3.x) may not be compatible with the local test harness yet. If you see flaky or failing tests, downgrade to v2.2.0.

- **Node.js** (v18 or later) and **pnpm**
  - Install Node.js from [https://nodejs.org/](https://nodejs.org/)
  - Install pnpm: `npm install -g pnpm`

- **Cargo Tools** (optional but recommended):
  - `cargo-audit` - Security vulnerability scanning
  - `cargo-deny` - Dependency linting
  - `cargo-expand` - Macro expansion for debugging

## Installation

### Quick Setup

Run the automated setup script to install all dependencies and configure your environment:

```bash
./scripts/setup.sh
```

This script will:

- Verify Rust and Solana CLI installations
- Install required Rust components (`rustfmt`, `clippy`)
- Install recommended cargo tools (`cargo-audit`, `cargo-deny`, `cargo-expand`)
- Configure Solana CLI for devnet
- Generate a keypair if one doesn't exist
- Build both the main program and transfer hook

### Manual Setup

If you prefer manual setup:

```bash
# Install Rust components
rustup component add rustfmt clippy

# Install cargo tools (pinned for Rust 1.87 compatibility)
cargo install cargo-audit --version 0.22.1 --locked
cargo install cargo-deny --version 0.18.3 --locked
cargo install cargo-expand --version 1.0.118 --locked

# Configure Solana for devnet
solana config set --url https://api.devnet.solana.com

# Generate keypair (if needed)
solana-keygen new --no-bip39-passphrase

# Install Node.js dependencies
pnpm install

# Build programs
./scripts/build.sh
```

## Building

### Build Programs

Build both the main security token program and the transfer hook:

```bash
./scripts/build.sh
```

This compiles:

- Security Token Program (`program/`)
- Transfer Hook Program (`transfer_hook/`)

For SBF-only builds (skip host build):

```bash
./scripts/build.sh sbf
```

### Build with Clients

Generate IDL and client libraries:

```bash
# Build everything including clients
pnpm build-all

# Or step by step:
pnpm build              # Build programs
pnpm generate-idl       # Generate IDL from program
pnpm generate-clients   # Generate Rust and TypeScript clients
```

### Code Formatting

Format all Rust code in the project:

```bash
./scripts/format.sh
```

## Testing

The project includes comprehensive unit and integration tests.

### Run All Tests

```bash
./scripts/test.sh
```

This will:

1. Clean previous builds
2. Build all workspace components
3. Run program unit tests
4. Run client library tests
5. Build programs for SBF
6. Run integration tests
7. Run BPF program tests

### Run Specific Tests

**Unit Tests (Program):**

```bash
cargo test --manifest-path program/Cargo.toml
```

**Client Tests:**

```bash
cargo test --manifest-path clients/rust/Cargo.toml
```

**Integration Tests:**

```bash
# Build programs first
./scripts/build.sh sbf

# Run integration tests
SBF_OUT_DIR=$(pwd)/target/deploy cargo test --manifest-path tests/Cargo.toml
```

**Quick Test (via npm):**

```bash
pnpm test
```

**Run with Code Quality Checks:**

The test script automatically runs additional quality checks:

- Code formatting (`cargo fmt --check`)
- Linting (`cargo clippy`)
- Security audit (`cargo deny check advisories -c deny.toml` - if installed)

These checks run automatically and don't require any parameters.

For license compliance checks, run `cargo deny check` manually (if installed).

## Deployment

### Prerequisites

Ensure you have SOL in your wallet for deployment fees:

```bash
# Check your balance
solana balance

# Request airdrop on devnet (2 SOL)
solana airdrop 2
```

**Note:** If the airdrop fails (common on devnet due to rate limits), use the [Solana Faucet](https://faucet.solana.com/) to request devnet SOL manually.

**Environment variables (deployment):**

- `DEPLOYER_KEYPAIR` — fee-payer keypair (defaults to `SOLANA_KEYPAIR` or `~/.config/solana/id.json`)
- `SOLANA_KEYPAIR` — legacy override for deployer keypair
- `SBF_OUT_DIR` / `BPF_OUT_DIR` — directory containing `.so` and program keypairs (default `target/deploy`)
- `PROGRAM_KEYPAIR_PATH` — override main program keypair path
- `TRANSFER_HOOK_KEYPAIR_PATH` — override transfer hook keypair path
- `PROGRAM_PATH` — override main program `.so` path
- `TRANSFER_HOOK_PROGRAM_PATH` — override transfer hook `.so` path

### Deploy Programs

By default, programs deploy to **devnet**. To deploy to a different cluster (testnet or mainnet), pass the cluster name as an argument.

### Vanity Program IDs (Required for custom IDs)

If you plan to deploy with **custom program IDs** (vanity or not), you must set those IDs in code **before** building and deploying. The program IDs are baked into:

- `program/src/lib.rs` (`declare_id!` for the main program)
- `transfer_hook/src/lib.rs`:
  - `declare_id!` for the transfer hook program ID
  - `SECURITY_TOKEN_PROGRAM_ID` (must match the main program ID)
- `program/src/constants.rs` (`TRANSFER_HOOK_PROGRAM_ID`)
- `idl/security_token_program.json` (program address)

After updating the IDs in code, regenerate IDL + clients:

```bash
pnpm generate-idl
pnpm generate-clients
```

**Generate vanity keypairs:**

```bash
# Example: find a keypair starting with "SSTS"
solana-keygen grind --starts-with SSTS:1 --ignore-case
```

**Move them into place (recommended):**

```bash
# Main program keypair
mkdir -p target/deploy
mv <GENERATED_KEYPAIR.json> target/deploy/security_token_program-keypair.json

# Transfer hook keypair
mkdir -p target/deploy
mv <GENERATED_KEYPAIR.json> target/deploy/security_token_transfer_hook-keypair.json
```

**Alternative:** keep them elsewhere and point the deploy scripts at them:

```bash
PROGRAM_KEYPAIR_PATH=/path/to/security_token_program-keypair.json \
TRANSFER_HOOK_KEYPAIR_PATH=/path/to/security_token_transfer_hook-keypair.json \
pnpm run deploy:all
```

**Deploy both programs (recommended):**

```bash
# Devnet (default)
pnpm deploy:all

# Other clusters
pnpm deploy:all -- testnet
pnpm deploy:all -- mainnet
```

**Deploy individual programs:**

```bash
# Main program only
./scripts/deploy.sh [devnet|testnet|mainnet]

# Transfer hook only
./scripts/deploy-transfer-hook.sh [devnet|testnet|mainnet]
```

### Post-Deployment

After deployment, the program IDs are saved to:

- `program_id.txt` - Main security token program ID
- `transfer_hook_program_id.txt` - Transfer hook program ID

Verify deployment:

```bash
solana program show <PROGRAM_ID>
```

## Documentation

- **[Program Instructions](./docs/program-instructions.md)** - Complete instruction reference, account structures, and authorization model
- **[IDL](./idl/security_token_program.json)** - Codama IDL for client generation
- **[Security Policy](./SECURITY.md)** - Disclosure process and security reporting expectations

## Development

### Available Scripts

| Script                              | Description               |
| ----------------------------------- | ------------------------- |
| `./scripts/setup.sh`                | Initial environment setup |
| `./scripts/build.sh`                | Build programs            |
| `./scripts/test.sh`                 | Run all tests             |
| `./scripts/format.sh`               | Format code               |
| `./scripts/deploy.sh`               | Deploy main program       |
| `./scripts/deploy-transfer-hook.sh` | Deploy transfer hook      |

### NPM Scripts

```bash
pnpm build              # Build programs
pnpm build-all          # Build + generate IDL + generate clients
pnpm test               # Run tests
pnpm generate-idl       # Generate IDL from program
pnpm generate-clients   # Generate client libraries
pnpm deploy:all         # Deploy both programs
pnpm deploy:program     # Deploy main program
pnpm deploy:transfer-hook # Deploy transfer hook
```

### Project Structure

```
├── program/              # Main security token program
├── transfer_hook/        # Transfer hook program
├── clients/
│   ├── rust/            # Rust client library
│   └── typescript/      # TypeScript client library
├── tests/               # Integration tests
├── scripts/             # Build and deployment scripts
├── idl/                 # Generated IDL
└── docs/                # Documentation
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `./scripts/test.sh`
5. Format code: `./scripts/format.sh`
6. Submit a pull request

## License

- [Apache-2.0](LICENSE.md)
- [Third Party Notices](THIRD_PARTY_NOTICES.md)

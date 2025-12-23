# Solana Security Token

## Instructions and Accounts

Check [documentation](./docs/program-instructions.md) for available security-token-program instructions.

## IDL

The security-token-program has the following [Codama IDL](./idl/security_token_program.json).

## Development

Here are useful commands for local development:

```sh
# Regenerate IDL
$ pnpm generate-idl

# Regenerate clients
$ pnpm generate-clients
```

### Run tests

In a project root:

```
cargo-build-sbf && SBF_OUT_DIR=$(pwd)/target/deploy cargo test
```

OR 

```
pnpm test
```

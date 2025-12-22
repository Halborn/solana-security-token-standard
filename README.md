# Solana Security Token Standard

## IDL

The security-token-program has the following [Codama IDL](./idl/security_token_program.json). 

### Generate IDL

```
pnpm generate-idl
```

### Generate clients

```
pnpm generate-clients
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

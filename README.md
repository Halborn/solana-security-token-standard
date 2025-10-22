# Solana Security Token Standard

The README is pending

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

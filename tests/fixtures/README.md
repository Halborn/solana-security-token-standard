# Token-2022 v11 test fixture

`spl_token_2022_v11.so` is the official `spl_token_2022.so` release artifact
from [`solana-program/token-2022` tag `program@v11.0.0`](https://github.com/solana-program/token-2022/releases/tag/program%40v11.0.0),
commit `9bc0275`. It is loaded at the canonical Token-2022 program ID:

```text
TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
```

SHA-256:

```text
9bbf90b30e06778ca0feca100b29f0eeb9be576ae024f6323cc207308f51a5d1
```

Reproduce the downloaded fixture:

```bash
curl --fail --location \
  'https://github.com/solana-program/token-2022/releases/download/program%40v11.0.0/spl_token_2022.so' \
  --output tests/fixtures/spl_token_2022_v11.so
(cd tests/fixtures && sha256sum --check spl_token_2022_v11.sha256)
```

Alternatively, check out the tag and follow its `make build-sbf-program`
procedure; copy the resulting Token-2022 SBF artifact to this path and verify
the program ID before use. The upstream source and binary are distributed
under the Apache License 2.0; copyright remains with the upstream contributors.

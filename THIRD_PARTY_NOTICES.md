# Third Party Notices

This project depends on third-party open source software. This file provides a
lightweight notice and a summary of commonly encountered licenses in the
dependency tree. It is not exhaustive.

Summary of license families present in the dependency graph:

- Apache-2.0
- MIT
- BSD-2-Clause
- BSD-3-Clause
- ISC
- 0BSD
- CC0-1.0
- Unicode-3.0
- MPL-2.0 (weak copyleft)
- CDLA-Permissive-2.0 (data license)

Notable data license:

- webpki-root-certs, webpki-roots: CDLA-Permissive-2.0 (root certificate data)

Distributed test fixture:

- `tests/fixtures/spl_token_2022_v11.so`: Token-2022 `program@v11.0.0`,
  copyright the `solana-program/token-2022` contributors, Apache-2.0. Source,
  provenance, reproduction steps, and checksum are documented in
  `tests/fixtures/README.md`.

Copyleft note:

- Some transitive dependencies are MPL-2.0. MPL is file-level copyleft; only
  modified MPL-licensed files must remain under MPL when distributed. This
  project does not modify those upstream files.

To generate a full license list for this repository:

```
cargo deny list -c deny.toml
cargo deny list -c deny.toml --format tsv --layout crate
```

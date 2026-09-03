# Changelog

## Unreleased

### Added

- Added optional Token-2022 Permissioned Burn initialization through the trailing
  `ix_permissioned_burn` field. Protected mints use the program-owned permanent
  delegate as the permissioned authority, closing direct holder `Burn` and
  `BurnChecked` bypasses while preserving verified SSTS burn, split, and convert
  flows.

### Compatibility

- Legacy `InitializeMint` payloads decode the missing field as `false`. Existing
  mints without Permissioned Burn, or with its authority cleared, remain
  unprotected from direct holder burns and require migration to a new protected
  mint if that guarantee is needed.

## 0.3.0 - 2026-05-21

### Added

- Added optional `DefaultAccountState` Token-2022 extension support at mint initialization (`ix_default_account_state: Option<u8>` in `InitializeMintArgs`). Accepted values: `1` (Initialized) or `2` (Frozen).
- Added `UpdateDefaultAccountState` instruction (discriminator `24`) to change the default state for newly created token accounts. Uses the `VerificationProgramsOrMintAuthority` authorization profile and signs the Token-2022 CPI with the program-owned `FreezeAuthority` PDA.

## 0.2.0 - 2026-05-08

### Breaking Changes

- Action receipt PDAs for Split and Convert now include the source token account in their seeds: `["receipt", mint, token_account, action_id]`.
- `CloseActionReceiptArgs` now requires `token_account` so the program can derive and validate the updated action receipt PDA.

### Added

- Added multi-holder Split and Convert coverage so one Rate account and `action_id` can be reused across separate holders.
- Added the `examples/split-guard` verification program, which can halt transfers during Split operations and resume them afterward.
- Added end-to-end Split Guard coverage for the introspection verification flow.

### Changed

- Updated the Rust client, TypeScript client, IDL, and program docs for the action receipt PDA seed change.
- Updated the lockfile to use `rand` `0.8.6`.

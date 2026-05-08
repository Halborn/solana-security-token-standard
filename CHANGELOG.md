# Changelog

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

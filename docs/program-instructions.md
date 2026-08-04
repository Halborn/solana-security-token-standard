# Security Token Program Documentation


## Table of Contents

- [Authorization](#authorization)
    - [Authorization Types](#authorization-types)
        - [Permissionless](#permissionless)
        - [Initial Mint Authority OR Verification Programs](#initial-mint-authority-or-verification-programs)
        - [Verification Programs Only](#verification-programs-only)
    - [Verification Modes](#verification-modes)
        - [Introspection Mode (`cpi_mode = false`)](#introspection-mode-cpi_mode--false)
        - [CPI Mode (`cpi_mode = true`)](#cpi-mode-cpi_mode--true)
    - [Verification Overhead Accounts](#verification-overhead-accounts)
        - [Verification Programs](#verification-programs)
        - [Initial Mint Authority](#initial-mint-authority)
- [Program Accounts](#program-accounts)
    - [MintAuthority](#mintauthority)
    - [VerificationConfig](#verificationconfig)
    - [Rate](#rate)
    - [Receipt](#receipt)
    - [Proof](#proof)
- [Virtual PDAs](#virtual-pdas)
    - [DistributionEscrowAuthority](#distributionescrowauthority)
    - [PermanentDelegateAuthority](#permanentdelegateauthority)
    - [PauseAuthority](#pauseauthority)
    - [FreezeAuthority](#freezeauthority)
    - [TransferHookAuthority](#transferhookauthority)
- [Serialization Conventions](#serialization-conventions)
- [Errors](#errors)
- [Instructions](#instructions)
    - [InitializeMint](#initializemint)
    - [UpdateMetadata](#updatemetadata)
    - [InitializeVerificationConfig](#initializeverificationconfig)
    - [UpdateVerificationConfig](#updateverificationconfig)
    - [TrimVerificationConfig](#trimverificationconfig)
    - [Verify](#verify)
    - [Mint](#mint)
    - [Burn](#burn)
    - [Pause](#pause)
    - [Resume](#resume)
    - [Freeze](#freeze)
    - [Thaw](#thaw)
    - [Transfer](#transfer)
    - [CreateRateAccount](#createrateaccount)
    - [UpdateRateAccount](#updaterateaccount)
    - [CloseRateAccount](#closerateaccount)
    - [Split](#split)
    - [Convert](#convert)
    - [CreateProofAccount](#createproofaccount)
    - [UpdateProofAccount](#updateproofaccount)
    - [CreateDistributionEscrow](#createdistributionescrow)
    - [ClaimDistribution](#claimdistribution)
    - [CloseActionReceiptAccount](#closeactionreceiptaccount)
    - [CloseClaimReceiptAccount](#closeclaimreceiptaccount)
    - [UpdateDefaultAccountState](#updatedefaultaccountstate)
- [Verification Program Interface](#verification-program-interface)


## Authorization

The Security Token Program uses different authorization strategies depending on the instruction type. Each instruction falls into one of three authorization profiles:


### Authorization Types

#### Permissionless

Instructions that require no special authorization.

**Applicable instructions:** `InitializeMint`, `Verify`

#### Initial Mint Authority OR Verification Programs

Instructions that can be authorized by **either**:

- **Verification Programs** - External programs configured in `VerificationConfig` that validate the operation
- **OR Mint Creator Signature** - The original creator who initialized the mint, verified through `MintAuthority` account

This dual authorization model allows flexibility: use verification programs for complex compliance workflows, or fall back to direct creator control when no verification is configured. It applies to mint configuration-related instructions.

**Applicable instructions:** `UpdateMetadata`, `InitializeVerificationConfig`, `UpdateVerificationConfig`, `TrimVerificationConfig`, `CreateRateAccount`, `UpdateRateAccount`, `CloseRateAccount`, `CreateDistributionEscrow`, `CloseActionReceiptAccount`, `CloseClaimReceiptAccount`, `UpdateDefaultAccountState`

#### Verification Programs Only

Instructions that **must** be authorized through configured verification programs. These are typically token operations that require compliance checks (KYC/AML, transfer restrictions, etc.).

**Applicable instructions:** `Mint`, `Burn`, `Pause`, `Resume`, `Freeze`, `Thaw`, `Transfer`, `Split`, `Convert`, `CreateProofAccount`, `UpdateProofAccount`, `ClaimDistribution`


### Verification Modes

When using verification programs, the Security Token Program supports two verification modes. The required verification flow is configured via the `cpi_mode` option in the corresponding verification config.

#### Introspection Mode (`cpi_mode = false`)

In introspection mode, the Security Token Program examines the Instructions Sysvar to verify that all required verification programs were called **before** the current instruction within the same transaction. In order to pass authorization via verification programs in introspection mode, the following conditions must be satisfied:

- A corresponding instruction verification config exists with `cpi_mode` disabled and is passed to the Security Token Program.
- Verification programs must form a contiguous block immediately before the Security Token instruction, in config order, and complete successfully.
- Each verification program call must include the same instruction data and target instruction discriminator prefix.
- Each verification program call must include exactly its canonical operation accounts followed by its own configured extras.

#### CPI Mode (`cpi_mode = true`)

In CPI mode, the Security Token Program directly invokes (via CPI) each configured verification program during instruction processing. In order to pass authorization via verification programs in CPI mode, the following conditions must be satisfied:

- A corresponding instruction verification config exists with `cpi_mode` enabled and is passed to the Security Token Program.
- Ordered `[program, own extras...]` routing groups must be appended after the fixed Security Token instruction accounts.
- Each verification program receives the same instruction data, canonical operation accounts, and only its own configured extras.

**Important:** Transfer uses the canonical order `[source, mint, destination, authority]` in both Core and Hook paths. Transfer Hook CPI privileges remain limited to those granted by Token-2022.


### Verification Overhead Accounts

Instructions that require authorization should include a **verification overhead** - 3 accounts at the beginning of the accounts list that handle the authorization logic. The exact accounts depend on the authorization type.

#### Verification Programs

For instructions that support authorization via verification programs:

| #   | Account             | Signer | Writable | Description                                                                   |
| --- | ------------------- | ------ | -------- | ----------------------------------------------------------------------------- |
| 0   | mint                |        |          | The mint account being operated on                                            |
| 1   | verification_config |        |          | [VerificationConfig](#verificationconfig) PDA for this instruction type       |
| 2   | instructions_sysvar |        |          | Instructions Sysvar (introspection mode) or program_id placeholder (CPI mode) |

#### Initial Mint Authority

For instructions that support authorization via initial mint creator signature:

| #   | Account        | Signer | Writable | Description                        |
| --- | -------------- | ------ | -------- | ---------------------------------- |
| 0   | mint           |        |          | The mint account being operated on |
| 1   | mint_authority |        |          | [MintAuthority](#mintauthority) PDA |
| 2   | creator        | ✓      |          | Creator signer                     |

After the overhead come the **instruction-specific accounts** (core accounts).


## Program Accounts

All program-owned accounts use a discriminator byte as the first byte of serialized data:

| Account Type       | Discriminator |
| ------------------ | ------------- |
| MintAuthority      | `0`           |
| VerificationConfig | `1`           |
| Rate               | `2`           |
| Receipt            | `3`           |
| Proof              | `4`           |


### MintAuthority

Stores the original mint creator information used for authorization fallback when verification programs are not configured.

**Structure:**

| Field         | Type   | Size | Description                                    |
| ------------- | ------ | ---- | ---------------------------------------------- |
| discriminator | u8     | 1    | Account discriminator (`0`)                    |
| mint          | Pubkey | 32   | SPL mint address this configuration belongs to |
| mint_creator  | Pubkey | 32   | Original creator address                       |
| bump          | u8     | 1    | PDA bump seed                                  |

**Total size:** 66 bytes

**PDA Derivation:**

```
seeds = ["mint.authority", mint_address, creator_address]
program_id = Security Token Program
```


### VerificationConfig

Stores verification program configuration for a specific instruction type on a specific mint.

**Structure:**

| Field                     | Type          | Size       | Description                                                            |
| ------------------------- | ------------- | ---------- | ---------------------------------------------------------------------- |
| discriminator             | u8            | 1          | Account discriminator (`1`)                                            |
| instruction_discriminator | u8            | 1          | Instruction type this config applies to                                |
| cpi_mode                  | bool          | 1          | `true` for CPI mode, `false` for introspection mode                    |
| bump                      | u8            | 1          | PDA bump seed                                                          |
| programs                  | Vec\<VerificationProgramConfig\> | variable | Ordered program IDs and private extra-account declarations |

**Minimum size:** 8 bytes (empty program list)

`VerificationProgramConfig` contains `program_id: Pubkey` and `extra_accounts: Vec<VerificationAccountMeta>`. Each 35-byte meta contains a discriminator, 32-byte address configuration, signer flag, and writable flag. This nested ABI is breaking; old flat configs must be recreated.

**PDA Derivation:**

```
seeds = ["verification_config", mint_address, instruction_discriminator]
program_id = Security Token Program
```

### Rate

Stores conversion/split rate configuration for corporate actions.

**Structure:**

| Field         | Type | Size | Description                              |
| ------------- | ---- | ---- | ---------------------------------------- |
| discriminator | u8   | 1    | Account discriminator (`2`)              |
| rounding      | u8   | 1    | Rounding direction: `0` = Up, `1` = Down |
| numerator     | u8   | 1    | Rate numerator                           |
| denominator   | u8   | 1    | Rate denominator                         |
| bump          | u8   | 1    | PDA bump seed                            |

**Total size:** 5 bytes

**PDA Derivation:**

```
seeds = ["rate", action_id (8 bytes LE), mint_from_address, mint_to_address]
program_id = Security Token Program
```


### Receipt

Records that a holder has participated in a corporate action (split/convert) or claimed a distribution. Prevents duplicate participation. Receipt has minimal structure (only discriminator) because all relevant information is encoded in the PDA seeds.

**Structure:**

| Field         | Type | Size | Description                 |
| ------------- | ---- | ---- | --------------------------- |
| discriminator | u8   | 1    | Account discriminator (`3`) |

**Total size:** 1 byte

**PDA Derivation (Action Receipt - for Split/Convert):**

```
seeds = ["receipt", mint_address, token_account_address, action_id (8 bytes LE)]
program_id = Security Token Program
```

**PDA Derivation (Claim Receipt - for ClaimDistribution):**

```
seeds = ["receipt", mint_address, token_account_address, action_id (8 bytes LE), proof_hash (32 bytes)]
program_id = Security Token Program
```


### Proof

Stores Merkle proof data for distribution claims. Allows splitting large proofs into separate transactions via `CreateProofAccount` and `UpdateProofAccount`.

**Structure:**

| Field         | Type            | Size       | Description                                    |
| ------------- | --------------- | ---------- | ---------------------------------------------- |
| discriminator | u8              | 1          | Account discriminator (`4`)                    |
| bump          | u8              | 1          | PDA bump seed                                  |
| data          | Vec\<[u8; 32]\> | 4 + 32 × N | Merkle proof nodes (u32 length prefix + nodes) |

**Minimum size:** 6 bytes (empty proof - invalid state, at least one node required)

**PDA Derivation:**

```
seeds = ["proof", token_account_address, action_id (8 bytes LE)]
program_id = Security Token Program
```


## Virtual PDAs

Virtual PDAs are program-derived addresses used as authorities when invoking SPL Token 2022 extension instructions or managing transfer-hook extras. They are not data accounts, and therefore:

- Do not store any on-chain data and are never initialized or closed.
- Hold no lamports and cannot be rent-exempt; they exist deterministically from seeds.
- Are passed in instructions as authority accounts and sign via `invoke_signed`.
- Are validated against expected derived keys in the program before use.
- Use seed layouts defined by the program; some include additional components like `action_id` or `merkle_root`.

### DistributionEscrowAuthority

Virtual PDA used as authority for distribution escrow token accounts. Does not store any data (not a program account).

**PDA Derivation:**

```
seeds = ["distribution_escrow_authority", mint_address, action_id (8 bytes LE), merkle_root (32 bytes)]
program_id = Security Token Program
```


### PermanentDelegateAuthority

Virtual PDA used as authority for permanent delegate operations (forced transfers and clawbacks). This PDA does not store data; it is derived and used as a signer via `invoke_signed` when calling SPL Token 2022 instructions.

**PDA Derivation:**

```
seeds = ["mint.permanent_delegate", mint_address]
program_id = Security Token Program
```


### PauseAuthority

Virtual PDA used as authority for the Pausable extension (`Pause`/`Resume`). This PDA does not store data; it is derived and used as a signer via `invoke_signed` when calling SPL Token 2022 instructions.

**PDA Derivation:**

```
seeds = ["mint.pause_authority", mint_address]
program_id = Security Token Program
```


### FreezeAuthority

Virtual PDA used as authority for freezing/thawing token accounts (`Freeze`/`Thaw`). This PDA does not store data; it is derived and used as a signer via `invoke_signed` when calling SPL Token 2022 instructions.

**PDA Derivation:**

```
seeds = ["mint.freeze_authority", mint_address]
program_id = Security Token Program
```


### TransferHookAuthority

Virtual PDA used as authority for the TransferHook extension on a mint. It is also required when managing verification config for `Transfer` to authorize updates to the `ExtraAccountMetaList` associated with the mint. This PDA does not store data; it is derived and used as a signer via `invoke_signed` when calling SPL Token 2022 instructions.

**PDA Derivation:**

```
seeds = ["mint.transfer_hook", mint_address]
program_id = Security Token Program
```


## Serialization Conventions

This section summarizes common encoding rules used throughout the program to keep instruction and account serialization consistent.

- Discriminators: First byte ($u8$) identifies the instruction or account type.
- Endianness: All integer fields use little-endian ($u32$, $u64$).
- Strings: UTF-8 with $u32$ (LE) length prefix, followed by raw bytes.
- Vec<T>: $u32$ (LE) length prefix, then each element in order.
- Option<T>: 1-byte prefix (0 = None, 1 = Some); if Some, the value bytes follow immediately.
- Fixed-size arrays: Stored inline as raw bytes in field order (e.g., 32-byte hashes).

Where a section provides explicit serialization notes, they follow these conventions. If unspecified, assume the rules above.


## Errors

Errors returned by the program map to `ProgramError::Custom(code)`. The table lists custom error codes and descriptions from `SecurityTokenError`.

| Error Name                          | Code | Description                                               |
| ----------------------------------- | ---- | --------------------------------------------------------- |
| VerificationProgramNotFound         | 1    | Verification program not found                            |
| NotEnoughAccountsForVerification    | 2    | Not enough accounts for verification                      |
| AccountIntersectionMismatch         | 3    | Required account sets do not intersect as expected        |
| InvalidVerificationConfigPda        | 4    | Provided VerificationConfig PDA does not match derivation |
| CannotModifyExternalMetadataAccount | 5    | External metadata account cannot be modified              |
| InternalMetadataRequiresData        | 6    | Internal metadata storage requires metadata to be present |
| ExternalMetadataForbidsData         | 7    | External metadata storage forbids metadata in this call   |

Refer to these when handling failures in verification flows or metadata updates.


## Instructions

All instructions use a discriminator byte as the first byte of instruction data:

| Instruction                  | Discriminator |
| ---------------------------- | ------------- |
| InitializeMint               | `0`           |
| UpdateMetadata               | `1`           |
| InitializeVerificationConfig | `2`           |
| UpdateVerificationConfig     | `3`           |
| TrimVerificationConfig       | `4`           |
| Verify                       | `5`           |
| Mint                         | `6`           |
| Burn                         | `7`           |
| Pause                        | `8`           |
| Resume                       | `9`           |
| Freeze                       | `10`          |
| Thaw                         | `11`          |
| Transfer                     | `12`          |
| CreateRateAccount            | `13`          |
| UpdateRateAccount            | `14`          |
| CloseRateAccount             | `15`          |
| Split                        | `16`          |
| Convert                      | `17`          |
| CreateProofAccount           | `18`          |
| UpdateProofAccount           | `19`          |
| CreateDistributionEscrow     | `20`          |
| ClaimDistribution            | `21`          |
| CloseActionReceiptAccount    | `22`          |
| CloseClaimReceiptAccount     | `23`          |
| UpdateDefaultAccountState    | `24`          |

For general encoding rules and failure codes, see [Serialization Conventions](#serialization-conventions) and [Errors](#errors).


### InitializeMint

Creates a new security token mint with required extensions and optional metadata.

**Discriminator:** `0`

**Authorization:** Permissionless

**Accounts:**

| #   | Account        | Signer | Writable | Description                     |
| --- | -------------- | ------ | -------- | ------------------------------- |
| 0   | mint           | ✓      | ✓        | New mint account (keypair)      |
| 1   | mint_authority |        | ✓        | [MintAuthority](#mintauthority) PDA to be created |
| 2   | creator        | ✓      | ✓        | Mint creator and payer          |
| 3   | token_program  |        |          | SPL Token 2022 Program          |
| 4   | system_program |        |          | System Program                  |
| 5   | rent_sysvar    |        |          | Rent Sysvar                     |

**Arguments:**

```rust
// Serialization:
// - InitializeMintArgs: bytes = MintArgs, then for each optional field in order
//   (ix_metadata_pointer, ix_metadata, ix_scaled_ui_amount, ix_default_account_state):
//   a 1-byte presence flag (0 = absent, 1 = present) immediately followed by the
//   field's bytes if present. Layout: flag | [payload], flag | [payload], ...
//   ix_default_account_state payload is a single byte: 1 = Initialized, 2 = Frozen.
struct InitializeMintArgs {
    ix_mint: MintArgs,
    ix_metadata_pointer: Option<MetadataPointerArgs>,
    ix_metadata: Option<TokenMetadataArgs>,
    ix_scaled_ui_amount: Option<ScaledUiAmountConfigArgs>,
    ix_default_account_state: Option<u8>, // 1 = Initialized, 2 = Frozen
}

// - MintArgs: decimals (1 byte), mint_authority (32 bytes), freeze_authority (32 bytes).
struct MintArgs {
    decimals: u8,
    mint_authority: Pubkey,
    freeze_authority: Pubkey,
}

// - MetadataPointerArgs: authority (32 bytes), metadata_address (32 bytes).
struct MetadataPointerArgs {
    authority: Pubkey,
    metadata_address: Pubkey,
}

// - TokenMetadataArgs (Borsh-like): name/symbol/uri as UTF-8 with u32 LE length;
//   additional_metadata as u32 LE length + raw bytes.
struct TokenMetadataArgs {
    update_authority: Pubkey,
    mint: Pubkey,
    name: String,
    symbol: String,
    uri: String,
    additional_metadata: Vec<u8>,
}

// - ScaledUiAmountConfigArgs: authority (32 bytes); multiplier and new_multiplier
//   are [u8; 8] containing f64 little-endian bytes; new_multiplier_effective_timestamp
//   is i64 little-endian.
struct ScaledUiAmountConfigArgs {
    authority: Pubkey,
    multiplier: [u8; 8],
    new_multiplier_effective_timestamp: i64,
    new_multiplier: [u8; 8],
}
```

**Description:**

Initializes a new SPL Token 2022 mint with the following extensions:

- **PermanentDelegate** - Enables forced transfers and clawbacks
- **TransferHook** - Routes transfers through verification
- **Pausable** - Enables emergency pause functionality
- **MetadataPointer** (optional) - Points to metadata location
- **TokenMetadata** (optional) - Stores metadata in mint account
- **ScaledUiAmount** (optional) - Display scaling for UI
- **DefaultAccountState** (optional) - Sets the initial state for newly created token accounts (`Initialized` or `Frozen`). When `Frozen`, new accounts are frozen by default and must be explicitly thawed before use. Managed by the program-owned [FreezeAuthority PDA](#freezeauthority).

After initialization, mint authority is transferred to a program-controlled `MintAuthority` PDA. The provided `creator` is stored in the `MintAuthority` account, and the creator's signature may authorize subsequent instructions that use the [Initial Mint Authority](#initial-mint-authority) authorization type.



### UpdateMetadata

Updates the token metadata stored in the mint account.

**Discriminator:** `1`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account        | Signer | Writable | Description            |
| --- | -------------- | ------ | -------- | ---------------------- |
| 0   | mint_authority |        |          | [MintAuthority](#mintauthority) PDA |
| 1   | payer          | ✓      | ✓        | Transaction fee payer  |
| 2   | mint_account   |        | ✓        | Mint account to update |
| 3   | token_program  |        |          | SPL Token 2022 Program |
| 4   | system_program |        |          | System Program         |

**Arguments:**

```rust
struct UpdateMetadataArgs {
    metadata: TokenMetadataArgs,
}

// - TokenMetadataArgs (Borsh-like): name/symbol/uri as UTF-8 with u32 LE length;
//   additional_metadata as u32 LE length + raw bytes.
struct TokenMetadataArgs {
    update_authority: Pubkey,
    mint: Pubkey,
    name: String,
    symbol: String,
    uri: String,
    additional_metadata: Vec<u8>,
}
```

**Description:**

Updates the token metadata stored in the mint account. If a metadata pointer is used, perform the update via the SPL Token 2022 Program directly.


### InitializeVerificationConfig

Creates a new verification configuration for a specific instruction type.

**Discriminator:** `2`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account               | Signer | Writable | Description                      |
| --- | --------------------- | ------ | -------- | -------------------------------- |
| 0   | payer                 | ✓      | ✓        | Transaction fee payer            |
| 1   | mint_account          |        |          | Mint account                     |
| 2   | config_account        |        | ✓        | [VerificationConfig](#verificationconfig) account to create |
| 3   | system_program        |        |          | System Program                   |
| 4   | account_metas_pda     |        | ✓        | ExtraAccountMetaList PDA \*      |
| 5   | transfer_hook_pda     |        |          | [TransferHookAuthority](#transferhookauthority) PDA \* |
| 6   | transfer_hook_program |        |          | Transfer hook program \*         |

\* Required only when `instruction_discriminator = 12` (Transfer) to manage ExtraAccountMetaList for transfer hook.

**Arguments:**

```rust
// Serialization: instruction_discriminator (1 byte) + cpi_mode (1 byte, 0/1)
// + nested programs count (u32 LE) + each program and its extra accounts.
struct InitializeVerificationConfigArgs {
    instruction_discriminator: u8,
    cpi_mode: bool,
    programs: Vec<VerificationProgramConfig>,
}
```


### UpdateVerificationConfig

Updates an existing verification configuration.

**Discriminator:** `3`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account               | Signer | Writable | Description                      |
| --- | --------------------- | ------ | -------- | -------------------------------- |
| 0   | payer                 | ✓      | ✓        | Transaction fee payer            |
| 1   | mint_account          |        |          | Mint account                     |
| 2   | config_account        |        | ✓        | [VerificationConfig](#verificationconfig) account to update |
| 3   | system_program        |        |          | System Program                   |
| 4   | account_metas_pda     |        | ✓        | ExtraAccountMetaList PDA \*      |
| 5   | transfer_hook_pda     |        |          | [TransferHookAuthority](#transferhookauthority) PDA \* |
| 6   | transfer_hook_program |        |          | Transfer hook program \*         |

\* Required only when `instruction_discriminator = 12` (Transfer) to manage ExtraAccountMetaList for transfer hook.

**Arguments:**

```rust
// Serialization: instruction_discriminator (1 byte) + cpi_mode (1 byte, 0/1)
// + offset (1 byte) + nested programs count (u32 LE) + each program and its extras.
struct UpdateVerificationConfigArgs {
    instruction_discriminator: u8,
    cpi_mode: bool,
    offset: u8,
    programs: Vec<VerificationProgramConfig>,
}
```

**Description:**

Updates the verification program list starting at the specified offset. You can also toggle CPI mode for the instruction config. If resizing is required, the VerificationConfig account is reallocated returning reclaimed rent to the payer.


### TrimVerificationConfig

Reduces the size of or closes a verification configuration.

**Discriminator:** `4`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account               | Signer | Writable | Description                    |
| --- | --------------------- | ------ | -------- | ------------------------------ |
| 0   | mint_account          |        | ✓        | Mint account                   |
| 1   | config_account        |        | ✓        | [VerificationConfig](#verificationconfig) account to trim |
| 2   | recipient             |        | ✓        | Recipient for reclaimed rent   |
| 3   | system_program        |        |          | System Program                 |
| 4   | account_metas_pda     |        | ✓        | ExtraAccountMetaList PDA \*    |
| 5   | transfer_hook_pda     |        |          | [TransferHookAuthority](#transferhookauthority) PDA \* |
| 6   | transfer_hook_program |        |          | Transfer hook program \*       |

\* Required only when `instruction_discriminator = 12` (Transfer) to manage ExtraAccountMetaList for transfer hook.

**Arguments:**

```rust
// Serialization: instruction_discriminator (1 byte) + size (1 byte) + close (1 byte, 0/1).
struct TrimVerificationConfigArgs {
    instruction_discriminator: u8,
    size: u8,
    close: bool,
}
```

**Description:**

Reduces the verification program list to the specified size or closes the account, returning reclaimed rent to the recipient.

For Transfer, `close=true` intentionally leaves the existing Hook meta-list account. Subsequent regular transfers fail closed and reinitialization is not supported until that lifecycle is redesigned.



### Verify

Validates that the caller has authority to execute a specific instruction. Used in introspection mode.

**Discriminator:** `5`

**Authorization:** Permissionless

**Accounts:**

| #   | Account             | Signer | Writable | Description            |
| --- | ------------------- | ------ | -------- | ---------------------- |
| 0   | mint                |        |          | Mint account           |
| 1   | verification_config |        |          | [VerificationConfig](#verificationconfig) account |
| 2   | instructions_sysvar |        |          | Instructions Sysvar    |

**Arguments:**

```rust
// Serialization: ix (1 byte) + instruction_data raw bytes (opaque to this instruction).
struct VerifyArgs {
    ix: u8,
    instruction_data: Vec<u8>,
}
```

**Description:**

This instruction performs a check that a specified instruction is successfully verified by all required verification programs and can proceed to execution.


### Mint

Mints new tokens to a destination account.

**Discriminator:** `6`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account        | Signer | Writable | Description               |
| --- | -------------- | ------ | -------- | ------------------------- |
| 0   | mint_authority |        | ✓        | [MintAuthority](#mintauthority) PDA |
| 1   | mint_account   |        | ✓        | Mint account              |
| 2   | destination    |        | ✓        | Destination token account |
| 3   | token_program  |        |          | SPL Token 2022 Program    |

**Arguments:**

```rust
// Serialization: amount (u64 LE, 8 bytes).
amount: u64
```

**Description:**

Increases token supply and immediately credits the specified destination token account.


### Burn

Burns tokens from a token account.

**Discriminator:** `7`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account            | Signer | Writable | Description                |
| --- | ------------------ | ------ | -------- | -------------------------- |
| 0   | permanent_delegate |        |          | [PermanentDelegate PDA](#permanentdelegateauthority) |
| 1   | mint_account       |        | ✓        | Mint account               |
| 2   | token_account      |        | ✓        | Token account to burn from |
| 3   | token_program      |        |          | SPL Token 2022 Program     |

**Arguments:**

```rust
// Serialization: amount (u64 LE, 8 bytes).
amount: u64
```

**Description:**

Decreases token supply and immediately debits the specified token account.


### Pause

Pauses all token transfers for the mint.

**Discriminator:** `8`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account         | Signer | Writable | Description            |
| --- | --------------- | ------ | -------- | ---------------------- |
| 0   | pause_authority |        |          | [PauseAuthority](#pauseauthority) PDA |
| 1   | mint_account    |        | ✓        | Mint account           |
| 2   | token_program   |        |          | SPL Token 2022 Program |

**Arguments:** None


### Resume

Resumes token transfers for a paused mint.

**Discriminator:** `9`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account         | Signer | Writable | Description            |
| --- | --------------- | ------ | -------- | ---------------------- |
| 0   | pause_authority |        |          | [PauseAuthority](#pauseauthority) PDA |
| 1   | mint_account    |        | ✓        | Mint account           |
| 2   | token_program   |        |          | SPL Token 2022 Program |

**Arguments:** None


### Freeze

Freezes a specific token account, preventing transfers.

**Discriminator:** `10`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account          | Signer | Writable | Description             |
| --- | ---------------- | ------ | -------- | ----------------------- |
| 0   | freeze_authority |        |          | [FreezeAuthority](#freezeauthority) PDA |
| 1   | mint_account     |        |          | Mint account            |
| 2   | token_account    |        | ✓        | Token account to freeze |
| 3   | token_program    |        |          | SPL Token 2022 Program  |

**Arguments:** None


### Thaw

Unfreezes a frozen token account.

**Discriminator:** `11`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account          | Signer | Writable | Description            |
| --- | ---------------- | ------ | -------- | ---------------------- |
| 0   | freeze_authority |        |          | [FreezeAuthority](#freezeauthority) PDA |
| 1   | mint_account     |        |          | Mint account           |
| 2   | token_account    |        | ✓        | Token account to thaw  |
| 3   | token_program    |        |          | SPL Token 2022 Program |

**Arguments:** None


### Transfer

Transfers tokens between accounts (forced transfer).

**Discriminator:** `12`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account                      | Signer | Writable | Description               |
| --- | ---------------------------- | ------ | -------- | ------------------------- |
| 0   | permanent_delegate_authority |        |          | [PermanentDelegate PDA](#permanentdelegateauthority) |
| 1   | mint_account                 |        |          | Mint account              |
| 2   | from_token_account           |        | ✓        | Source token account      |
| 3   | to_token_account             |        | ✓        | Destination token account |
| 4   | transfer_hook_program        |        |          | Transfer hook program     |
| 5   | token_program                |        |          | SPL Token 2022 Program    |

**Arguments:**

```rust
// Serialization: amount (u64 LE, 8 bytes).
amount: u64
```

### CreateRateAccount

Creates a rate configuration for split/convert operations.

**Discriminator:** `13`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account        | Signer | Writable | Description           |
| --- | -------------- | ------ | -------- | --------------------- |
| 0   | payer          | ✓      | ✓        | Transaction fee payer |
| 1   | rate_account   |        | ✓        | [Rate](#rate) account to create |
| 2   | mint_from      |        |          | Source mint           |
| 3   | mint_to        |        |          | Destination mint      |
| 4   | system_program |        |          | System Program        |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + rate.rounding (u8)
// + rate.numerator (u8) + rate.denominator (u8).
struct CreateRateArgs {
    action_id: u64,
    rate: RateArgs,
}

struct RateArgs {
    rounding: u8,    // 0 = Up, 1 = Down
    numerator: u8,
    denominator: u8,
}
```


### UpdateRateAccount

Updates an existing rate configuration.

**Discriminator:** `14`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account      | Signer | Writable | Description        |
| --- | ------------ | ------ | -------- | ------------------ |
| 0   | rate_account |        | ✓        | [Rate](#rate) account to update |
| 1   | mint_from    |        |          | Source mint        |
| 2   | mint_to      |        |          | Destination mint   |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + rate.rounding (u8)
// + rate.numerator (u8) + rate.denominator (u8).
struct UpdateRateArgs {
    action_id: u64,
    rate: RateArgs,
}

struct RateArgs {
    rounding: u8,    // 0 = Up, 1 = Down
    numerator: u8,
    denominator: u8,
}
```


### CloseRateAccount

Closes a rate account and reclaims rent.

**Discriminator:** `15`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account      | Signer | Writable | Description                    |
| --- | ------------ | ------ | -------- | ------------------------------ |
| 0   | rate_account |        | ✓        | [Rate](#rate) account to close |
| 1   | destination  |        | ✓        | Recipient for reclaimed rent   |
| 2   | mint_from    |        |          | Source mint                    |
| 3   | mint_to      |        |          | Destination mint               |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes).
struct CloseRateArgs {
    action_id: u64,
}
```


### Split

Executes a token split operation (e.g., stock split). Mints additional tokens to holder based on rate.

**Discriminator:** `16`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account            | Signer | Writable | Description            |
| --- | ------------------ | ------ | -------- | ---------------------- |
| 0   | mint_authority     |        |          | [MintAuthority](#mintauthority) PDA |
| 1   | permanent_delegate |        |          | [PermanentDelegate PDA](#permanentdelegateauthority) |
| 2   | payer              | ✓      | ✓        | Transaction fee payer  |
| 3   | mint_account       |        | ✓        | Mint account           |
| 4   | token_account      |        | ✓        | Holder's token account |
| 5   | rate_account       |        |          | [Rate](#rate) account |
| 6   | receipt_account    |        | ✓        | [Receipt](#receipt) account to create |
| 7   | token_program      |        |          | SPL Token 2022 Program |
| 8   | system_program     |        |          | System Program         |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes).
struct SplitArgs {
    action_id: u64,
}
```


### Convert

Converts tokens from one mint to another based on rate (e.g., bond conversion).

**Discriminator:** `17`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account            | Signer | Writable | Description               |
| --- | ------------------ | ------ | -------- | ------------------------- |
| 0   | mint_authority     |        |          | [MintAuthority](#mintauthority) PDA |
| 1   | permanent_delegate |        |          | [PermanentDelegate PDA](#permanentdelegateauthority) |
| 2   | payer              | ✓      | ✓        | Transaction fee payer     |
| 3   | mint_from          |        | ✓        | Source mint account       |
| 4   | mint_to            |        | ✓        | Destination mint account  |
| 5   | token_account_from |        | ✓        | Source token account      |
| 6   | token_account_to   |        | ✓        | Destination token account |
| 7   | rate_account       |        |          | [Rate](#rate) account     |
| 8   | receipt_account    |        | ✓        | [Receipt](#receipt) account to create |
| 9   | token_program      |        |          | SPL Token 2022 Program    |
| 10  | system_program     |        |          | System Program            |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + amount_to_convert (u64 LE, 8 bytes).
struct ConvertArgs {
    action_id: u64,
    amount_to_convert: u64,
}
```


### CreateProofAccount

Creates a Proof account to store Merkle proof data for distribution claims.

**Discriminator:** `18`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account        | Signer | Writable | Description                    |
| --- | -------------- | ------ | -------- | ------------------------------ |
| 0   | payer          | ✓      | ✓        | Transaction fee payer          |
| 1   | mint_account   |        |          | Mint account                   |
| 2   | proof_account  |        | ✓        | [Proof](#proof) account to create |
| 3   | token_account  |        |          | Token account the proof is for |
| 4   | system_program |        |          | System Program                 |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + data length (u32 LE)
// followed by each node as 32 raw bytes.
struct CreateProofArgs {
    action_id: u64,
    data: Vec<[u8; 32]>,
}
```


### UpdateProofAccount

Updates an existing Proof account with additional proof nodes.

**Discriminator:** `19`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account        | Signer | Writable | Description                    |
| --- | -------------- | ------ | -------- | ------------------------------ |
| 0   | payer          | ✓      | ✓        | Transaction fee payer          |
| 1   | mint_account   |        |          | Mint account                   |
| 2   | proof_account  |        | ✓        | [Proof](#proof) account to update |
| 3   | token_account  |        |          | Token account the proof is for |
| 4   | system_program |        |          | System Program                 |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + data (32 raw bytes)
// + offset (u32 LE).
struct UpdateProofArgs {
    action_id: u64,
    data: [u8; 32],
    offset: u32,
}
```


### CreateDistributionEscrow

Creates an escrow token account for distribution (dividends/coupons).

**Discriminator:** `20`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account                          | Signer | Writable | Description                      |
| --- | -------------------------------- | ------ | -------- | -------------------------------- |
| 0   | distribution_escrow_authority    |        |          | [DistributionEscrowAuthority](#distributionescrowauthority) PDA |
| 1   | payer                            | ✓      | ✓        | Transaction fee payer            |
| 2   | distribution_token_account       |        | ✓        | Escrow token account to create   |
| 3   | distribution_mint                |        |          | Distribution mint                |
| 4   | token_program                    |        |          | SPL Token 2022 Program           |
| 5   | associated_token_account_program |        |          | Associated Token Account Program |
| 6   | system_program                   |        |          | System Program                   |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + merkle_root (32 raw bytes).
struct CreateDistributionEscrowArgs {
    action_id: u64,
    merkle_root: [u8; 32],
}
```


### ClaimDistribution

Claims tokens from a distribution escrow based on Merkle proof.

**Discriminator:** `21`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account                      | Signer | Writable | Description                     |
| --- | ---------------------------- | ------ | -------- | ------------------------------- |
| 0   | permanent_delegate_authority |        |          | [PermanentDelegate PDA](#permanentdelegateauthority) |
| 1   | payer                        | ✓      | ✓        | Transaction fee payer           |
| 2   | mint_account                 |        |          | Mint account                    |
| 3   | eligible_token_account       |        | ✓        | Claimant's token account        |
| 4   | escrow_token_account         |        | ✓        | (Optional) Escrow token account |
| 5   | receipt_account              |        | ✓        | [Receipt](#receipt) account to create |
| 6   | proof_account                |        |          | (Optional) [Proof](#proof) account |
| 7   | transfer_hook_program        |        |          | Transfer hook program           |
| 8   | token_program                |        |          | SPL Token 2022 Program          |
| 9   | system_program               |        |          | System Program                  |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + amount (u64 LE, 8 bytes) + merkle_root (32 raw bytes)
// + leaf_index (u32 LE) + Option prefix (1 byte: 0 = None, 1 = Some) for merkle_proof.
// If Some: proof length (u32 LE) followed by each node (32 raw bytes).
struct ClaimDistributionArgs {
    action_id: u64,
    amount: u64,
    merkle_root: [u8; 32],
    leaf_index: u32,
    merkle_proof: Option<Vec<[u8; 32]>>,
}
```


### CloseActionReceiptAccount

Closes an action receipt account (for Split/Convert) and reclaims rent.

**Discriminator:** `22`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account         | Signer | Writable | Description                  |
| --- | --------------- | ------ | -------- | ---------------------------- |
| 0   | receipt_account |        | ✓        | [Receipt](#receipt) account to close |
| 1   | destination     |        | ✓        | Recipient for reclaimed rent |
| 2   | mint_account    |        |          | Mint account                 |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + token_account (32 bytes).
struct CloseActionReceiptArgs {
    action_id: u64,
    token_account: Pubkey,
}
```

---

### CloseClaimReceiptAccount

Closes a claim receipt account (for ClaimDistribution) and reclaims rent.

**Discriminator:** `23`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account                | Signer | Writable | Description                  |
| --- | ---------------------- | ------ | -------- | ---------------------------- |
| 0   | receipt_account        |        | ✓        | [Receipt](#receipt) account to close |
| 1   | destination            |        | ✓        | Recipient for reclaimed rent |
| 2   | mint_account           |        |          | Mint account                 |
| 3   | eligible_token_account |        |          | Token account from the claim |
| 4   | proof_account          |        |          | (Optional) [Proof](#proof) account |

**Arguments:**

```rust
// Serialization: action_id (u64 LE, 8 bytes) + Option prefix (1 byte: 0 = None, 1 = Some).
// If Some: proof length (u32 LE) followed by each node (32 raw bytes).
struct CloseClaimReceiptArgs {
    action_id: u64,
    merkle_proof: Option<Vec<[u8; 32]>>,
}
```


### UpdateDefaultAccountState

Changes the default state applied to newly created token accounts for a mint that was initialized with the `DefaultAccountState` extension.

**Discriminator:** `24`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account          | Signer | Writable | Description                                                   |
| --- | ---------------- | ------ | -------- | ------------------------------------------------------------- |
| 0   | freeze_authority |        |          | [FreezeAuthority PDA](#freezeauthority) — program-owned signer for the CPI |
| 1   | mint_account     |        | ✓        | Mint account to update                                        |
| 2   | token_program    |        |          | SPL Token 2022 Program                                        |

**Arguments:**

```rust
// Serialization: state (1 byte). Valid values: 1 = Initialized, 2 = Frozen.
struct UpdateDefaultAccountStateArgs {
    state: u8,
}
```

**Description:**

Updates the `DefaultAccountState` Token-2022 extension on an existing mint. The new `state` value determines the initial state of all token accounts created after this call. `Uninitialized` (`0`) is rejected.

The instruction proxies the Token-2022 `UpdateDefaultAccountState` CPI, signing with the program-owned `FreezeAuthority` PDA. The mint **must** have been initialized with `ix_default_account_state` set; calling this instruction on a mint without the extension will fail.


## Verification Program Interface

Verification programs must implement a specific interface to be compatible with the Security Token Program.

[A boilerplate example for a verification program](./../examples/verification-program-example/README.md) is provided.

### Instruction Format

Verification programs receive instructions with the following data format:

```
[instruction_discriminator: u8, ...instruction_args]
```

The discriminator byte matches the Security Token instruction being verified, followed by the same arguments.

### Account Format

Verification programs receive the canonical operation accounts followed by only their own configured extras. Account matching is exact; unrelated trailing accounts are rejected.

Client-side routing and new transaction assembly use Versioned Transaction V0 by default. Large routing configurations require an address lookup table; legacy transaction helpers remain supported only for existing callers.

### Configuration and V0 Transaction Flow

Configuration data and runtime accounts have different transaction-size constraints. An address lookup table compresses runtime account keys, but it does not compress serialized `InitializeVerificationConfig` or `UpdateVerificationConfig` arguments.

#### Creating a Configuration

Build a new configuration with bounded V0 transactions and no lookup table:

1. Send `InitializeVerificationConfig` with the first `VerificationProgramConfig` group.
2. For every remaining group at index `i`, send `UpdateVerificationConfig` with `offset = i` and `programs = [group]`.
3. Fetch and decode the final config, then verify its ordered program groups before enabling the affected operation.

One group contains at most 8 extras, so each chunk fits without a lookup table. The complete config remains capped at 10 programs and 32 total extras. `UpdateVerificationConfig` replaces an existing group at its offset or appends it when the offset equals the current program count; it does not insert a group or truncate later groups.

For Transfer, every chunk must pass `account_metas_pda`, `transfer_hook_pda`, and `transfer_hook_program`. Core updates the config and the Transfer Hook meta-list in the same transaction. A failed meta-list update rolls back the config update.

Each successful chunk is immediately active. Initial setup should finish before transfers or other affected operations are enabled. Updating a live policy requires a maintenance window or another mechanism that pauses the affected operation. If policy replacement must be atomic without pausing, the complete encoded config must fit in one transaction; lookup tables cannot solve that instruction-data limit.

#### Preparing a Lookup Table

Prepare the lookup table after the final config is known:

1. Decode or fetch the config and resolve each group sequentially with the final operation instruction data and canonical accounts.
2. Start with the unique resolved extra-account addresses.
3. In CPI mode, also include verifier program IDs because they are routing accounts of the Security Token instruction.
4. Optionally include other stable, non-signer canonical or fixed accounts used by the final transaction.
5. Exclude the payer and every signer. Directly invoked program IDs remain static message keys and do not benefit from a lookup table.
6. Create the table with its authority and a recent slot, then extend it in bounded address batches.
7. Wait until the bank slot is later than the table's last extension slot, fetch the active table, and compile the final V0 transaction with it.

With the Solana Rust crates, the setup instructions are created by `solana_address_lookup_table_interface::instruction::create_lookup_table(authority, payer, recent_slot)` and `extend_lookup_table(table_address, authority, Some(payer), address_batch)`. Send the create instruction first, then as many extend transactions as required by the serialized transaction-size check. Compile the operation only after fetching the active `AddressLookupTableAccount`:

```rust
let message = solana_sdk::message::v0::Message::try_compile(
    &payer,
    &operation_instructions,
    &[lookup_table_account],
    recent_blockhash,
)?;
```

The lookup table is client infrastructure and is not stored in `VerificationConfig`. Updating a config requires resolving the routing again and extending or replacing the table when new stable addresses appear. Table membership does not grant signer or writable privileges; those still come from the instruction account metas.

Resolution can depend on instruction data or current account data. If a resolved address changes per operation, either add the exact address before use or leave it as a static V0 key. Signer extras always remain static keys. Therefore the maximum routing size check assumes lookup-eligible, stable extras; every final serialized transaction must still be checked against the 1232-byte packet limit.

#### Executing with a Lookup Table

For CPI mode, append ordered `[program, own extras...]` groups to the Security Token instruction, compile it as V0 with the active lookup table, serialize it, validate the packet size, and send it.

For introspection mode, build the verifier instructions in config order, place that contiguous block immediately before the Security Token instruction, then compile the complete block as one V0 transaction. Verifier program IDs are directly invoked and remain static, while eligible canonical and extra accounts may be loaded from the table.

Do not split one verified operation across transactions. CPI routing and the introspection block must remain atomic with the Security Token instruction.

#### Executing without a Lookup Table

Use the same V0 assembly with an empty lookup-table list:

1. Resolve the config and append the routing groups or build the contiguous introspection block.
2. Compile and serialize the complete V0 transaction without lookup tables.
3. Send it only when the serialized size is at most 1232 bytes.

For the Rust compiler above, the no-LUT form passes `&[]` instead of `&[lookup_table_account]` to `try_compile`.

There is no fixed no-LUT extras limit because the size also depends on canonical accounts, signers, instruction data, repeated keys, and the number of verifier instructions. If the complete transaction is too large, create a lookup table or reduce the routing config; falling back to a legacy transaction or splitting the operation is not supported by the new flow.

### Expected Behavior

- **Success:** Return `Ok(())` to approve the operation
- **Failure:** Return an error to reject the operation

In CPI mode, any error from a verification program will cause the entire Security Token instruction to fail.

In introspection mode, the verification program must have been called successfully before the Security Token instruction.

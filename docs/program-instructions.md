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
- [Accounts](#accounts)
- [Instructions](#instructions)
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

**Applicable instructions:** `UpdateMetadata`, `InitializeVerificationConfig`, `UpdateVerificationConfig`, `TrimVerificationConfig`, `CreateRateAccount`, `UpdateRateAccount`, `CloseRateAccount`, `CreateDistributionEscrow`, `CloseActionReceiptAccount`, `CloseClaimReceiptAccount`

#### Verification Programs Only

Instructions that **must** be authorized through configured verification programs. These are typically token operations that require compliance checks (KYC/AML, transfer restrictions, etc.).

**Applicable instructions:** `Mint`, `Burn`, `Pause`, `Resume`, `Freeze`, `Thaw`, `Transfer`, `Split`, `Convert`, `CreateProofAccount`, `UpdateProofAccount`, `ClaimDistribution`


### Verification Modes

When using verification programs, the Security Token Program supports two verification modes. The required verification flow is configured via the `cpi_mode` option in the corresponding verification config.

#### Introspection Mode (`cpi_mode = false`)

In introspection mode, the Security Token Program examines the Instructions Sysvar to verify that all required verification programs were called **before** the current instruction within the same transaction. In order to pass authorization via verification programs in introspection mode, the following conditions must be satisfied:

- A corresponding instruction verification config exists with `cpi_mode` disabled and passed to Security Token Program.
- A corresponding instruction verification config exists with `cpi_mode` disabled and is passed to the Security Token Program.
- All verification programs must be invoked **before** the Security Token instruction and must complete successfully.
- Each verification program call must include the same instruction data and target instruction discriminator prefix.
- Each verification program call must include **at least** all accounts used in the Security Token instruction. Additional accounts may be included for verification purposes if needed, provided they appear at the end of the instruction's required account list.

#### CPI Mode (`cpi_mode = true`)

In CPI mode, the Security Token Program directly invokes (via CPI) each configured verification program during instruction processing. In order to pass authorization via verification programs in CPI mode, the following conditions must be satisfied:

- A corresponding instruction verification config exists with `cpi_mode` disabled and passed to Security Token Program.
- A corresponding instruction verification config exists with `cpi_mode` enabled and is passed to the Security Token Program.
- Verification program accounts must be appended at the end of the Security Token Program instruction accounts.
- Each verification program receives the same instruction data and accounts (verification overhead and verification program accounts are stripped before CPI)

**Important:** When verification programs are invoked in CPI, they receive **only the core instruction accounts** - the overhead accounts and CPI program accounts are stripped. This ensures verification programs have a consistent interface regardless of the verification mode used.


### Verification Overhead Accounts

Instructions that require authorization should include a **verification overhead** - 3 accounts at the beginning of the accounts list that handle the authorization logic. The exact accounts depend on the authorization type.

#### Verification Programs

For instructions that support authorization via verification programs:

| #   | Account             | Description                                                                   |
| --- | ------------------- | ----------------------------------------------------------------------------- |
| 0   | mint                | The mint account being operated on                                            |
| 1   | verification_config | VerificationConfig PDA for this instruction type                              |
| 2   | instructions_sysvar | Instructions Sysvar (introspection mode) or program_id placeholder (CPI mode) |

#### Initial Mint Authority

For instructions that support authorization via initial mint creator signature:

| #   | Account                               | Description                        |
| --- | ------------------------------------- | ---------------------------------- |
| 0   | mint                                  | The mint account being operated on |
| 1   | mint_authority                        | MintAuthority PDA                  |
| 2   | creator                               | Creator signer                     |

After the overhead come the **instruction-specific accounts** (core accounts).


## Accounts

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
| verification_programs     | Vec\<Pubkey\> | 4 + 32 × N | List of verification program addresses (u32 length prefix + addresses) |

**Minimum size:** 8 bytes (empty program list)

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
seeds = ["receipt", mint_address, action_id (8 bytes LE)]
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


### DistributionEscrowAuthority

Virtual PDA used as authority for distribution escrow token accounts. Does not store any data (not a program account).

**PDA Derivation:**

```
seeds = ["distribution_escrow_authority", mint_address, action_id (8 bytes LE), merkle_root (32 bytes)]
program_id = Security Token Program
```

---

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

### InitializeMint

Creates a new security token mint with required extensions and optional metadata.

**Discriminator:** `0`

**Authorization:** Permissionless

**Accounts:**

| #   | Account        | Signer | Writable | Description                     |
| --- | -------------- | ------ | -------- | ------------------------------- |
| 0   | mint           | ✓      | ✓        | New mint account (keypair)      |
| 1   | mint_authority |        | ✓        | MintAuthority PDA to be created |
| 2   | creator        | ✓      | ✓        | Mint creator and payer          |
| 3   | token_program  |        |          | SPL Token 2022 Program          |
| 4   | system_program |        |          | System Program                  |
| 5   | rent_sysvar    |        |          | Rent Sysvar                     |

**Arguments:**

```rust
struct InitializeMintArgs {
    ix_mint: MintArgs,
    ix_metadata_pointer: Option<MetadataPointerArgs>,
    ix_metadata: Option<TokenMetadataArgs>,
    ix_scaled_ui_amount: Option<ScaledUiAmountConfigArgs>,
}

struct MintArgs {
    decimals: u8,
    mint_authority: Pubkey,
    freeze_authority: Pubkey,
}

struct MetadataPointerArgs {
    authority: Pubkey,
    metadata_address: Pubkey,
}

struct TokenMetadataArgs {
    update_authority: Pubkey,
    mint: Pubkey,
    name: String,
    symbol: String,
    uri: String,
    additional_metadata: Vec<u8>,
}

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

After initialization, mint authority is transferred to a program-controlled PDA.

---

### UpdateMetadata

Updates the token metadata stored in the mint account.

**Discriminator:** `1`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account        | Signer | Writable | Description            |
| --- | -------------- | ------ | -------- | ---------------------- |
| 0   | mint_authority |        |          | MintAuthority PDA      |
| 1   | payer          | ✓      | ✓        | Transaction fee payer  |
| 2   | mint_account   |        | ✓        | Mint account to update |
| 3   | token_program  |        |          | SPL Token 2022 Program |
| 4   | system_program |        |          | System Program         |

**Arguments:**

```rust
struct UpdateMetadataArgs {
    metadata: TokenMetadataArgs,
}

struct TokenMetadataArgs {
    update_authority: Pubkey,
    mint: Pubkey,
    name: String,
    symbol: String,
    uri: String,
    additional_metadata: Vec<u8>,
}
```

---

### InitializeVerificationConfig

Creates a new verification configuration for a specific instruction type.

**Discriminator:** `2`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account               | Signer | Writable | Description                      |
| --- | --------------------- | ------ | -------- | -------------------------------- |
| 0   | payer                 | ✓      | ✓        | Transaction fee payer            |
| 1   | mint_account          |        |          | Mint account                     |
| 2   | config_account        |        | ✓        | VerificationConfig PDA to create |
| 3   | system_program        |        |          | System Program                   |
| 4   | account_metas_pda     |        | ✓        | ExtraAccountMetaList PDA \*      |
| 5   | transfer_hook_pda     |        |          | Transfer hook PDA \*             |
| 6   | transfer_hook_program |        |          | Transfer hook program \*         |

\* Required only when `instruction_discriminator = 12` (Transfer) to manage ExtraAccountMetaList for transfer hook.

**Arguments:**

```rust
struct InitializeVerificationConfigArgs {
    instruction_discriminator: u8,
    cpi_mode: bool,
    program_addresses: Vec<Pubkey>,
}
```

---

### UpdateVerificationConfig

Updates an existing verification configuration.

**Discriminator:** `3`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account               | Signer | Writable | Description                      |
| --- | --------------------- | ------ | -------- | -------------------------------- |
| 0   | payer                 | ✓      | ✓        | Transaction fee payer            |
| 1   | mint_account          |        |          | Mint account                     |
| 2   | config_account        |        | ✓        | VerificationConfig PDA to update |
| 3   | system_program        |        |          | System Program                   |
| 4   | account_metas_pda     |        | ✓        | ExtraAccountMetaList PDA \*      |
| 5   | transfer_hook_pda     |        |          | Transfer hook PDA \*             |
| 6   | transfer_hook_program |        |          | Transfer hook program \*         |

\* Required only when `instruction_discriminator = 12` (Transfer) to manage ExtraAccountMetaList for transfer hook.

**Arguments:**

```rust
struct UpdateVerificationConfigArgs {
    instruction_discriminator: u8,
    cpi_mode: bool,
    offset: u8,
    program_addresses: Vec<Pubkey>,
}
```

---

### TrimVerificationConfig

Reduces the size of or closes a verification configuration.

**Discriminator:** `4`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account               | Signer | Writable | Description                    |
| --- | --------------------- | ------ | -------- | ------------------------------ |
| 0   | mint_account          |        | ✓        | Mint account                   |
| 1   | config_account        |        | ✓        | VerificationConfig PDA to trim |
| 2   | recipient             |        | ✓        | Recipient for reclaimed rent   |
| 3   | system_program        |        |          | System Program                 |
| 4   | account_metas_pda     |        | ✓        | ExtraAccountMetaList PDA \*    |
| 5   | transfer_hook_pda     |        |          | Transfer hook PDA \*           |
| 6   | transfer_hook_program |        |          | Transfer hook program \*       |

\* Required only when `instruction_discriminator = 12` (Transfer) to manage ExtraAccountMetaList for transfer hook.

**Arguments:**

```rust
struct TrimVerificationConfigArgs {
    instruction_discriminator: u8,
    size: u8,
    close: bool,
}
```

---

### Verify

Validates that the caller has authority to execute a specific instruction. Used in introspection mode.

**Discriminator:** `5`

**Authorization:** Permissionless

**Accounts:**

| #   | Account             | Signer | Writable | Description            |
| --- | ------------------- | ------ | -------- | ---------------------- |
| 0   | mint                |        |          | Mint account           |
| 1   | verification_config |        |          | VerificationConfig PDA |
| 2   | instructions_sysvar |        |          | Instructions Sysvar    |

**Arguments:**

```rust
struct VerifyArgs {
    ix: u8,
    instruction_data: Vec<u8>,
}
```

---

### Mint

Mints new tokens to a destination account.

**Discriminator:** `6`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account        | Signer | Writable | Description               |
| --- | -------------- | ------ | -------- | ------------------------- |
| 0   | mint_authority |        | ✓        | MintAuthority PDA         |
| 1   | mint_account   |        | ✓        | Mint account              |
| 2   | destination    |        | ✓        | Destination token account |
| 3   | token_program  |        |          | SPL Token 2022 Program    |

**Arguments:**

```rust
amount: u64
```

---

### Burn

Burns tokens from a token account using permanent delegate authority.

**Discriminator:** `7`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account            | Signer | Writable | Description                |
| --- | ------------------ | ------ | -------- | -------------------------- |
| 0   | permanent_delegate |        |          | PermanentDelegate PDA      |
| 1   | mint_account       |        | ✓        | Mint account               |
| 2   | token_account      |        | ✓        | Token account to burn from |
| 3   | token_program      |        |          | SPL Token 2022 Program     |

**Arguments:**

```rust
amount: u64
```

---

### Pause

Pauses all token transfers for the mint.

**Discriminator:** `8`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account         | Signer | Writable | Description            |
| --- | --------------- | ------ | -------- | ---------------------- |
| 0   | pause_authority |        |          | PauseAuthority PDA     |
| 1   | mint_account    |        | ✓        | Mint account           |
| 2   | token_program   |        |          | SPL Token 2022 Program |

**Arguments:** None

---

### Resume

Resumes token transfers for a paused mint.

**Discriminator:** `9`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account         | Signer | Writable | Description            |
| --- | --------------- | ------ | -------- | ---------------------- |
| 0   | pause_authority |        |          | PauseAuthority PDA     |
| 1   | mint_account    |        | ✓        | Mint account           |
| 2   | token_program   |        |          | SPL Token 2022 Program |

**Arguments:** None

---

### Freeze

Freezes a specific token account, preventing transfers.

**Discriminator:** `10`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account          | Signer | Writable | Description             |
| --- | ---------------- | ------ | -------- | ----------------------- |
| 0   | freeze_authority |        |          | FreezeAuthority PDA     |
| 1   | mint_account     |        |          | Mint account            |
| 2   | token_account    |        | ✓        | Token account to freeze |
| 3   | token_program    |        |          | SPL Token 2022 Program  |

**Arguments:** None

---

### Thaw

Unfreezes a frozen token account.

**Discriminator:** `11`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account          | Signer | Writable | Description            |
| --- | ---------------- | ------ | -------- | ---------------------- |
| 0   | freeze_authority |        |          | FreezeAuthority PDA    |
| 1   | mint_account     |        |          | Mint account           |
| 2   | token_account    |        | ✓        | Token account to thaw  |
| 3   | token_program    |        |          | SPL Token 2022 Program |

**Arguments:** None

---

### Transfer

Transfers tokens between accounts using permanent delegate authority (forced transfer).

**Discriminator:** `12`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account                      | Signer | Writable | Description               |
| --- | ---------------------------- | ------ | -------- | ------------------------- |
| 0   | permanent_delegate_authority |        |          | PermanentDelegate PDA     |
| 1   | mint_account                 |        |          | Mint account              |
| 2   | from_token_account           |        | ✓        | Source token account      |
| 3   | to_token_account             |        | ✓        | Destination token account |
| 4   | transfer_hook_program        |        |          | Transfer hook program     |
| 5   | token_program                |        |          | SPL Token 2022 Program    |

**Arguments:**

```rust
amount: u64
```

---

### CreateRateAccount

Creates a rate configuration for split/convert operations.

**Discriminator:** `13`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account        | Signer | Writable | Description           |
| --- | -------------- | ------ | -------- | --------------------- |
| 0   | payer          | ✓      | ✓        | Transaction fee payer |
| 1   | rate_account   |        | ✓        | Rate PDA to create    |
| 2   | mint_from      |        |          | Source mint           |
| 3   | mint_to        |        |          | Destination mint      |
| 4   | system_program |        |          | System Program        |

**Arguments:**

```rust
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

---

### UpdateRateAccount

Updates an existing rate configuration.

**Discriminator:** `14`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account      | Signer | Writable | Description        |
| --- | ------------ | ------ | -------- | ------------------ |
| 0   | rate_account |        | ✓        | Rate PDA to update |
| 1   | mint_from    |        |          | Source mint        |
| 2   | mint_to      |        |          | Destination mint   |

**Arguments:**

```rust
struct UpdateRateArgs {
    action_id: u64,
    rate: RateArgs,
}

struct RateArgs {
    rounding: u8,
    numerator: u8,
    denominator: u8,
}
```

---

### CloseRateAccount

Closes a rate account and reclaims rent.

**Discriminator:** `15`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account      | Signer | Writable | Description                  |
| --- | ------------ | ------ | -------- | ---------------------------- |
| 0   | rate_account |        | ✓        | Rate PDA to close            |
| 1   | destination  |        | ✓        | Recipient for reclaimed rent |
| 2   | mint_from    |        |          | Source mint                  |
| 3   | mint_to      |        |          | Destination mint             |

**Arguments:**

```rust
struct CloseRateArgs {
    action_id: u64,
}
```

---

### Split

Executes a token split operation (e.g., stock split). Mints additional tokens to holder based on rate.

**Discriminator:** `16`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account            | Signer | Writable | Description            |
| --- | ------------------ | ------ | -------- | ---------------------- |
| 0   | mint_authority     |        |          | MintAuthority PDA      |
| 1   | permanent_delegate |        |          | PermanentDelegate PDA  |
| 2   | payer              | ✓      | ✓        | Transaction fee payer  |
| 3   | mint_account       |        | ✓        | Mint account           |
| 4   | token_account      |        | ✓        | Holder's token account |
| 5   | rate_account       |        |          | Rate PDA               |
| 6   | receipt_account    |        | ✓        | Receipt PDA to create  |
| 7   | token_program      |        |          | SPL Token 2022 Program |
| 8   | system_program     |        |          | System Program         |

**Arguments:**

```rust
struct SplitArgs {
    action_id: u64,
}
```

---

### Convert

Converts tokens from one mint to another based on rate (e.g., bond conversion).

**Discriminator:** `17`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account            | Signer | Writable | Description               |
| --- | ------------------ | ------ | -------- | ------------------------- |
| 0   | mint_authority     |        |          | MintAuthority PDA         |
| 1   | permanent_delegate |        |          | PermanentDelegate PDA     |
| 2   | payer              | ✓      | ✓        | Transaction fee payer     |
| 3   | mint_from          |        | ✓        | Source mint account       |
| 4   | mint_to            |        | ✓        | Destination mint account  |
| 5   | token_account_from |        | ✓        | Source token account      |
| 6   | token_account_to   |        | ✓        | Destination token account |
| 7   | rate_account       |        |          | Rate PDA                  |
| 8   | receipt_account    |        | ✓        | Receipt PDA to create     |
| 9   | token_program      |        |          | SPL Token 2022 Program    |
| 10  | system_program     |        |          | System Program            |

**Arguments:**

```rust
struct ConvertArgs {
    action_id: u64,
    amount_to_convert: u64,
}
```

---

### CreateProofAccount

Creates a Proof account to store Merkle proof data for distribution claims.

**Discriminator:** `18`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account        | Signer | Writable | Description                    |
| --- | -------------- | ------ | -------- | ------------------------------ |
| 0   | payer          | ✓      | ✓        | Transaction fee payer          |
| 1   | mint_account   |        |          | Mint account                   |
| 2   | proof_account  |        | ✓        | Proof PDA to create            |
| 3   | token_account  |        |          | Token account the proof is for |
| 4   | system_program |        |          | System Program                 |

**Arguments:**

```rust
struct CreateProofArgs {
    action_id: u64,
    data: Vec<[u8; 32]>,
}
```

---

### UpdateProofAccount

Updates an existing Proof account with additional proof nodes.

**Discriminator:** `19`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account        | Signer | Writable | Description                    |
| --- | -------------- | ------ | -------- | ------------------------------ |
| 0   | payer          | ✓      | ✓        | Transaction fee payer          |
| 1   | mint_account   |        |          | Mint account                   |
| 2   | proof_account  |        | ✓        | Proof PDA to update            |
| 3   | token_account  |        |          | Token account the proof is for |
| 4   | system_program |        |          | System Program                 |

**Arguments:**

```rust
struct UpdateProofArgs {
    action_id: u64,
    data: [u8; 32],
    offset: u32,
}
```

---

### CreateDistributionEscrow

Creates an escrow token account for distribution (dividends/coupons).

**Discriminator:** `20`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account                          | Signer | Writable | Description                      |
| --- | -------------------------------- | ------ | -------- | -------------------------------- |
| 0   | distribution_escrow_authority    |        |          | DistributionEscrowAuthority PDA  |
| 1   | payer                            | ✓      | ✓        | Transaction fee payer            |
| 2   | distribution_token_account       |        | ✓        | Escrow token account to create   |
| 3   | distribution_mint                |        |          | Distribution mint                |
| 4   | token_program                    |        |          | SPL Token 2022 Program           |
| 5   | associated_token_account_program |        |          | Associated Token Account Program |
| 6   | system_program                   |        |          | System Program                   |

**Arguments:**

```rust
struct CreateDistributionEscrowArgs {
    action_id: u64,
    merkle_root: [u8; 32],
}
```

---

### ClaimDistribution

Claims tokens from a distribution escrow based on Merkle proof.

**Discriminator:** `21`

**Authorization:** Verification Programs Only

**Accounts:**

| #   | Account                      | Signer | Writable | Description                     |
| --- | ---------------------------- | ------ | -------- | ------------------------------- |
| 0   | permanent_delegate_authority |        |          | PermanentDelegate PDA           |
| 1   | payer                        | ✓      | ✓        | Transaction fee payer           |
| 2   | mint_account                 |        |          | Mint account                    |
| 3   | eligible_token_account       |        | ✓        | Claimant's token account        |
| 4   | escrow_token_account         |        | ✓        | (Optional) Escrow token account |
| 5   | receipt_account              |        | ✓        | Receipt PDA to create           |
| 6   | proof_account                |        |          | (Optional) Proof PDA            |
| 7   | transfer_hook_program        |        |          | Transfer hook program           |
| 8   | token_program                |        |          | SPL Token 2022 Program          |
| 9   | system_program               |        |          | System Program                  |

**Arguments:**

```rust
struct ClaimDistributionArgs {
    action_id: u64,
    amount: u64,
    merkle_root: [u8; 32],
    leaf_index: u32,
    merkle_proof: Option<Vec<[u8; 32]>>,
}
```

---

### CloseActionReceiptAccount

Closes an action receipt account (for Split/Convert) and reclaims rent.

**Discriminator:** `22`

**Authorization:** Initial Mint Authority OR Verification Programs

**Accounts:**

| #   | Account         | Signer | Writable | Description                  |
| --- | --------------- | ------ | -------- | ---------------------------- |
| 0   | receipt_account |        | ✓        | Receipt PDA to close         |
| 1   | destination     |        | ✓        | Recipient for reclaimed rent |
| 2   | mint_account    |        |          | Mint account                 |

**Arguments:**

```rust
struct CloseActionReceiptArgs {
    action_id: u64,
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
| 0   | receipt_account        |        | ✓        | Receipt PDA to close         |
| 1   | destination            |        | ✓        | Recipient for reclaimed rent |
| 2   | mint_account           |        |          | Mint account                 |
| 3   | eligible_token_account |        |          | Token account from the claim |
| 4   | proof_account          |        |          | (Optional) Proof PDA         |

**Arguments:**

```rust
struct CloseClaimReceiptArgs {
    action_id: u64,
    merkle_proof: Option<Vec<[u8; 32]>>,
}
```

---

---

## Verification Program Interface

Verification programs must implement a specific interface to be compatible with the Security Token Program.

### Instruction Format

Verification programs receive instructions with the following data format:

```
[instruction_discriminator: u8, ...instruction_args]
```

The discriminator byte matches the Security Token instruction being verified, followed by the same arguments.

### Account Format

Verification programs receive the same accounts as the Security Token instruction (excluding verification overhead accounts).

### Expected Behavior

- **Success:** Return `Ok(())` to approve the operation
- **Failure:** Return an error to reject the operation

In CPI mode, any error from a verification program will cause the entire Security Token instruction to fail.

In introspection mode, the verification program must have been called successfully before the Security Token instruction.

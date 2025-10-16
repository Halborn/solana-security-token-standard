import {
  programNode,
  instructionNode,
  instructionAccountNode,
  instructionArgumentNode,
  definedTypeNode,
  structTypeNode,
  structFieldTypeNode,
  publicKeyTypeNode,
  stringTypeNode,
  bytesTypeNode,
  numberTypeNode,
  optionTypeNode,
  arrayTypeNode,
  errorNode,
  rootNode,
  definedTypeLinkNode,
  fixedCountNode,
  fieldDiscriminatorNode,
  numberValueNode,
  prefixedCountNode,
  booleanTypeNode,
} from '@codama/nodes';

import { renderVisitor as renderRustVisitor } from '@codama/renderers-rust';
import { visit } from '@codama/visitors-core';

const program = programNode({
  name: 'securityToken',
  publicKey: 'Gwbvvf4L2BWdboD1fT7Ax6JrgVCKv5CN6MqkwsEhjRdH',
  version: '0.1.0',
  definedTypes: [
    // VerificationConfig - Account type for storing verification configuration
    definedTypeNode({
      name: 'VerificationConfig',
      docs: [
        'Verification configuration for instructions stored as account data',
      ],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'accountDiscriminator',
          docs: ['Account type discriminator byte (must be set to 1).'],
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(1),
          defaultValueStrategy: 'omitted',
        }),
        structFieldTypeNode({
          name: 'instructionDiscriminator',
          docs: ['Instruction discriminator this config applies to'],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'verificationPrograms',
          docs: ['Required verification programs as raw bytes (32 bytes each)'],
          type: arrayTypeNode(
            publicKeyTypeNode(),
            prefixedCountNode(numberTypeNode('u32'))
          ),
        }),
      ]),
    }),

    definedTypeNode({
      name: 'MintAuthority',
      docs: ['Mint authority state stored in PDA account'],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'accountDiscriminator',
          docs: ['Account type discriminator byte (must be set to 0).'],
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(0),
          defaultValueStrategy: 'omitted',
        }),
        structFieldTypeNode({
          name: 'mint',
          docs: ['SPL mint address this configuration belongs to'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'mintCreator',
          docs: ['Original creator used to derive the mint authority PDA'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'bump',
          docs: ['Bump seed used for mint authority PDA derivation'],
          type: numberTypeNode('u8'),
        }),
      ]),
    }),

    // InitializeMintArgs
    definedTypeNode({
      name: 'InitializeMintArgs',
      docs: [
        'Arguments for initializing a mint, following SPL Token 2022 format',
      ],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'decimals',
          docs: ['Number of decimals for the token'],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'mintAuthority',
          docs: ['Mint authority public key'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'freezeAuthority',
          docs: ['Freeze authority public key'],
          type: publicKeyTypeNode(),
        }),
      ]),
    }),

    // MetadataPointer
    definedTypeNode({
      name: 'MetadataPointer',
      docs: [
        'Pointer to where metadata is stored, part of SPL Token 2022 extensions',
      ],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'authority',
          docs: ['Authority that can modify the metadata pointer'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'metadataAddress',
          docs: ['Address where the metadata is stored'],
          type: publicKeyTypeNode(),
        }),
      ]),
    }),

    // TokenMetadata
    definedTypeNode({
      name: 'TokenMetadata',
      docs: ['Token metadata structure compatible with SPL Token 2022'],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'updateAuthority',
          docs: ['Authority that can update the metadata'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'mint',
          docs: ['The mint this metadata belongs to'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'nameLen',
          docs: ['Length of the name field'],
          type: numberTypeNode('u32'),
        }),
        structFieldTypeNode({
          name: 'name',
          docs: ['Token name'],
          type: stringTypeNode('utf8'),
        }),
        structFieldTypeNode({
          name: 'symbolLen',
          docs: ['Length of the symbol field'],
          type: numberTypeNode('u32'),
        }),
        structFieldTypeNode({
          name: 'symbol',
          docs: ['Token symbol'],
          type: stringTypeNode('utf8'),
        }),
        structFieldTypeNode({
          name: 'uriLen',
          docs: ['Length of the URI field'],
          type: numberTypeNode('u32'),
        }),
        structFieldTypeNode({
          name: 'uri',
          docs: ['URI pointing to metadata JSON'],
          type: stringTypeNode('utf8'),
        }),
        structFieldTypeNode({
          name: 'additionalMetadataLen',
          docs: ['Length of additional metadata'],
          type: numberTypeNode('u32'),
        }),
        structFieldTypeNode({
          name: 'additionalMetadata',
          docs: ['Additional metadata as raw bytes'],
          type: bytesTypeNode(),
        }),
      ]),
    }),

    // ScaledUiAmountConfig
    definedTypeNode({
      name: 'ScaledUiAmountConfig',
      docs: [
        'Configuration for scaled UI amounts, part of SPL Token 2022 extensions',
      ],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'authority',
          docs: ['Authority that can modify the scaling configuration'],
          type: publicKeyTypeNode(),
        }),
        structFieldTypeNode({
          name: 'multiplier',
          docs: ['Current multiplier as 8-byte array (f64 in little-endian)'],
          type: arrayTypeNode(numberTypeNode('u8'), fixedCountNode(8)),
        }),
        structFieldTypeNode({
          name: 'newMultiplierEffectiveTimestamp',
          docs: ['Timestamp when new multiplier becomes effective'],
          type: numberTypeNode('i64'),
        }),
        structFieldTypeNode({
          name: 'newMultiplier',
          docs: ['New multiplier as 8-byte array (f64 in little-endian)'],
          type: arrayTypeNode(numberTypeNode('u8'), fixedCountNode(8)),
        }),
      ]),
    }),

    // InitializeArgs
    definedTypeNode({
      name: 'InitializeArgs',
      docs: [
        'Arguments for Initialize instruction that supports both mint and metadata',
      ],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'ixMint',
          docs: ['Basic mint arguments'],
          type: definedTypeLinkNode('InitializeMintArgs'),
        }),
        structFieldTypeNode({
          name: 'ixMetadataPointer',
          docs: ['Optional metadata pointer configuration'],
          type: optionTypeNode(definedTypeLinkNode('MetadataPointer')),
        }),
        structFieldTypeNode({
          name: 'ixMetadata',
          docs: ['Optional metadata'],
          type: optionTypeNode(definedTypeLinkNode('TokenMetadata')),
        }),
        structFieldTypeNode({
          name: 'ixScaledUiAmount',
          docs: ['Optional scaled UI amount configuration'],
          type: optionTypeNode(definedTypeLinkNode('ScaledUiAmountConfig')),
        }),
      ]),
    }),

    // UpdateMetadataArgs
    definedTypeNode({
      name: 'UpdateMetadataArgs',
      docs: ['Arguments for UpdateMetadata instruction'],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'metadata',
          docs: ['Metadata to update'],
          type: definedTypeLinkNode('TokenMetadata'),
        }),
      ]),
    }),

    // InitializeVerificationConfigArgs
    definedTypeNode({
      name: 'InitializeVerificationConfigArgs',
      type: structTypeNode([
        structFieldTypeNode({
          name: 'instructionDiscriminator',
          docs: [
            '1-byte discriminator for the instruction type (e.g., burn, transfer)',
          ],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'programAddresses',
          docs: ['Array of verification program addresses'],
          type: arrayTypeNode(
            publicKeyTypeNode(),
            prefixedCountNode(numberTypeNode('u32'))
          ),
        }),
      ]),
    }),

    // UpdateVerificationConfigArgs
    definedTypeNode({
      name: 'UpdateVerificationConfigArgs',
      type: structTypeNode([
        structFieldTypeNode({
          name: 'instructionDiscriminator',
          docs: [
            '1-byte discriminator for the instruction type (e.g., burn, transfer)',
          ],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'offset',
          docs: [
            'Offset at which to start replacement/insertion (0-based index)',
          ],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'programAddresses',
          docs: ['Array of new verification program addresses to add/replace'],
          type: arrayTypeNode(
            publicKeyTypeNode(),
            prefixedCountNode(numberTypeNode('u32'))
          ),
        }),
      ]),
    }),

    // TrimVerificationConfigArgs
    definedTypeNode({
      name: 'TrimVerificationConfigArgs',
      docs: ['Arguments for TrimVerificationConfig instruction'],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'instructionDiscriminator',
          docs: [
            '1-byte discriminator for the instruction type (e.g., burn, transfer)',
          ],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'size',
          docs: ['New size of the program array (number of Pubkeys to keep)'],
          type: numberTypeNode('u8'),
        }),
        structFieldTypeNode({
          name: 'close',
          docs: ['Whether to close the account completely'],
          type: booleanTypeNode(),
        }),
      ]),
    }),

    // VerifyArgs
    definedTypeNode({
      name: 'VerifyArgs',
      docs: ['Arguments for Verify instruction'],
      type: structTypeNode([
        structFieldTypeNode({
          name: 'ix',
          docs: ['The Security Token instruction discriminant to verify'],
          type: numberTypeNode('u8'),
        }),
      ]),
    }),
  ],

  instructions: [
    // InitializeMint (discriminant = 0)
    instructionNode({
      name: 'initializeMint',
      discriminators: [fieldDiscriminatorNode('discriminator', 0)],
      docs: [
        'Initialize a new security token mint with metadata and compliance features',
      ],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: [
            'The mint account (must be a signer when creating new account)',
          ],
          isSigner: true,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'payer',
          docs: ['The creator/payer account'],
          isSigner: true,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAuthorityAccount',
          docs: ['Mint authority PDA account owned by the program'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['The SPL Token 2022 program ID'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'systemProgram',
          docs: ['The system program ID'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'rent',
          docs: ['The rent sysvar'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(0),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'args',
          type: definedTypeLinkNode('InitializeArgs'),
        }),
      ],
    }),

    // UpdateMetadata (discriminant = 1)
    instructionNode({
      name: 'updateMetadata',
      discriminators: [fieldDiscriminatorNode('discriminator', 1)],
      docs: ['Update the metadata of an existing security token mint'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfigOrMintAuthority',
          docs: [
            'The VerificationConfig PDA or the MintAuthority PDA (position 1 - required for verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'sysvarOrCreator',
          docs: [
            'The Instructions sysvar or Creator signer(position 2 - required for Instruction Introspection)',
          ],
          isSigner: 'either',
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintForUpdate',
          docs: [
            'The mint account again (position 3 - required for update_metadata function)',
          ],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAuthority',
          docs: ['The mint authority account (position 4)'],
          isSigner: true,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['The SPL Token 2022 program ID'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'systemProgram',
          docs: ['The system program ID'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(1),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'args',
          type: definedTypeLinkNode('UpdateMetadataArgs'),
        }),
      ],
    }),

    // InitializeVerificationConfig (discriminant = 2)
    instructionNode({
      name: 'initializeVerificationConfig',
      discriminators: [fieldDiscriminatorNode('discriminator', 2)],
      docs: [
        'Initialize a verification configuration PDA for a specific instruction type',
      ],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfigOrMintAuthority',
          docs: [
            'The VerificationConfig PDA or the MintAuthority PDA (position 1 - required for verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'sysvarOrCreator',
          docs: [
            'The Instructions sysvar or Creator signer(position 2 - required for Instruction Introspection)',
          ],
          isSigner: 'either',
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'configAccount',
          docs: [
            'The VerificationConfig PDA (derived from instruction_id + mint)',
          ],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'payer',
          docs: ['The payer account for account creation'],
          isSigner: true,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAccount',
          docs: ['The mint account'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'systemProgram',
          docs: ['The system program ID'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(2),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'args',
          type: definedTypeLinkNode('InitializeVerificationConfigArgs'),
        }),
      ],
    }),

    // UpdateVerificationConfig (discriminant = 3)
    instructionNode({
      name: 'updateVerificationConfig',
      discriminators: [fieldDiscriminatorNode('discriminator', 3)],
      docs: ['Update verification configuration for an instruction'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfigOrMintAuthority',
          docs: [
            'The VerificationConfig PDA or the MintAuthority PDA (position 1 - required for verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'sysvarOrCreator',
          docs: [
            'The Instructions sysvar or Creator signer(position 2 - required for Instruction Introspection)',
          ],
          isSigner: 'either',
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'configAccount',
          docs: ['The VerificationConfig PDA account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAccount',
          docs: ['The mint account'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'payer',
          docs: ['The payer account covering rent increases'],
          isSigner: true,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'systemProgram',
          docs: ['The system program ID'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(3),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'args',
          type: definedTypeLinkNode('UpdateVerificationConfigArgs'),
        }),
      ],
    }),

    // TrimVerificationConfig (discriminant = 4)
    instructionNode({
      name: 'trimVerificationConfig',
      discriminators: [fieldDiscriminatorNode('discriminator', 4)],
      docs: ['Trim verification configuration to recover rent'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfigOrMintAuthority',
          docs: [
            'The VerificationConfig PDA or the MintAuthority PDA (position 1 - required for verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'sysvarOrCreator',
          docs: [
            'The Instructions sysvar or Creator signer(position 2 - required for Instruction Introspection)',
          ],
          isSigner: 'either',
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'configAccount',
          docs: ['The VerificationConfig PDA account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAccount',
          docs: ['The mint account'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'recipient',
          docs: ['The recipient account for recovered rent'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'systemProgram',
          docs: ['The system program ID (optional for closing account)'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(4),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'args',
          type: definedTypeLinkNode('TrimVerificationConfigArgs'),
        }),
      ],
    }),

    // Verify (discriminant = 5)
    instructionNode({
      name: 'verify',
      discriminators: [fieldDiscriminatorNode('discriminator', 5)],
      docs: [
        'Verify that a specific instruction type can be executed according to configured verification programs',
      ],
      accounts: [
        instructionAccountNode({
          name: 'mintAccount',
          docs: ['The mint account'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: ['The verification config PDA for this instruction type'],
          isSigner: false,
          isWritable: false,
          isOptional: true, // Optional since not all instructions may have verification config
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: ['The Solana Instructions sysvar account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(5),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'args',
          type: definedTypeLinkNode('VerifyArgs'),
        }),
      ],
    }),

    // Mint (discriminant = 6)
    instructionNode({
      name: 'mint',
      discriminators: [fieldDiscriminatorNode('discriminator', 6)],
      docs: [
        'Mint new tokens to a destination account after verification succeeds',
      ],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: [
            'The VerificationConfig PDA (position 1 - may not exist but position reserved)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: [
            'The Instructions sysvar (position 2 - required for Instruction Introspection)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'creator',
          docs: [
            'Original mint creator account that must sign and matches the mint authority PDA seeds',
          ],
          isSigner: true,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintInfo',
          docs: ['SPL Token mint account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAuthority',
          docs: [
            'Mint authority PDA account owned by the Security Token program',
          ],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'destinationAccount',
          docs: [
            'Destination token account that will receive the newly minted tokens',
          ],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['SPL Token 2022 program account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(6),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'amount',
          docs: ['Amount of tokens to mint'],
          type: numberTypeNode('u64'),
        }),
      ],
    }),

    // Burn (discriminant = 7)
    instructionNode({
      name: 'burn',
      discriminators: [fieldDiscriminatorNode('discriminator', 7)],
      docs: ['Burn tokens from a holder account after verification succeeds'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: [
            'The VerificationConfig PDA (position 1 - may not exist but position reserved)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: [
            'The Instructions sysvar (position 2 - required for Instruction Introspection)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintInfo',
          docs: ['SPL Token mint account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'permanentDelegate',
          docs: [
            'Permanent delegate PDA account derived for the mint (signs via program seeds)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'tokenAccount',
          docs: ['Token account holding the balance to be burned'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['SPL Token 2022 program account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(7),
          defaultValueStrategy: 'omitted',
        }),
        instructionArgumentNode({
          name: 'amount',
          docs: ['Amount of tokens to burn'],
          type: numberTypeNode('u64'),
        }),
      ],
    }),

    // Pause (discriminant = 8)
    instructionNode({
      name: 'pause',
      discriminators: [fieldDiscriminatorNode('discriminator', 8)],
      docs: ['Pause all token activity after verification succeeds'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: [
            'The VerificationConfig PDA (position 1 - required for pause verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: [
            'The Instructions sysvar (position 2 - required for Instruction Introspection)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintInfo',
          docs: ['SPL Token mint account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'pauseAuthority',
          docs: ['Pause authority PDA account derived for the mint'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['SPL Token 2022 program account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(8),
          defaultValueStrategy: 'omitted',
        }),
      ],
    }),

    // Resume (discriminant = 9)
    instructionNode({
      name: 'resume',
      discriminators: [fieldDiscriminatorNode('discriminator', 9)],
      docs: ['Resume token activity after verification succeeds'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: [
            'The VerificationConfig PDA (position 1 - required for resume verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: [
            'The Instructions sysvar (position 2 - required for Instruction Introspection)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintInfo',
          docs: ['SPL Token mint account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'pauseAuthority',
          docs: ['Pause authority PDA account derived for the mint'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['SPL Token 2022 program account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(9),
          defaultValueStrategy: 'omitted',
        }),
      ],
    }),

    // Freeze (discriminant = 10)
    instructionNode({
      name: 'freeze',
      discriminators: [fieldDiscriminatorNode('discriminator', 10)],
      docs: ['Freeze a token account after verification succeeds'],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: [
            'The VerificationConfig PDA (position 1 - required for freeze verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: [
            'The Instructions sysvar (position 2 - required for Instruction Introspection)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintInfo',
          docs: ['SPL Token mint account'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'freezeAuthority',
          docs: ['Freeze authority PDA account derived for the mint'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'tokenAccount',
          docs: ['Token account that will be frozen'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['SPL Token 2022 program account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(10),
          defaultValueStrategy: 'omitted',
        }),
      ],
    }),

    // Thaw (discriminant = 11)
    instructionNode({
      name: 'thaw',
      discriminators: [fieldDiscriminatorNode('discriminator', 11)],
      docs: [
        'Thaw a previously frozen token account after verification succeeds',
      ],
      accounts: [
        instructionAccountNode({
          name: 'mint',
          docs: ['The mint account (position 0 - required for verification)'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'verificationConfig',
          docs: [
            'The VerificationConfig PDA (position 1 - required for thaw verification)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'instructionsSysvar',
          docs: [
            'The Instructions sysvar (position 2 - required for Instruction Introspection)',
          ],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'mintInfo',
          docs: ['SPL Token mint account'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'freezeAuthority',
          docs: ['Freeze authority PDA account derived for the mint'],
          isSigner: false,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'tokenAccount',
          docs: ['Token account that will be thawed'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'tokenProgram',
          docs: ['SPL Token 2022 program account'],
          isSigner: false,
          isWritable: false,
        }),
      ],
      arguments: [
        instructionArgumentNode({
          name: 'discriminator',
          type: numberTypeNode('u8'),
          defaultValue: numberValueNode(11),
          defaultValueStrategy: 'omitted',
        }),
      ],
    }),
  ],
  errors: [
    errorNode({
      name: 'VerificationProgramNotFound',
      code: 1,
      message: 'Verification program not found',
    }),
    errorNode({
      name: 'NotEnoughAccountsForVerification',
      code: 2,
      message: 'Not enough accounts for verification',
    }),
    errorNode({
      name: 'AccountIntersectionMismatch',
      code: 3,
      message: 'Account intersection mismatch',
    }),
    errorNode({
      name: 'InvalidVerificationConfigPda',
      code: 4,
      message: 'Invalid verification config PDA',
    }),
  ],
});

const codama = rootNode(program);

const rustRenderer = renderRustVisitor('client/rust/src/generated', {
  crateFolder: '.',
});

visit(codama, rustRenderer);

console.log('Rust client generated successfully!');

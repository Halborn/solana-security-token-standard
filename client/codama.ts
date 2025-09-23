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
          docs: ['Optional freeze authority public key'],
          type: optionTypeNode(publicKeyTypeNode()),
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
          name: 'programAddresses',
          docs: ['Array of new verification program addresses to add/replace'],
          type: arrayTypeNode(
            publicKeyTypeNode(),
            prefixedCountNode(numberTypeNode('u32'))
          ),
        }),
        structFieldTypeNode({
          name: 'offset',
          docs: [
            'Offset at which to start replacement/insertion (0-based index)',
          ],
          type: numberTypeNode('u8'),
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
          docs: ['The mint account'],
          isSigner: false,
          isWritable: true,
        }),
        instructionAccountNode({
          name: 'mintAuthority',
          docs: ['The mint authority account'],
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
          name: 'authority',
          docs: [
            'The authority account (mint authority or designated config authority)',
          ],
          isSigner: true,
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
          name: 'authority',
          docs: ['The authority account (mint authority)'],
          isSigner: true,
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
          name: 'authority',
          docs: ['The authority account (mint authority)'],
          isSigner: true,
          isWritable: false,
        }),
        instructionAccountNode({
          name: 'rentRecipient',
          docs: ['The rent recipient account (to receive recovered lamports)'],
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
  ],
  errors: [
    errorNode({
      name: 'InvalidInstruction',
      code: 0,
      message: 'Invalid instruction',
    }),
    errorNode({ name: 'NotRentExempt', code: 1, message: 'Not rent exempt' }),
    errorNode({ name: 'ExpectedMint', code: 2, message: 'Expected mint' }),
    errorNode({
      name: 'ExpectedTokenAccount',
      code: 3,
      message: 'Expected token account',
    }),
    errorNode({
      name: 'ExpectedMintAuthority',
      code: 4,
      message: 'Expected mint authority',
    }),
    errorNode({
      name: 'InvalidMintAuthority',
      code: 5,
      message: 'Invalid mint authority',
    }),
    errorNode({
      name: 'InvalidTokenOwner',
      code: 6,
      message: 'Invalid token owner',
    }),
    errorNode({
      name: 'VerificationFailed',
      code: 7,
      message: 'Verification failed',
    }),
    errorNode({
      name: 'TransferRestricted',
      code: 8,
      message: 'Transfer restricted',
    }),
    errorNode({ name: 'AccountFrozen', code: 9, message: 'Account frozen' }),
    errorNode({ name: 'TokenPaused', code: 10, message: 'Token paused' }),
    errorNode({
      name: 'InsufficientCompliance',
      code: 11,
      message: 'Insufficient compliance',
    }),
    errorNode({
      name: 'InvalidVerificationConfig',
      code: 12,
      message: 'Invalid verification config',
    }),
    errorNode({
      name: 'MissingVerificationSignature',
      code: 13,
      message: 'Missing verification signature',
    }),
    errorNode({
      name: 'CorporateActionNotFound',
      code: 14,
      message: 'Corporate action not found',
    }),
    errorNode({
      name: 'InvalidRateConfiguration',
      code: 15,
      message: 'Invalid rate configuration',
    }),
    errorNode({
      name: 'ReceiptAlreadyExists',
      code: 16,
      message: 'Receipt already exists',
    }),
    errorNode({
      name: 'InvalidMerkleProof',
      code: 17,
      message: 'Invalid merkle proof',
    }),
    errorNode({
      name: 'DistributionAlreadyClaimed',
      code: 18,
      message: 'Distribution already claimed',
    }),
    errorNode({
      name: 'InsufficientBalance',
      code: 19,
      message: 'Insufficient balance',
    }),
    errorNode({ name: 'MathOverflow', code: 20, message: 'Math overflow' }),
    errorNode({
      name: 'InvalidAccountData',
      code: 21,
      message: 'Invalid account data',
    }),
    errorNode({
      name: 'AccountNotInitialized',
      code: 22,
      message: 'Account not initialized',
    }),
    errorNode({
      name: 'AccountAlreadyInitialized',
      code: 23,
      message: 'Account already initialized',
    }),
  ],
});

const codama = rootNode(program);

const rustRenderer = renderRustVisitor('client/rust/src/generated', {
  crateFolder: '.',
});

visit(codama, rustRenderer);

console.log('Rust client generated successfully!');

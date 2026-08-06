import {
  AccountRole,
  address,
  getAddressDecoder,
  getAddressEncoder,
  getProgramDerivedAddress,
  type AccountMeta,
  type Address,
} from '@solana/kit';
import { describe, expect, it, vi } from 'vitest';
import {
  MAX_V0_TRANSACTION_SIZE,
  appendVerificationAccounts,
  buildIntrospectionInstructions,
  decodeVerificationConfigData,
  fetchAndResolveVerificationAccounts,
  getVerificationConfigEncoder,
  resolveVerificationAccounts,
  validateV0TransactionSize,
  type VerificationConfig,
  type VerificationInstruction,
  type VerificationResolutionAccount,
} from '../dist';

const PROGRAM = address('11111111111111111111111111111111');
const FIXED = address('SysvarRent111111111111111111111111111111111');
const CANONICAL = address('SysvarC1ock11111111111111111111111111111111');

function addressConfig(value: Address): Uint8Array {
  return Uint8Array.from(getAddressEncoder().encode(value));
}

function paddedConfig(bytes: readonly number[]): Uint8Array {
  const config = new Uint8Array(32);
  config.set(bytes);
  return config;
}

function configWith(
  extraAccounts: VerificationConfig['programs'][number]['extraAccounts'],
  cpiMode = false
): VerificationConfig {
  return {
    discriminator: 1,
    instructionDiscriminator: 12,
    cpiMode,
    bump: 1,
    programs: [{ programId: PROGRAM, extraAccounts }],
  };
}

describe('verification config decoding', () => {
  it('strictly decodes the shared nested wire shape', () => {
    const programBytes = new Uint8Array(32).fill(7);
    const fixedBytes = new Uint8Array(32).fill(9);
    const config: VerificationConfig = {
      discriminator: 1,
      instructionDiscriminator: 12,
      cpiMode: false,
      bump: 1,
      programs: [
        {
          programId: getAddressDecoder().decode(programBytes),
          extraAccounts: [
            {
              discriminator: 0,
              addressConfig: fixedBytes,
              isSigner: false,
              isWritable: true,
            },
          ],
        },
      ],
    };
    const expected = Uint8Array.from([
      1,
      12,
      0,
      1,
      1,
      0,
      0,
      0,
      ...programBytes,
      1,
      0,
      0,
      0,
      0,
      ...fixedBytes,
      0,
      1,
    ]);

    expect(getVerificationConfigEncoder().encode(config)).toEqual(expected);
    expect(decodeVerificationConfigData(expected)).toEqual(config);
    expect(() =>
      decodeVerificationConfigData(Uint8Array.from([...expected, 0]))
    ).toThrow('Trailing verification config data');
  });

  it('uses the strict decoder when fetching an account', async () => {
    const configAddress = address(
      'SysvarRent111111111111111111111111111111111'
    );
    const encoded = Uint8Array.from([
      ...getVerificationConfigEncoder().encode(configWith([])),
      0,
    ]);
    const send = vi.fn(async () => ({
      context: { slot: 0n },
      value: {
        data: [Buffer.from(encoded).toString('base64'), 'base64'] as const,
        executable: false,
        lamports: 0n,
        owner: PROGRAM,
        space: BigInt(encoded.length),
      },
    }));
    const rpc = {
      getAccountInfo: vi.fn((requestedAddress: Address) => {
        expect(requestedAddress).toBe(configAddress);
        return { send };
      }),
    } as unknown as Parameters<typeof fetchAndResolveVerificationAccounts>[0];

    await expect(
      fetchAndResolveVerificationAccounts(
        rpc,
        configAddress,
        [],
        new Uint8Array([12]),
        async () => undefined
      )
    ).rejects.toThrow('Trailing verification config data');
    expect(send).toHaveBeenCalledOnce();
  });
});

describe('verification account resolution', () => {
  it('resolves fixed, all PDA seed kinds, chained accounts, and external pubkeys', async () => {
    const canonicalData = new Uint8Array(40);
    canonicalData.set(addressConfig(FIXED), 4);
    const instructionData = new Uint8Array(40);
    instructionData.set([12, 21, 22], 0);
    instructionData.set(addressConfig(CANONICAL), 5);
    const pdaConfig = paddedConfig([
      1,
      2,
      7,
      8,
      2,
      1,
      2,
      3,
      0,
      4,
      0,
      4,
      2,
      0,
    ]);
    const chainedPdaConfig = paddedConfig([3, 1, 0]);
    const declarations: VerificationConfig['programs'][number]['extraAccounts'] = [
      {
        discriminator: 0,
        addressConfig: addressConfig(FIXED),
        isSigner: false,
        isWritable: false,
      },
      {
        discriminator: 1,
        addressConfig: pdaConfig,
        isSigner: false,
        isWritable: true,
      },
      {
        discriminator: 1,
        addressConfig: chainedPdaConfig,
        isSigner: true,
        isWritable: false,
      },
      {
        discriminator: 2,
        addressConfig: paddedConfig([1, 5]),
        isSigner: true,
        isWritable: true,
      },
      {
        discriminator: 2,
        addressConfig: paddedConfig([2, 0, 4]),
        isSigner: false,
        isWritable: false,
      },
    ];
    const canonical: VerificationResolutionAccount[] = [
      {
        meta: { address: CANONICAL, role: AccountRole.READONLY },
        data: canonicalData,
      },
    ];
    const fetched = vi.fn(async () => new Uint8Array([31, 32]));

    const [group] = await resolveVerificationAccounts(
      configWith(declarations),
      canonical,
      instructionData,
      fetched
    );
    const expectedPda = (
      await getProgramDerivedAddress({
        programAddress: PROGRAM,
        seeds: [
          Uint8Array.from([7, 8]),
          Uint8Array.from([21, 22]),
          addressConfig(CANONICAL),
          canonicalData.slice(4, 6),
        ],
      })
    )[0];
    const chainedPda = (
      await getProgramDerivedAddress({
        programAddress: PROGRAM,
        seeds: [addressConfig(FIXED)],
      })
    )[0];

    expect(group.extraAccounts).toEqual([
      { address: FIXED, role: AccountRole.READONLY },
      { address: expectedPda, role: AccountRole.WRITABLE },
      { address: chainedPda, role: AccountRole.READONLY_SIGNER },
      { address: CANONICAL, role: AccountRole.WRITABLE_SIGNER },
      { address: FIXED, role: AccountRole.READONLY },
    ]);
    expect(fetched).toHaveBeenCalledTimes(5);
  });

  it('preserves program group order', async () => {
    const secondProgram = address(
      'SysvarRecentB1ockHashes11111111111111111111'
    );
    const config: VerificationConfig = {
      ...configWith([]),
      programs: [
        { programId: PROGRAM, extraAccounts: [] },
        { programId: secondProgram, extraAccounts: [] },
      ],
    };

    const groups = await resolveVerificationAccounts(
      config,
      [],
      new Uint8Array([12]),
      async () => undefined
    );

    expect(groups.map((group) => group.programId)).toEqual([
      PROGRAM,
      secondProgram,
    ]);
  });

  it.each([
    ['missing account index', paddedConfig([3, 2, 0]), 'account not found'],
    ['missing account data', paddedConfig([4, 0, 0, 1, 0]), 'data not found'],
    ['invalid PDA seed', paddedConfig([9]), 'Invalid verification PDA seed'],
    ['short instruction slice', paddedConfig([2, 9, 2, 0]), 'data is too short'],
  ])('rejects %s', async (_name, addressConfigBytes, message) => {
    const canonical: VerificationResolutionAccount[] = [
      { meta: { address: CANONICAL, role: AccountRole.READONLY } },
    ];
    await expect(
      resolveVerificationAccounts(
        configWith([
          {
            discriminator: 1,
            addressConfig: addressConfigBytes,
            isSigner: false,
            isWritable: false,
          },
        ]),
        canonical,
        new Uint8Array([12]),
        async () => undefined
      )
    ).rejects.toThrow(message);
  });

  it.each([
    [paddedConfig([2, 0, 0]), 'data not found'],
    [paddedConfig([7]), 'Invalid verification account meta'],
  ])('rejects invalid external pubkey metadata', async (addressConfigBytes, message) => {
    await expect(
      resolveVerificationAccounts(
        configWith([
          {
            discriminator: 2,
            addressConfig: addressConfigBytes,
            isSigner: false,
            isWritable: false,
          },
        ]),
        [{ meta: { address: CANONICAL, role: AccountRole.READONLY } }],
        new Uint8Array([12]),
        async () => undefined
      )
    ).rejects.toThrow(message);
  });

  it('rejects an unknown account-meta discriminator', async () => {
    await expect(
      resolveVerificationAccounts(
        configWith([
          {
            discriminator: 99,
            addressConfig: new Uint8Array(32),
            isSigner: false,
            isWritable: false,
          },
        ]),
        [],
        new Uint8Array([12]),
        async () => undefined
      )
    ).rejects.toThrow('Invalid verification account meta');
  });
});

describe('instruction assembly and transaction bounds', () => {
  it('appends CPI routing without mutating the input instruction or groups', () => {
    const originalAccounts: AccountMeta[] = [
      { address: CANONICAL, role: AccountRole.READONLY },
    ];
    const instruction: VerificationInstruction = {
      programAddress: PROGRAM,
      accounts: originalAccounts,
      data: new Uint8Array([12]),
    };
    const groups = [
      {
        programId: PROGRAM,
        extraAccounts: [
          { address: FIXED, role: AccountRole.WRITABLE } as AccountMeta,
        ],
      },
    ];

    const appended = appendVerificationAccounts(instruction, groups);

    expect(appended.accounts).toEqual([
      ...originalAccounts,
      { address: PROGRAM, role: AccountRole.READONLY },
      { address: FIXED, role: AccountRole.WRITABLE },
    ]);
    expect(instruction.accounts).toBe(originalAccounts);
    expect(instruction.accounts).toHaveLength(1);
    expect(groups[0].extraAccounts).toHaveLength(1);
  });

  it('builds introspection instructions without mutating inputs', () => {
    const canonical: AccountMeta[] = [
      { address: CANONICAL, role: AccountRole.READONLY },
    ];
    const data = new Uint8Array([12, 1]);
    const groups = [
      {
        programId: PROGRAM,
        extraAccounts: [
          { address: FIXED, role: AccountRole.READONLY } as AccountMeta,
        ],
      },
    ];

    const instructions = buildIntrospectionInstructions(canonical, data, groups);

    expect(instructions).toEqual([
      {
        programAddress: PROGRAM,
        accounts: [...canonical, ...groups[0].extraAccounts],
        data,
      },
    ]);
    expect(instructions[0].accounts).not.toBe(canonical);
    expect(canonical).toHaveLength(1);
    expect(groups[0].extraAccounts).toHaveLength(1);
  });

  it('accepts the V0 packet limit and rejects one byte over it', () => {
    expect(() =>
      validateV0TransactionSize(new Uint8Array(MAX_V0_TRANSACTION_SIZE))
    ).not.toThrow();
    expect(() =>
      validateV0TransactionSize(new Uint8Array(MAX_V0_TRANSACTION_SIZE + 1))
    ).toThrow(`V0 transaction exceeds ${MAX_V0_TRANSACTION_SIZE} bytes`);
  });
});

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  AccountRole,
  address,
  getAddressDecoder,
  getAddressEncoder,
  getProgramDerivedAddress,
} = require('@solana/kit');
const {
  MAX_V0_TRANSACTION_SIZE,
  appendVerificationAccounts,
  decodeVerificationConfigData,
  fetchAndResolveVerificationAccounts,
  getVerificationConfigEncoder,
  resolveVerificationAccounts,
  validateV0TransactionSize,
} = require('../dist');

test('nested config matches the shared wire fixture', () => {
  const programBytes = new Uint8Array(32).fill(7);
  const fixedBytes = new Uint8Array(32).fill(9);
  const config = {
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
    1, 12, 0, 1,
    1, 0, 0, 0,
    ...programBytes,
    1, 0, 0, 0,
    0,
    ...fixedBytes,
    0, 1,
  ]);
  assert.deepEqual(getVerificationConfigEncoder().encode(config), expected);
  assert.deepEqual(decodeVerificationConfigData(expected), config);
  assert.throws(() =>
    decodeVerificationConfigData(Uint8Array.from([...expected, 0]))
  );
});

test('high-level fetch rejects trailing config data', async () => {
  const configAddress = address('SysvarRent111111111111111111111111111111111');
  const programAddress = address('11111111111111111111111111111111');
  const config = {
    discriminator: 1,
    instructionDiscriminator: 12,
    cpiMode: false,
    bump: 1,
    programs: [],
  };
  const encoded = Uint8Array.from([
    ...getVerificationConfigEncoder().encode(config),
    0,
  ]);
  const rpc = {
    getAccountInfo(requestedAddress) {
      assert.equal(requestedAddress, configAddress);
      return {
        async send() {
          return {
            context: { slot: 0n },
            value: {
              data: [Buffer.from(encoded).toString('base64'), 'base64'],
              executable: false,
              lamports: 0n,
              owner: programAddress,
              space: BigInt(encoded.length),
            },
          };
        },
      };
    },
  };

  await assert.rejects(() =>
    fetchAndResolveVerificationAccounts(
      rpc,
      configAddress,
      [],
      new Uint8Array([12]),
      async () => undefined
    )
  );
});

test('nested config fixture and sequential routing match', async () => {
  const programId = address('11111111111111111111111111111111');
  const fixed = address('SysvarRent111111111111111111111111111111111');
  const fixedBytes = getAddressEncoder().encode(fixed);
  const previousExtraSeed = new Uint8Array(32);
  previousExtraSeed.set([3, 1]);
  const config = {
    discriminator: 1,
    instructionDiscriminator: 12,
    cpiMode: false,
    bump: 1,
    programs: [
      {
        programId,
        extraAccounts: [
          {
            discriminator: 0,
            addressConfig: fixedBytes,
            isSigner: false,
            isWritable: false,
          },
          {
            discriminator: 1,
            addressConfig: previousExtraSeed,
            isSigner: false,
            isWritable: true,
          },
        ],
      },
    ],
  };
  const encoded = getVerificationConfigEncoder().encode(config);
  assert.deepEqual(decodeVerificationConfigData(encoded), config);

  const canonical = [
    {
      meta: { address: address('SysvarC1ock11111111111111111111111111111111'), role: AccountRole.READONLY },
    },
  ];
  const groups = await resolveVerificationAccounts(
    config,
    canonical,
    new Uint8Array([12]),
    async () => undefined
  );
  const expectedPda = (
    await getProgramDerivedAddress({ programAddress: programId, seeds: [fixedBytes] })
  )[0];
  assert.equal(groups[0].extraAccounts[0].address, fixed);
  assert.equal(groups[0].extraAccounts[1].address, expectedPda);
  assert.equal(groups[0].extraAccounts[1].role, AccountRole.WRITABLE);

  const instruction = {
    programAddress: programId,
    accounts: [],
    data: new Uint8Array([12]),
  };
  const appended = appendVerificationAccounts(instruction, groups);
  assert.equal(instruction.accounts.length, 0);
  assert.equal(appended.accounts.length, 3);
});

test('V0 size validation uses the packet limit', () => {
  validateV0TransactionSize(new Uint8Array(MAX_V0_TRANSACTION_SIZE));
  assert.throws(() =>
    validateV0TransactionSize(new Uint8Array(MAX_V0_TRANSACTION_SIZE + 1))
  );
});

import {
  AccountRole,
  assertAccountExists,
  fetchEncodedAccount,
  getAddressDecoder,
  getAddressEncoder,
  getProgramDerivedAddress,
  type AccountMeta,
  type Address,
  type Instruction,
  type InstructionWithAccounts,
  type InstructionWithData,
  type ReadonlyUint8Array,
} from '@solana/kit';
import {
  getVerificationConfigDecoder,
  type VerificationAccountMeta,
  type VerificationConfig,
} from './generated';

export const MAX_V0_TRANSACTION_SIZE = 1232;

export type VerificationResolutionAccount = {
  meta: AccountMeta;
  data?: ReadonlyUint8Array;
};

export type VerificationRoutingGroup = {
  programId: Address;
  extraAccounts: AccountMeta[];
};

export type VerificationInstruction = Instruction &
  InstructionWithAccounts<readonly AccountMeta[]> &
  InstructionWithData<ReadonlyUint8Array>;

export function decodeVerificationConfigData(
  data: ReadonlyUint8Array
): VerificationConfig {
  const [config, offset] = getVerificationConfigDecoder().read(data, 0);
  if (offset !== data.length) throw new Error('Trailing verification config data');
  return config;
}

export async function fetchAndResolveVerificationAccounts(
  rpc: Parameters<typeof fetchEncodedAccount>[0],
  configAddress: Address,
  canonicalAccounts: readonly VerificationResolutionAccount[],
  instructionData: ReadonlyUint8Array,
  fetchAccountData: (
    address: Address
  ) => Promise<ReadonlyUint8Array | undefined>
): Promise<{
  config: VerificationConfig;
  groups: VerificationRoutingGroup[];
}> {
  const account = await fetchEncodedAccount(rpc, configAddress);
  assertAccountExists(account);
  const config = decodeVerificationConfigData(account.data);
  const groups = await resolveVerificationAccounts(
    config,
    canonicalAccounts,
    instructionData,
    fetchAccountData
  );
  return { config, groups };
}

export async function resolveVerificationAccounts(
  config: VerificationConfig,
  canonicalAccounts: readonly VerificationResolutionAccount[],
  instructionData: ReadonlyUint8Array,
  fetchAccountData: (
    address: Address
  ) => Promise<ReadonlyUint8Array | undefined>
): Promise<VerificationRoutingGroup[]> {
  const groups: VerificationRoutingGroup[] = [];
  for (const program of config.programs) {
    const localAccounts = [...canonicalAccounts];
    const extraAccounts: AccountMeta[] = [];
    for (const declaration of program.extraAccounts) {
      const address = await resolveVerificationAccount(
        declaration,
        program.programId,
        localAccounts,
        instructionData
      );
      const meta = { address, role: accountRole(declaration) };
      localAccounts.push({ meta, data: await fetchAccountData(address) });
      extraAccounts.push(meta);
    }
    groups.push({ programId: program.programId, extraAccounts });
  }
  return groups;
}

export function appendVerificationAccounts(
  instruction: VerificationInstruction,
  groups: readonly VerificationRoutingGroup[]
): VerificationInstruction {
  const routingAccounts = groups.flatMap((group) => [
    { address: group.programId, role: AccountRole.READONLY },
    ...group.extraAccounts,
  ]);
  return { ...instruction, accounts: [...instruction.accounts, ...routingAccounts] };
}

export function buildIntrospectionInstructions(
  canonicalAccounts: readonly AccountMeta[],
  instructionData: ReadonlyUint8Array,
  groups: readonly VerificationRoutingGroup[]
): VerificationInstruction[] {
  return groups.map((group) => ({
    programAddress: group.programId,
    accounts: [...canonicalAccounts, ...group.extraAccounts],
    data: instructionData,
  }));
}

export function validateV0TransactionSize(
  serializedTransaction: ReadonlyUint8Array
): void {
  if (serializedTransaction.length > MAX_V0_TRANSACTION_SIZE) {
    throw new Error(
      `V0 transaction exceeds ${MAX_V0_TRANSACTION_SIZE} bytes`
    );
  }
}

async function resolveVerificationAccount(
  declaration: VerificationAccountMeta,
  programId: Address,
  accounts: readonly VerificationResolutionAccount[],
  instructionData: ReadonlyUint8Array
): Promise<Address> {
  if (declaration.discriminator === 0) {
    return getAddressDecoder().decode(declaration.addressConfig);
  }
  if (declaration.discriminator === 1) {
    const seeds = unpackSeeds(declaration.addressConfig).map((seed) => {
      if (seed.kind === 'literal') return seed.bytes;
      if (seed.kind === 'instructionData') {
        return checkedSlice(instructionData, seed.index, seed.length);
      }
      const account = accounts[seed.accountIndex];
      if (!account) throw new Error('Verification resolution account not found');
      if (seed.kind === 'accountKey') {
        return getAddressEncoder().encode(account.meta.address);
      }
      if (!account.data) throw new Error('Verification account data not found');
      return checkedSlice(account.data, seed.dataIndex, seed.length);
    });
    return (await getProgramDerivedAddress({ programAddress: programId, seeds }))[0];
  }
  if (declaration.discriminator === 2) {
    const kind = declaration.addressConfig[0];
    if (kind === 1) {
      return getAddressDecoder().decode(
        checkedSlice(instructionData, declaration.addressConfig[1], 32)
      );
    }
    if (kind === 2) {
      const account = accounts[declaration.addressConfig[1]];
      if (!account?.data) throw new Error('Verification account data not found');
      return getAddressDecoder().decode(
        checkedSlice(account.data, declaration.addressConfig[2], 32)
      );
    }
  }
  throw new Error('Invalid verification account meta');
}

type ResolutionSeed =
  | { kind: 'literal'; bytes: Uint8Array }
  | { kind: 'instructionData'; index: number; length: number }
  | { kind: 'accountKey'; accountIndex: number }
  | {
      kind: 'accountData';
      accountIndex: number;
      dataIndex: number;
      length: number;
    };

function unpackSeeds(config: ReadonlyUint8Array): ResolutionSeed[] {
  const seeds: ResolutionSeed[] = [];
  let offset = 0;
  while (offset < config.length && config[offset] !== 0) {
    const kind = config[offset++];
    if (kind === 1) {
      const length = config[offset++];
      seeds.push({ kind: 'literal', bytes: checkedSlice(config, offset, length) });
      offset += length;
    } else if (kind === 2) {
      seeds.push({
        kind: 'instructionData',
        index: requiredByte(config, offset++),
        length: requiredByte(config, offset++),
      });
    } else if (kind === 3) {
      seeds.push({ kind: 'accountKey', accountIndex: requiredByte(config, offset++) });
    } else if (kind === 4) {
      seeds.push({
        kind: 'accountData',
        accountIndex: requiredByte(config, offset++),
        dataIndex: requiredByte(config, offset++),
        length: requiredByte(config, offset++),
      });
    } else {
      throw new Error('Invalid verification PDA seed');
    }
  }
  return seeds;
}

function accountRole(meta: VerificationAccountMeta): AccountRole {
  if (meta.isSigner) {
    return meta.isWritable
      ? AccountRole.WRITABLE_SIGNER
      : AccountRole.READONLY_SIGNER;
  }
  return meta.isWritable ? AccountRole.WRITABLE : AccountRole.READONLY;
}

function checkedSlice(
  bytes: ReadonlyUint8Array,
  start: number,
  length: number
): Uint8Array {
  const end = start + length;
  if (!Number.isSafeInteger(end) || end > bytes.length) {
    throw new Error('Verification resolution data is too short');
  }
  return Uint8Array.from(bytes.slice(start, end));
}

function requiredByte(bytes: ReadonlyUint8Array, index: number): number {
  const value = bytes[index];
  if (value === undefined) throw new Error('Invalid verification account meta');
  return value;
}

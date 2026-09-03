import { fileURLToPath } from 'node:url';
import {
  AccountRole,
  address,
  createClient,
  extendClient,
  generateKeyPairSigner,
  getAddressEncoder,
  getProgramDerivedAddress,
  getUtf8Encoder,
  lamports,
  type AccountMeta,
  type Address,
  type Instruction,
  type ReadonlyUint8Array,
  type TransactionSigner,
} from '@solana/kit';
import {
  findAssociatedTokenPda,
  getCreateAssociatedTokenInstructionAsync,
  TOKEN_2022_PROGRAM_ADDRESS,
} from '@solana-program/token-2022';
import { litesvm } from '@solana/kit-plugin-litesvm';
import {
  appendVerificationAccounts,
  buildIntrospectionInstructions,
  fetchAndResolveVerificationAccounts,
  getInitializeMintInstruction,
  getInitializeVerificationConfigInstruction,
  type InitializeMintArgsArgs,
  type VerificationInstruction,
  type VerificationProgramConfigArgs,
} from '../../dist';

export const SECURITY_TOKEN_PROGRAM_ADDRESS = address(
  'SSTS8Qk2bW3aVaBEsY1Ras95YdbaaYQQx21JWHxvjap'
);
export const TRANSFER_HOOK_PROGRAM_ADDRESS = address(
  'HookXqLKgPaNrHBJ9Jui7oQZz93vMbtA88JjsLa8bmfL'
);
export const MEMO_PROGRAM_ADDRESS = address(
  'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo'
);

const utf8 = getUtf8Encoder();
const addresses = getAddressEncoder();
const mainProgramPath = fileURLToPath(
  new URL('../../../../target/deploy/security_token_program.so', import.meta.url)
);
const transferHookPath = fileURLToPath(
  new URL(
    '../../../../target/deploy/security_token_transfer_hook.so',
    import.meta.url
  )
);

export async function createE2eContext() {
  const payer = await generateKeyPairSigner();
  const client = createClient()
    .use((base) => extendClient(base, { payer }))
    .use(litesvm({ transactionConfig: { version: 'legacy' } }));

  client.svm.addProgramFromFile(SECURITY_TOKEN_PROGRAM_ADDRESS, mainProgramPath);
  client.svm.addProgramFromFile(TRANSFER_HOOK_PROGRAM_ADDRESS, transferHookPath);
  await client.airdrop(payer.address, lamports(10_000_000_000n));

  const memoAccount = client.svm.getAccount(MEMO_PROGRAM_ADDRESS);
  if (!memoAccount.exists || !memoAccount.executable) {
    throw new Error('LiteSVM Memo v1 program is missing or not executable');
  }

  return { client, payer };
}

export type E2eContext = Awaited<ReturnType<typeof createE2eContext>>;

export async function sendInstructions(
  context: E2eContext,
  instructions: readonly Instruction[]
): Promise<void> {
  try {
    await context.client.sendTransaction(instructions);
  } catch (error) {
    console.error('LiteSVM transaction failed', error);
    throw error;
  }
}

export async function findSecurityTokenPda(
  seeds: readonly ReadonlyUint8Array[]
): Promise<Address> {
  return (
    await getProgramDerivedAddress({
      programAddress: SECURITY_TOKEN_PROGRAM_ADDRESS,
      seeds: [...seeds],
    })
  )[0];
}

export async function findMintAuthorityPda(
  mint: Address,
  creator: Address
): Promise<Address> {
  return findSecurityTokenPda([
    utf8.encode('mint.authority'),
    addresses.encode(mint),
    addresses.encode(creator),
  ]);
}

export async function findFreezeAuthorityPda(mint: Address): Promise<Address> {
  return findSecurityTokenPda([
    utf8.encode('mint.freeze_authority'),
    addresses.encode(mint),
  ]);
}

export async function findPermanentDelegatePda(
  mint: Address
): Promise<Address> {
  return findSecurityTokenPda([
    utf8.encode('mint.permanent_delegate'),
    addresses.encode(mint),
  ]);
}

export async function findPauseAuthorityPda(mint: Address): Promise<Address> {
  return findSecurityTokenPda([
    utf8.encode('mint.pause_authority'),
    addresses.encode(mint),
  ]);
}

export async function findTransferHookAuthorityPda(
  mint: Address
): Promise<Address> {
  return findSecurityTokenPda([
    utf8.encode('mint.transfer_hook'),
    addresses.encode(mint),
  ]);
}

export async function findVerificationConfigPda(
  mint: Address,
  discriminator: number
): Promise<Address> {
  return findSecurityTokenPda([
    utf8.encode('verification_config'),
    addresses.encode(mint),
    Uint8Array.of(discriminator),
  ]);
}

export async function findExtraAccountMetasPda(
  mint: Address
): Promise<Address> {
  return (
    await getProgramDerivedAddress({
      programAddress: TRANSFER_HOOK_PROGRAM_ADDRESS,
      seeds: [utf8.encode('extra-account-metas'), addresses.encode(mint)],
    })
  )[0];
}

export async function initializeMint(
  context: E2eContext,
  args?: Partial<InitializeMintArgsArgs>
): Promise<{
  mint: TransactionSigner;
  mintAuthority: Address;
  freezeAuthority: Address;
  permanentDelegate: Address;
  pauseAuthority: Address;
  transferHookAuthority: Address;
}> {
  const mint = await generateKeyPairSigner();
  const [mintAuthority, freezeAuthority, permanentDelegate, pauseAuthority, transferHookAuthority] =
    await Promise.all([
      findMintAuthorityPda(mint.address, context.payer.address),
      findFreezeAuthorityPda(mint.address),
      findPermanentDelegatePda(mint.address),
      findPauseAuthorityPda(mint.address),
      findTransferHookAuthorityPda(mint.address),
    ]);
  const initializeMintArgs: InitializeMintArgsArgs = {
    ixMint: {
      decimals: 2,
      mintAuthority: context.payer.address,
      freezeAuthority,
    },
    ixMetadataPointer: args?.ixMetadata
      ? {
          authority: context.payer.address,
          metadataAddress: mint.address,
        }
      : null,
    ixMetadata: null,
    ixScaledUiAmount: null,
    ixDefaultAccountState: null,
    ...args,
  };

  await sendInstructions(context, [
    getInitializeMintInstruction({
      mint,
      authority: mintAuthority,
      payer: context.payer,
      initializeMintArgs,
    }),
  ]);

  return {
    mint,
    mintAuthority,
    freezeAuthority,
    permanentDelegate,
    pauseAuthority,
    transferHookAuthority,
  };
}

export async function createAssociatedTokenAccount(
  context: E2eContext,
  mint: Address,
  owner: Address
): Promise<Address> {
  const [token] = await findAssociatedTokenPda({
    owner,
    mint,
    tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
  });
  await sendInstructions(context, [
    await getCreateAssociatedTokenInstructionAsync({
      payer: context.payer,
      ata: token,
      owner,
      mint,
      tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
    }),
  ]);
  return token;
}

export async function initializeVerificationConfig(
  context: E2eContext,
  mint: Address,
  mintAuthority: Address,
  discriminator: number,
  cpiMode: boolean,
  programs: VerificationProgramConfigArgs[] = [
    { programId: MEMO_PROGRAM_ADDRESS, extraAccounts: [] },
  ]
): Promise<Address> {
  const [configAccount, accountMetasPda, transferHookPda] = await Promise.all([
    findVerificationConfigPda(mint, discriminator),
    findExtraAccountMetasPda(mint),
    findTransferHookAuthorityPda(mint),
  ]);

  await sendInstructions(context, [
    getInitializeVerificationConfigInstruction({
      mint,
      verificationConfigOrMintAuthority: mintAuthority,
      instructionsSysvarOrCreator: context.payer.address,
      payer: context.payer,
      mintAccount: mint,
      configAccount,
      accountMetasPda,
      transferHookPda,
      transferHookProgram: TRANSFER_HOOK_PROGRAM_ADDRESS,
      initializeVerificationConfigArgs: {
        instructionDiscriminator: discriminator,
        cpiMode,
        programs,
      },
    }),
  ]);

  return configAccount;
}

export function canonicalVerificationAccounts(
  instruction: VerificationInstruction
): AccountMeta[] {
  if (instruction.data[0] === 12 && instruction.accounts.length >= 7) {
    return [5, 4, 6, 3].map((index) => instruction.accounts[index]!);
  }
  return instruction.accounts.slice(3);
}

export async function routeVerification(
  context: E2eContext,
  instruction: VerificationInstruction,
  configAddress: Address
): Promise<{
  instruction: VerificationInstruction;
  priorInstructions: VerificationInstruction[];
}> {
  const canonical = canonicalVerificationAccounts(instruction);
  const { config, groups } = await fetchAndResolveVerificationAccounts(
    context.client.rpc,
    configAddress,
    canonical.map((meta) => ({ meta })),
    instruction.data,
    async (accountAddress) => {
      const account = context.client.svm.getAccount(accountAddress);
      return account.exists ? account.data : undefined;
    }
  );
  const routed = appendVerificationAccounts(instruction, groups);
  const priorInstructions = config.cpiMode
    ? []
    : buildIntrospectionInstructions(canonical, instruction.data, groups);
  return { instruction: routed, priorInstructions };
}

export function readonlyMeta(accountAddress: Address): AccountMeta {
  return { address: accountAddress, role: AccountRole.READONLY };
}

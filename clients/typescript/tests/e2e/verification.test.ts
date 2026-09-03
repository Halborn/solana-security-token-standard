import {
  AccountRole,
  address,
  getAddressEncoder,
  getProgramDerivedAddress,
  lamports,
  type AccountMeta,
} from '@solana/kit';
import { fetchToken } from '@solana-program/token-2022';
import { describe, expect, it } from 'vitest';
import {
  MINT_DISCRIMINATOR,
  UPDATE_METADATA_DISCRIMINATOR,
  appendVerificationAccounts,
  buildIntrospectionInstructions,
  fetchAndResolveVerificationAccounts,
  fetchVerificationConfig,
  getMintInstruction,
  getTrimVerificationConfigInstruction,
  getUpdateMetadataInstruction,
  getUpdateVerificationConfigInstruction,
  getVerifyInstruction,
  type VerificationInstruction,
  type VerificationProgramConfigArgs,
} from '../../dist';
import {
  MEMO_PROGRAM_ADDRESS,
  TRANSFER_HOOK_PROGRAM_ADDRESS,
  createAssociatedTokenAccount,
  createE2eContext,
  findExtraAccountMetasPda,
  findTransferHookAuthorityPda,
  initializeMint,
  initializeVerificationConfig,
  readonlyMeta,
  routeVerification,
  sendInstructions,
} from './helpers';

const SYSTEM_PROGRAM_ADDRESS = address('11111111111111111111111111111111');
const INSTRUCTIONS_SYSVAR_ADDRESS = address(
  'Sysvar1nstructions1111111111111111111111111'
);

function fixedExtraAccount(
  accountAddress = SYSTEM_PROGRAM_ADDRESS
): VerificationProgramConfigArgs['extraAccounts'][number] {
  return {
    discriminator: 0,
    addressConfig: getAddressEncoder().encode(accountAddress),
    isSigner: false,
    isWritable: false,
  };
}

function accountKeyPdaExtraAccount(
  canonicalAccountIndex: number
): VerificationProgramConfigArgs['extraAccounts'][number] {
  const addressConfig = new Uint8Array(32);
  addressConfig.set([3, canonicalAccountIndex, 0]);
  return {
    discriminator: 1,
    addressConfig,
    isSigner: false,
    isWritable: false,
  };
}

describe('verification E2E', () => {
  it('initializes, decodes, updates, and trims an on-chain config', async () => {
    const context = await createE2eContext();
    const mintSetup = await initializeMint(context);
    const configAddress = await initializeVerificationConfig(
      context,
      mintSetup.mint.address,
      mintSetup.mintAuthority,
      UPDATE_METADATA_DISCRIMINATOR,
      false
    );

    const initialized = await fetchVerificationConfig(
      context.client.rpc,
      configAddress
    );
    expect(initialized.data).toMatchObject({
      discriminator: 1,
      instructionDiscriminator: UPDATE_METADATA_DISCRIMINATOR,
      cpiMode: false,
    });
    expect(initialized.data.programs).toEqual([
      { programId: MEMO_PROGRAM_ADDRESS, extraAccounts: [] },
    ]);

    const [accountMetasPda, transferHookPda] = await Promise.all([
      findExtraAccountMetasPda(mintSetup.mint.address),
      findTransferHookAuthorityPda(mintSetup.mint.address),
    ]);
    const updatedPrograms: VerificationProgramConfigArgs[] = [
      {
        programId: MEMO_PROGRAM_ADDRESS,
        extraAccounts: [fixedExtraAccount()],
      },
    ];
    await sendInstructions(context, [
      getUpdateVerificationConfigInstruction({
        mint: mintSetup.mint.address,
        verificationConfigOrMintAuthority: mintSetup.mintAuthority,
        instructionsSysvarOrCreator: context.payer.address,
        payer: context.payer,
        mintAccount: mintSetup.mint.address,
        configAccount: configAddress,
        accountMetasPda,
        transferHookPda,
        transferHookProgram: TRANSFER_HOOK_PROGRAM_ADDRESS,
        updateVerificationConfigArgs: {
          instructionDiscriminator: UPDATE_METADATA_DISCRIMINATOR,
          cpiMode: false,
          offset: 0,
          programs: updatedPrograms,
        },
      }),
    ]);

    const updated = await fetchVerificationConfig(
      context.client.rpc,
      configAddress
    );
    expect(updated.data.programs).toEqual(updatedPrograms);

    await sendInstructions(context, [
      getTrimVerificationConfigInstruction({
        mint: mintSetup.mint.address,
        verificationConfigOrMintAuthority: mintSetup.mintAuthority,
        instructionsSysvarOrCreator: context.payer.address,
        mintAccount: mintSetup.mint.address,
        configAccount: configAddress,
        recipient: context.payer.address,
        accountMetasPda,
        transferHookPda,
        transferHookProgram: TRANSFER_HOOK_PROGRAM_ADDRESS,
        trimVerificationConfigArgs: {
          instructionDiscriminator: UPDATE_METADATA_DISCRIMINATOR,
          size: 1,
          close: false,
        },
      }),
    ]);

    const trimmed = await fetchVerificationConfig(
      context.client.rpc,
      configAddress
    );
    expect(trimmed.data.programs).toEqual(updatedPrograms);
  });

  it('routes a dynamic extra account in CPI mode', async () => {
    const context = await createE2eContext();
    const mintSetup = await initializeMint(context);
    const destination = await createAssociatedTokenAccount(
      context,
      mintSetup.mint.address,
      context.payer.address
    );
    const dynamicExtraAddress = (
      await getProgramDerivedAddress({
        programAddress: MEMO_PROGRAM_ADDRESS,
        seeds: [getAddressEncoder().encode(destination)],
      })
    )[0];
    context.client.svm.setAccount({
      address: dynamicExtraAddress,
      data: new Uint8Array(),
      executable: false,
      lamports: lamports(1_000_000n),
      programAddress: SYSTEM_PROGRAM_ADDRESS,
      space: 0n,
    });
    const configAddress = await initializeVerificationConfig(
      context,
      mintSetup.mint.address,
      mintSetup.mintAuthority,
      MINT_DISCRIMINATOR,
      true,
      [
        {
          programId: MEMO_PROGRAM_ADDRESS,
          extraAccounts: [accountKeyPdaExtraAccount(2)],
        },
      ]
    );
    const mintInstruction = getMintInstruction({
      mint: mintSetup.mint.address,
      verificationConfig: configAddress,
      mintAuthority: mintSetup.mintAuthority,
      mintAccount: mintSetup.mint.address,
      destination,
      amount: 64,
    });

    const routed = await routeVerification(
      context,
      mintInstruction,
      configAddress
    );
    expect(routed.priorInstructions).toEqual([]);
    expect(
      routed.instruction.accounts[routed.instruction.accounts.length - 1]
    ).toEqual(
      readonlyMeta(dynamicExtraAddress)
    );
    await sendInstructions(context, [routed.instruction]);

    expect((await fetchToken(context.client.rpc, destination)).data.amount).toBe(
      64n
    );
  });

  it('builds and executes introspection instructions for a client operation', async () => {
    const context = await createE2eContext();
    const mintSetup = await initializeMint(context, {
      ixMetadata: {
        name: 'Before',
        symbol: 'BFR',
        uri: 'https://example.test/before',
        additionalMetadata: new Uint8Array(),
      },
    });
    const configAddress = await initializeVerificationConfig(
      context,
      mintSetup.mint.address,
      mintSetup.mintAuthority,
      UPDATE_METADATA_DISCRIMINATOR,
      false,
      [
        {
          programId: MEMO_PROGRAM_ADDRESS,
          extraAccounts: [fixedExtraAccount()],
        },
      ]
    );
    const operation = getUpdateMetadataInstruction({
      mint: mintSetup.mint.address,
      verificationConfigOrMintAuthority: configAddress,
      instructionsSysvarOrCreator: INSTRUCTIONS_SYSVAR_ADDRESS,
      mintAuthority: mintSetup.mintAuthority,
      payer: context.payer,
      mintAccount: mintSetup.mint.address,
      updateMetadataArgs: {
        metadata: {
          name: 'After',
          symbol: 'AFT',
          uri: 'https://example.test/after',
          additionalMetadata: new Uint8Array(),
        },
      },
    });

    const routed = await routeVerification(
      context,
      operation as VerificationInstruction,
      configAddress
    );
    expect(routed.priorInstructions).toHaveLength(1);
    expect(routed.priorInstructions[0].programAddress).toBe(
      MEMO_PROGRAM_ADDRESS
    );
    expect(
      routed.priorInstructions[0].accounts[
        routed.priorInstructions[0].accounts.length - 1
      ]
    ).toEqual(
      readonlyMeta(SYSTEM_PROGRAM_ADDRESS)
    );
    await sendInstructions(context, [
      ...routed.priorInstructions,
      routed.instruction,
    ]);
  });

  it('executes generated Verify after the matching prior Memo instruction', async () => {
    const context = await createE2eContext();
    const mintSetup = await initializeMint(context);
    const configAddress = await initializeVerificationConfig(
      context,
      mintSetup.mint.address,
      mintSetup.mintAuthority,
      UPDATE_METADATA_DISCRIMINATOR,
      false,
      [
        {
          programId: MEMO_PROGRAM_ADDRESS,
          extraAccounts: [fixedExtraAccount()],
        },
      ]
    );
    const instructionData = Uint8Array.of(42);
    const verifierData = Uint8Array.of(
      UPDATE_METADATA_DISCRIMINATOR,
      ...instructionData
    );
    const canonical: AccountMeta[] = [
      readonlyMeta(mintSetup.mint.address),
      readonlyMeta(configAddress),
      readonlyMeta(SYSTEM_PROGRAM_ADDRESS),
      readonlyMeta(INSTRUCTIONS_SYSVAR_ADDRESS),
      readonlyMeta(TRANSFER_HOOK_PROGRAM_ADDRESS),
    ];
    const { groups } = await fetchAndResolveVerificationAccounts(
      context.client.rpc,
      configAddress,
      canonical.map((meta) => ({ meta })),
      verifierData,
      async (accountAddress) => {
        const account = context.client.svm.getAccount(accountAddress);
        return account.exists ? account.data : undefined;
      }
    );
    const prior = buildIntrospectionInstructions(
      canonical,
      verifierData,
      groups
    );
    const baseVerify = getVerifyInstruction({
      mint: mintSetup.mint.address,
      verificationConfig: configAddress,
      verifyArgs: {
        ix: UPDATE_METADATA_DISCRIMINATOR,
        instructionData,
      },
    });
    const verifyWithCanonical: VerificationInstruction = {
      ...baseVerify,
      accounts: [...baseVerify.accounts, ...canonical],
    };
    const routedVerify = appendVerificationAccounts(
      verifyWithCanonical,
      groups
    );

    expect(prior).toHaveLength(1);
    expect(routedVerify.accounts[routedVerify.accounts.length - 2]).toEqual({
      address: MEMO_PROGRAM_ADDRESS,
      role: AccountRole.READONLY,
    });
    await sendInstructions(context, [...prior, routedVerify]);
  });
});

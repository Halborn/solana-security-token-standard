import {
  address,
  generateKeyPairSigner,
  isSome,
  unwrapOption,
} from '@solana/kit';
import {
  AccountState,
  fetchMint,
  fetchToken,
} from '@solana-program/token-2022';
import { describe, expect, it } from 'vitest';
import {
  BURN_DISCRIMINATOR,
  FREEZE_DISCRIMINATOR,
  MINT_DISCRIMINATOR,
  PAUSE_DISCRIMINATOR,
  RESUME_DISCRIMINATOR,
  THAW_DISCRIMINATOR,
  TRANSFER_DISCRIMINATOR,
  UPDATE_METADATA_DISCRIMINATOR,
  getBurnInstruction,
  getFreezeInstruction,
  getMintInstruction,
  getPauseInstruction,
  getResumeInstruction,
  getThawInstruction,
  getTransferInstruction,
  getUpdateMetadataInstruction,
  type VerificationInstruction,
} from '../../dist';
import {
  TRANSFER_HOOK_PROGRAM_ADDRESS,
  createAssociatedTokenAccount,
  createE2eContext,
  initializeMint,
  initializeVerificationConfig,
  routeVerification,
  sendInstructions,
} from './helpers';

describe('TypeScript client against the SBF programs', () => {
  it('initializes a mint and updates its metadata', async () => {
    const context = await createE2eContext();
    const metadata = {
      name: 'Security Token',
      symbol: 'SCTS',
      uri: 'https://example.test/token.json',
      additionalMetadata: new Uint8Array(),
    };
    const mintSetup = await initializeMint(context, {
      ixMetadata: metadata,
    });

    const initialMint = await fetchMint(context.client.rpc, mintSetup.mint.address);
    expect(initialMint.data.decimals).toBe(2);
    expect(initialMint.data.supply).toBe(0n);
    expect(isSome(initialMint.data.mintAuthority)).toBe(true);
    expect(unwrapOption(initialMint.data.mintAuthority)).toBe(
      mintSetup.mintAuthority
    );
    expect(unwrapOption(initialMint.data.freezeAuthority)).toBe(
      mintSetup.freezeAuthority
    );
    const extensions = unwrapOption(initialMint.data.extensions) ?? [];
    expect(extensions.map((extension) => extension.__kind)).toEqual(
      expect.arrayContaining([
        'PermanentDelegate',
        'TransferHook',
        'PausableConfig',
        'MetadataPointer',
        'TokenMetadata',
      ])
    );
    const permanentDelegate = extensions.find(
      (extension) => extension.__kind === 'PermanentDelegate'
    );
    const transferHook = extensions.find(
      (extension) => extension.__kind === 'TransferHook'
    );
    const pausable = extensions.find(
      (extension) => extension.__kind === 'PausableConfig'
    );
    const initialMetadata = extensions.find(
      (extension) => extension.__kind === 'TokenMetadata'
    );
    expect(permanentDelegate).toMatchObject({
      delegate: mintSetup.permanentDelegate,
    });
    expect(transferHook).toMatchObject({
      programId: TRANSFER_HOOK_PROGRAM_ADDRESS,
    });
    expect(
      transferHook?.__kind === 'TransferHook'
        ? transferHook.authority
        : null
    ).toBe(mintSetup.transferHookAuthority);
    expect(
      pausable?.__kind === 'PausableConfig'
        ? unwrapOption(pausable.authority)
        : null
    ).toBe(mintSetup.pauseAuthority);
    expect(initialMetadata).toMatchObject({
      name: metadata.name,
      symbol: metadata.symbol,
      uri: metadata.uri,
    });

    const config = await initializeVerificationConfig(
      context,
      mintSetup.mint.address,
      mintSetup.mintAuthority,
      UPDATE_METADATA_DISCRIMINATOR,
      false
    );
    const updated = {
      name: 'Updated Token',
      symbol: 'UPDT',
      uri: 'https://example.test/updated.json',
      additionalMetadata: new Uint8Array(),
    };
    const update = getUpdateMetadataInstruction({
      mint: mintSetup.mint.address,
      verificationConfigOrMintAuthority: config,
      instructionsSysvarOrCreator: address(
        'Sysvar1nstructions1111111111111111111111111'
      ),
      mintAuthority: mintSetup.mintAuthority,
      payer: context.payer,
      mintAccount: mintSetup.mint.address,
      updateMetadataArgs: { metadata: updated },
    });
    const routed = await routeVerification(
      context,
      update as VerificationInstruction,
      config
    );
    await sendInstructions(context, [
      ...routed.priorInstructions,
      routed.instruction,
    ]);

    const updatedMint = await fetchMint(context.client.rpc, mintSetup.mint.address);
    const tokenMetadata = (unwrapOption(updatedMint.data.extensions) ?? []).find(
      (extension) => extension.__kind === 'TokenMetadata'
    );
    expect(tokenMetadata).toMatchObject({
      name: updated.name,
      symbol: updated.symbol,
      uri: updated.uri,
      additionalMetadata: new Map(),
    });
  });

  it('mints, burns, freezes, thaws, pauses, resumes, and transfers', async () => {
    const context = await createE2eContext();
    const mintSetup = await initializeMint(context);
    const recipient = await generateKeyPairSigner();
    const source = await createAssociatedTokenAccount(
      context,
      mintSetup.mint.address,
      context.payer.address
    );
    const destination = await createAssociatedTokenAccount(
      context,
      mintSetup.mint.address,
      recipient.address
    );
    const discriminators = [
      MINT_DISCRIMINATOR,
      BURN_DISCRIMINATOR,
      FREEZE_DISCRIMINATOR,
      THAW_DISCRIMINATOR,
      PAUSE_DISCRIMINATOR,
      RESUME_DISCRIMINATOR,
      TRANSFER_DISCRIMINATOR,
    ];
    const configs = new Map<number, Awaited<ReturnType<typeof initializeVerificationConfig>>>();
    for (const discriminator of discriminators) {
      configs.set(
        discriminator,
        await initializeVerificationConfig(
          context,
          mintSetup.mint.address,
          mintSetup.mintAuthority,
          discriminator,
          false
        )
      );
    }

    const execute = async (
      discriminator: number,
      instruction: VerificationInstruction
    ) => {
      const config = configs.get(discriminator)!;
      const routed = await routeVerification(context, instruction, config);
      await sendInstructions(context, [
        ...routed.priorInstructions,
        routed.instruction,
      ]);
    };

    await execute(
      MINT_DISCRIMINATOR,
      getMintInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(MINT_DISCRIMINATOR)!,
        mintAuthority: mintSetup.mintAuthority,
        mintAccount: mintSetup.mint.address,
        destination: source,
        amount: 100,
      })
    );
    expect((await fetchMint(context.client.rpc, mintSetup.mint.address)).data.supply).toBe(100n);
    expect((await fetchToken(context.client.rpc, source)).data.amount).toBe(100n);

    await execute(
      BURN_DISCRIMINATOR,
      getBurnInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(BURN_DISCRIMINATOR)!,
        permanentDelegate: mintSetup.permanentDelegate,
        mintAccount: mintSetup.mint.address,
        tokenAccount: source,
        amount: 25,
      })
    );
    expect((await fetchMint(context.client.rpc, mintSetup.mint.address)).data.supply).toBe(75n);
    expect((await fetchToken(context.client.rpc, source)).data.amount).toBe(75n);

    await execute(
      FREEZE_DISCRIMINATOR,
      getFreezeInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(FREEZE_DISCRIMINATOR)!,
        freezeAuthority: mintSetup.freezeAuthority,
        mintAccount: mintSetup.mint.address,
        tokenAccount: source,
      })
    );
    expect((await fetchToken(context.client.rpc, source)).data.state).toBe(
      AccountState.Frozen
    );

    await execute(
      THAW_DISCRIMINATOR,
      getThawInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(THAW_DISCRIMINATOR)!,
        freezeAuthority: mintSetup.freezeAuthority,
        mintAccount: mintSetup.mint.address,
        tokenAccount: source,
      })
    );
    expect((await fetchToken(context.client.rpc, source)).data.state).toBe(
      AccountState.Initialized
    );

    await execute(
      PAUSE_DISCRIMINATOR,
      getPauseInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(PAUSE_DISCRIMINATOR)!,
        pauseAuthority: mintSetup.pauseAuthority,
        mintAccount: mintSetup.mint.address,
      })
    );
    const paused = (
      unwrapOption(
        (await fetchMint(context.client.rpc, mintSetup.mint.address)).data
          .extensions
      ) ?? []
    ).find((extension) => extension.__kind === 'PausableConfig');
    expect(paused).toMatchObject({ paused: true });

    await execute(
      RESUME_DISCRIMINATOR,
      getResumeInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(RESUME_DISCRIMINATOR)!,
        pauseAuthority: mintSetup.pauseAuthority,
        mintAccount: mintSetup.mint.address,
      })
    );
    const resumed = (
      unwrapOption(
        (await fetchMint(context.client.rpc, mintSetup.mint.address)).data
          .extensions
      ) ?? []
    ).find((extension) => extension.__kind === 'PausableConfig');
    expect(resumed).toMatchObject({ paused: false });

    await execute(
      TRANSFER_DISCRIMINATOR,
      getTransferInstruction({
        mint: mintSetup.mint.address,
        verificationConfig: configs.get(TRANSFER_DISCRIMINATOR)!,
        permanentDelegateAuthority: mintSetup.permanentDelegate,
        mintAccount: mintSetup.mint.address,
        fromTokenAccount: source,
        toTokenAccount: destination,
        transferHookProgram: TRANSFER_HOOK_PROGRAM_ADDRESS,
        amount: 10,
      })
    );
    expect((await fetchToken(context.client.rpc, source)).data.amount).toBe(65n);
    expect((await fetchToken(context.client.rpc, destination)).data.amount).toBe(10n);
  });
});

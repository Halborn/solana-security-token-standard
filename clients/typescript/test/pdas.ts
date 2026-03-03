import { assert } from 'chai';
import {
  address,
  getAddressEncoder,
  getProgramDerivedAddress,
  getU64Encoder,
} from '@solana/kit';
import {
  deriveMintAuthorityPda,
  deriveVerificationConfigPda,
  deriveFreezeAuthorityPda,
  derivePauseAuthorityPda,
  derivePermanentDelegatePda,
  deriveRatePda,
  deriveCommonActionReceiptPda,
  deriveClaimReceiptPda,
  deriveProofPda,
  deriveDistributionEscrowAuthorityPda,
  MINT_AUTHORITY_SEED,
  FREEZE_AUTHORITY_SEED,
  PAUSE_AUTHORITY_SEED,
  PERMANENT_DELEGATE_SEED,
  VERIFICATION_CONFIG_SEED,
  RATE_SEED,
  RECEIPT_SEED,
  PROOF_SEED,
  DISTRIBUTION_ESCROW_AUTHORITY_SEED,
} from '../src';
import { SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS } from '../src/generated';

const MINT = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
const TOKEN_ACCOUNT = address('G6QmvUp3a1Kv9rX2LqHDH8AWcKD8yaufcoXEB1h6SzN8');
const CREATOR = address('tbFevHibEdBNFJfZ7xKC8k1th8pt2YPEXTk4sGMxCGa');
const MINT_FROM = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
const MINT_TO = address('So11111111111111111111111111111111111111112');
const ACTION_ID = 12345n;

describe('PDAs', () => {
  describe('input validation', () => {
    it('deriveVerificationConfigPda should throw on discriminator > 255', () => {
      assert.throws(
        () => deriveVerificationConfigPda({ mint: MINT, discriminator: 256 }),
        'discriminator must be an integer in the range 0–255',
      );
    });

    it('deriveVerificationConfigPda should throw on negative discriminator', () => {
      assert.throws(
        () => deriveVerificationConfigPda({ mint: MINT, discriminator: -1 }),
        'discriminator must be an integer in the range 0–255',
      );
    });

    it('deriveVerificationConfigPda should throw on non-integer discriminator', () => {
      assert.throws(
        () => deriveVerificationConfigPda({ mint: MINT, discriminator: 1.5 }),
        'discriminator must be an integer in the range 0–255',
      );
    });

    it('deriveRatePda should throw on actionId = 0', () => {
      assert.throws(
        () => deriveRatePda({ actionId: 0n, mintFrom: MINT_FROM, mintTo: MINT_TO }),
        'action_id must not be 0',
      );
    });

    it('deriveCommonActionReceiptPda should throw on actionId = 0', () => {
      assert.throws(
        () => deriveCommonActionReceiptPda({ mint: MINT, actionId: 0n }),
        'action_id must not be 0',
      );
    });

    it('deriveClaimReceiptPda should throw on actionId = 0', () => {
      assert.throws(
        () =>
          deriveClaimReceiptPda({
            mint: MINT,
            tokenAccount: TOKEN_ACCOUNT,
            actionId: 0n,
            proofHash: new Uint8Array(32),
          }),
        'action_id must not be 0',
      );
    });

    it('deriveClaimReceiptPda should throw on proofHash with wrong length', () => {
      assert.throws(
        () =>
          deriveClaimReceiptPda({
            mint: MINT,
            tokenAccount: TOKEN_ACCOUNT,
            actionId: 1n,
            proofHash: new Uint8Array(16),
          }),
        'proofHash must be exactly 32 bytes',
      );
    });

    it('deriveProofPda should throw on actionId = 0', () => {
      assert.throws(
        () => deriveProofPda({ tokenAccount: TOKEN_ACCOUNT, actionId: 0n }),
        'action_id must not be 0',
      );
    });

    it('deriveDistributionEscrowAuthorityPda should throw on actionId = 0', () => {
      assert.throws(
        () =>
          deriveDistributionEscrowAuthorityPda({
            mint: MINT,
            actionId: 0n,
            merkleRoot: new Uint8Array(32),
          }),
        'action_id must not be 0',
      );
    });

    it('deriveDistributionEscrowAuthorityPda should throw on merkleRoot with wrong length', () => {
      assert.throws(
        () =>
          deriveDistributionEscrowAuthorityPda({
            mint: MINT,
            actionId: 1n,
            merkleRoot: new Uint8Array(16),
          }),
        'merkleRoot must be exactly 32 bytes',
      );
    });
  });

  describe('PDA derivation', () => {
    const enc = getAddressEncoder();
    const u64 = getU64Encoder();
    const program = SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS;

    it('should derive mint authority PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [MINT_AUTHORITY_SEED, enc.encode(MINT), enc.encode(CREATOR)],
      });
      assert.deepEqual(await deriveMintAuthorityPda({ mint: MINT, creator: CREATOR }), expected);
    });

    it('should derive verification config PDA from correct seeds', async () => {
      const discriminator = 1;
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [VERIFICATION_CONFIG_SEED, enc.encode(MINT), new Uint8Array([discriminator])],
      });
      assert.deepEqual(
        await deriveVerificationConfigPda({ mint: MINT, discriminator }),
        expected,
      );
    });

    it('should derive freeze authority PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [FREEZE_AUTHORITY_SEED, enc.encode(MINT)],
      });
      assert.deepEqual(await deriveFreezeAuthorityPda({ mint: MINT }), expected);
    });

    it('should derive pause authority PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [PAUSE_AUTHORITY_SEED, enc.encode(MINT)],
      });
      assert.deepEqual(await derivePauseAuthorityPda({ mint: MINT }), expected);
    });

    it('should derive permanent delegate PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [PERMANENT_DELEGATE_SEED, enc.encode(MINT)],
      });
      assert.deepEqual(await derivePermanentDelegatePda({ mint: MINT }), expected);
    });

    it('should derive rate PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [RATE_SEED, u64.encode(ACTION_ID), enc.encode(MINT_FROM), enc.encode(MINT_TO)],
      });
      assert.deepEqual(
        await deriveRatePda({ actionId: ACTION_ID, mintFrom: MINT_FROM, mintTo: MINT_TO }),
        expected,
      );
    });

    it('should derive common action receipt PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [RECEIPT_SEED, enc.encode(MINT), u64.encode(ACTION_ID)],
      });
      assert.deepEqual(await deriveCommonActionReceiptPda({ mint: MINT, actionId: ACTION_ID }), expected);
    });

    it('should derive claim receipt PDA from correct seeds', async () => {
      const proofHash = new Uint8Array(32).fill(1);
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [
          RECEIPT_SEED,
          enc.encode(MINT),
          enc.encode(TOKEN_ACCOUNT),
          u64.encode(ACTION_ID),
          proofHash,
        ],
      });
      assert.deepEqual(
        await deriveClaimReceiptPda({ mint: MINT, tokenAccount: TOKEN_ACCOUNT, actionId: ACTION_ID, proofHash }),
        expected,
      );
    });

    it('should derive proof PDA from correct seeds', async () => {
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [PROOF_SEED, enc.encode(TOKEN_ACCOUNT), u64.encode(ACTION_ID)],
      });
      assert.deepEqual(await deriveProofPda({ tokenAccount: TOKEN_ACCOUNT, actionId: ACTION_ID }), expected);
    });

    it('should derive distribution escrow authority PDA from correct seeds', async () => {
      const merkleRoot = new Uint8Array(32).fill(2);
      const expected = await getProgramDerivedAddress({
        programAddress: program,
        seeds: [
          DISTRIBUTION_ESCROW_AUTHORITY_SEED,
          enc.encode(MINT),
          u64.encode(ACTION_ID),
          merkleRoot,
        ],
      });
      assert.deepEqual(
        await deriveDistributionEscrowAuthorityPda({ mint: MINT, actionId: ACTION_ID, merkleRoot }),
        expected,
      );
    });
  });
});

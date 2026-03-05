import { assert } from 'chai';
import { address } from '@solana/kit';
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
} from '../src';

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
    // Precomputed golden addresses for program SSTS8Qk2bW3aVaBEsY1Ras95YdbaaYQQx21JWHxvjap.
    // If any seed string or encoding changes on-chain, these assertions will fail.

    it('should derive mint authority PDA', async () => {
      const [pda, bump] = await deriveMintAuthorityPda({ mint: MINT, creator: CREATOR });
      assert.equal(pda, 'GLpBiBfz8zzoyAFpbkymBPTMBYrBSsHv4qs5Fs25EUQt');
      assert.equal(bump, 255);
    });

    it('should derive verification config PDA', async () => {
      const [pda, bump] = await deriveVerificationConfigPda({ mint: MINT, discriminator: 1 });
      assert.equal(pda, 'DKJ5KnnqTCbae68qiMfsJdszeoZcfn6GqSFBMjEN4DpY');
      assert.equal(bump, 255);
    });

    it('should derive freeze authority PDA', async () => {
      const [pda, bump] = await deriveFreezeAuthorityPda({ mint: MINT });
      assert.equal(pda, '4SPTobhTmzMs9VKB97ruzeC1Me8UaecmhkLN6E5Mzb3S');
      assert.equal(bump, 255);
    });

    it('should derive pause authority PDA', async () => {
      const [pda, bump] = await derivePauseAuthorityPda({ mint: MINT });
      assert.equal(pda, '7nze7BaooFMi2xverhsMvkkDcHsvicxinB3Vzzh6KEtz');
      assert.equal(bump, 255);
    });

    it('should derive permanent delegate PDA', async () => {
      const [pda, bump] = await derivePermanentDelegatePda({ mint: MINT });
      assert.equal(pda, '9waW3SJnxdsAQfer8n7eFKZBxAFfpsh4DShxoow2k4s8');
      assert.equal(bump, 255);
    });

    it('should derive rate PDA', async () => {
      const [pda, bump] = await deriveRatePda({ actionId: ACTION_ID, mintFrom: MINT_FROM, mintTo: MINT_TO });
      assert.equal(pda, 'DaBRX4SQdMZECJGaHcN33CVAVyA2QCLN1CHsoDuQG9X5');
      assert.equal(bump, 255);
    });

    it('should derive common action receipt PDA', async () => {
      const [pda, bump] = await deriveCommonActionReceiptPda({ mint: MINT, actionId: ACTION_ID });
      assert.equal(pda, '8NGjM9JnVqUsuZWgrifBhgMqKyUu98mfrfVA6RaFAZCC');
      assert.equal(bump, 255);
    });

    it('should derive claim receipt PDA', async () => {
      const proofHash = new Uint8Array(32).fill(1);
      const [pda, bump] = await deriveClaimReceiptPda({ mint: MINT, tokenAccount: TOKEN_ACCOUNT, actionId: ACTION_ID, proofHash });
      assert.equal(pda, 'FYzTLNeNxQh8B6kdFRRPKn1oWh8Qd6YMmQbD5umBWSCi');
      assert.equal(bump, 255);
    });

    it('should derive proof PDA', async () => {
      const [pda, bump] = await deriveProofPda({ tokenAccount: TOKEN_ACCOUNT, actionId: ACTION_ID });
      assert.equal(pda, 'C8iRbMV8tjTBKtJUuLQMSKz2cwbyvwvpGxm2mK1UjL9u');
      assert.equal(bump, 251);
    });

    it('should derive distribution escrow authority PDA', async () => {
      const merkleRoot = new Uint8Array(32).fill(2);
      const [pda, bump] = await deriveDistributionEscrowAuthorityPda({ mint: MINT, actionId: ACTION_ID, merkleRoot });
      assert.equal(pda, 'BhiBBbZh2c7ErGrm7AqaCKNdiSJfsYc1Tbi9kLKgeDEe');
      assert.equal(bump, 253);
    });
  });
});

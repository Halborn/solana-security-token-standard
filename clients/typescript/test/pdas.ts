import { assert } from 'chai';
import { Address, address, ProgramDerivedAddressBump } from '@solana/kit';
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

describe('PDAs', () => {
  describe('PDA derivation', () => {
    it('should derive a mint authority PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const creator = address('tbFevHibEdBNFJfZ7xKC8k1th8pt2YPEXTk4sGMxCGa');

      const expectedPda = [
        '8v3GCA9Z54z5SuoFG6Yv5jZZvgHgGV5Mj3LZ27seT4BP',
        254,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveMintAuthorityPda({ mint, creator });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a verification config PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const discriminator = 1;

      const expectedPda = [
        '6oTvhWZV8bWVhiTEYhgRLNFRhtfH6ZEjwJNnw9GbhicE',
        250,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveVerificationConfigPda({
        mint,
        discriminator,
      });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a freeze authority PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

      const expectedPda = [
        'G6ya6sq4LQZhyqe57aLb76mTv33WwDsmYfCzDNE5uRV5',
        255,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveFreezeAuthorityPda({ mint });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a pause authority PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

      const expectedPda = [
        'HHunMbuFPETHmRuQyGN8GoL9pjydJPRGkFVhWMmkuJPf',
        255,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await derivePauseAuthorityPda({ mint });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a permanent delegate PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

      const expectedPda = [
        '7AkN9c8X4wLueqyLfAxVfE5cm5GWj7Vxh7GAatX3By47',
        255,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await derivePermanentDelegatePda({ mint });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a rate PDA', async () => {
      const mintFrom = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const mintTo = address('So11111111111111111111111111111111111111112');
      const actionId = 12345n;

      const expectedPda = [
        'FQJcEDAYFPZddNE5c3EYVUFb1cX36eT2SrXh3m93uYmW',
        255,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveRatePda({
        actionId,
        mintFrom,
        mintTo,
      });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a common action receipt PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const actionId = 12345n;

      const expectedPda = [
        '6zQ4g3fRKAoqDT4QP1MhPPUaSgj3EqRySEzKz7Mncpcy',
        255,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveCommonActionReceiptPda({
        mint,
        actionId,
      });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a claim receipt PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const tokenAccount = address(
        'G6QmvUp3a1Kv9rX2LqHDH8AWcKD8yaufcoXEB1h6SzN8',
      );
      const actionId = 12345n;
      const proofHash = new Uint8Array(32).fill(1);

      const expectedPda = [
        '71GomJHo9KCqfu7CSKCL1yB9X7zKyxoiXReeyE4yDyKj',
        254,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveClaimReceiptPda({
        mint,
        tokenAccount,
        actionId,
        proofHash,
      });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a proof PDA', async () => {
      const tokenAccount = address(
        'G6QmvUp3a1Kv9rX2LqHDH8AWcKD8yaufcoXEB1h6SzN8',
      );
      const actionId = 12345n;

      const expectedPda = [
        'Gmvc2ZRnUsreGCG8JA6kznmna9h8JhNZSFewHMB54jKM',
        254,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveProofPda({ tokenAccount, actionId });

      assert.deepEqual(testPda, expectedPda);
    });

    it('should derive a distribution escrow authority PDA', async () => {
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const actionId = 12345n;
      const merkleRoot = new Uint8Array(32).fill(2);

      const expectedPda = [
        'ERMdD7ZG5hDT1EChcoDCJfGoX5BJwQwz5SYCdiNui1m4',
        255,
      ] as [Address<string>, ProgramDerivedAddressBump];
      const testPda = await deriveDistributionEscrowAuthorityPda({
        mint,
        actionId,
        merkleRoot,
      });

      assert.deepEqual(testPda, expectedPda);
    });
  });
});

import { assert } from 'chai';
import { address } from '@solana/kit';
import {
  hashProofData,
  createMerkleTreeLeafNode,
  calculateConvertAmount,
  calculateSplitAmount,
} from '../src';

describe('Utils', () => {
  describe('hashProofData', () => {
    it('should throw when a proof node is not 32 bytes', () => {
      const node1 = new Uint8Array(32).fill(1);
      const shortNode = new Uint8Array(16).fill(2);
      assert.throws(
        () => hashProofData([node1, shortNode]),
        'every proof node must be exactly 32 bytes',
      );
    });

    it('should be deterministic and order-sensitive', () => {
      const node1 = new Uint8Array(32).fill(1);
      const node2 = new Uint8Array(32).fill(2);

      // Same inputs produce same hash
      const hash1a = hashProofData([node1, node2]);
      const hash1b = hashProofData([node1, node2]);
      assert.deepEqual(hash1a, hash1b);

      // Different order produces different hash
      const hash2 = hashProofData([node2, node1]);
      assert.notDeepEqual(hash1a, hash2);

      // Output is 32 bytes
      assert.equal(hash1a.length, 32);
    });

    it('should match on-chain keccak256 output for known inputs', () => {
      // Golden vector: keccak256(fill(1,32) ++ fill(2,32))
      // Must match solana_keccak_hasher::hashv on-chain
      const node1 = new Uint8Array(32).fill(1);
      const node2 = new Uint8Array(32).fill(2);
      const expected = Buffer.from(
        '346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0',
        'hex',
      );
      assert.deepEqual(hashProofData([node1, node2]), new Uint8Array(expected));
    });
  });

  describe('createMerkleTreeLeafNode', () => {
    it('should be deterministic', () => {
      const tokenAccount = address(
        'tbFevHibEdBNFJfZ7xKC8k1th8pt2YPEXTk4sGMxCGa',
      );
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const actionId = 12345n;
      const amount = 1000000000n;

      const leaf1 = createMerkleTreeLeafNode(
        tokenAccount,
        mint,
        actionId,
        amount,
      );
      const leaf2 = createMerkleTreeLeafNode(
        tokenAccount,
        mint,
        actionId,
        amount,
      );

      assert.deepEqual(leaf1, leaf2);
      assert.equal(leaf1.length, 32);
    });

    it('should match on-chain keccak256 output for known inputs', () => {
      // Golden vector: keccak256(tokenAccount(32) ++ mint(32) ++ actionId(8,le) ++ amount(8,le))
      // Must match on-chain leaf creation logic
      const tokenAccount = address('tbFevHibEdBNFJfZ7xKC8k1th8pt2YPEXTk4sGMxCGa');
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const expected = Buffer.from(
        '04cdba254800b57c0aab166dd87f7755b1b94f699ed23bee73aed2d0d5adaa83',
        'hex',
      );
      assert.deepEqual(
        createMerkleTreeLeafNode(tokenAccount, mint, 12345n, 1000000000n),
        new Uint8Array(expected),
      );
    });

    it('should produce different leaves for different inputs', () => {
      const tokenAccount1 = address(
        'tbFevHibEdBNFJfZ7xKC8k1th8pt2YPEXTk4sGMxCGa',
      );
      const tokenAccount2 = address(
        'G6QmvUp3a1Kv9rX2LqHDH8AWcKD8yaufcoXEB1h6SzN8',
      );
      const mint = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      const actionId = 12345n;

      const leaf1 = createMerkleTreeLeafNode(
        tokenAccount1,
        mint,
        actionId,
        1000n,
      );
      const leaf2 = createMerkleTreeLeafNode(
        tokenAccount2,
        mint,
        actionId,
        1000n,
      );
      const leaf3 = createMerkleTreeLeafNode(
        tokenAccount1,
        mint,
        actionId,
        2000n,
      );

      assert.notDeepEqual(leaf1, leaf2);
      assert.notDeepEqual(leaf1, leaf3);
    });
  });

  describe('calculateConvertAmount', () => {
    it('should calculate conversion with given rate', () => {
      // 1:2 ratio
      assert.equal(calculateConvertAmount(1000n, 1n, 2n), 2000n);

      // 2:1 ratio
      assert.equal(calculateConvertAmount(1000n, 2n, 1n), 500n);

      // 1:1 ratio
      assert.equal(calculateConvertAmount(1000n, 1n, 1n), 1000n);
    });

    it('should truncate on integer division', () => {
      // (100 * 2) / 3 = 66.666... → 66
      assert.equal(calculateConvertAmount(100n, 3n, 2n), 66n);
    });

    it('should throw error for zero rateFrom', () => {
      assert.throws(
        () => calculateConvertAmount(1000n, 0n, 2n),
        'rateFrom cannot be zero',
      );
    });
  });

  describe('calculateSplitAmount', () => {
    it('should use same formula as calculateConvertAmount', () => {
      const inputAmount = 1000n;
      const rateFrom = 3n;
      const rateTo = 5n;

      const convertResult = calculateConvertAmount(
        inputAmount,
        rateFrom,
        rateTo,
      );
      const splitResult = calculateSplitAmount(inputAmount, rateFrom, rateTo);

      assert.equal(splitResult, convertResult);
    });
  });
});

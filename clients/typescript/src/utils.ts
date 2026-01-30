import { Address, getAddressEncoder, getU64Encoder } from '@solana/kit';
import { keccak_256 } from '@noble/hashes/sha3';

/**
 * Hash proof data using Keccak256.
 * This is used to derive the claim receipt PDA.
 *
 * The proof data is flattened (concatenated) before hashing.
 *
 * @param proof - Array of 32-byte proof nodes
 * @returns The 32-byte keccak256 hash of the concatenated proof data
 *
 * @example
 * ```typescript
 * const proof = [
 *   new Uint8Array(32), // proof node 1
 *   new Uint8Array(32), // proof node 2
 * ];
 * const hash = hashProofData(proof);
 * ```
 */
export function hashProofData(proof: Uint8Array[]): Uint8Array {
  // Flatten proof array into single Uint8Array by concatenating all nodes
  const proofData = new Uint8Array(proof.length * 32);
  proof.forEach((node, i) => {
    proofData.set(node, i * 32);
  });

  // Hash the concatenated proof data using keccak256
  return keccak256(proofData);
}

/**
 * Keccak256 hash function using @noble/hashes.
 *
 * @param data - Data to hash
 * @returns 32-byte hash
 */
function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/**
 * Create a Merkle tree leaf node from eligible claimer data.
 *
 * This matches the on-chain leaf creation logic.
 *
 * @param eligibleTokenAccount - The eligible token account address
 * @param mint - The mint address
 * @param actionId - The action ID
 * @param amount - The eligible amount to claim
 * @returns The 32-byte leaf node hash
 *
 * @example
 * ```typescript
 * const leaf = createMerkleTreeLeafNode(
 *   tokenAccountAddress,
 *   mintAddress,
 *   12345n,
 *   1000000000n
 * );
 * ```
 */
export function createMerkleTreeLeafNode(
  eligibleTokenAccount: Address,
  mint: Address,
  actionId: bigint,
  amount: bigint,
): Uint8Array {
  const addressEncoder = getAddressEncoder();
  const u64Encoder = getU64Encoder();

  // Encode all components
  const tokenAccountBytes = new Uint8Array(
    addressEncoder.encode(eligibleTokenAccount),
  );
  const mintBytes = new Uint8Array(addressEncoder.encode(mint));
  const actionIdBytes = new Uint8Array(u64Encoder.encode(actionId));
  const amountBytes = new Uint8Array(u64Encoder.encode(amount));

  // Concatenate: eligible_token_account (32) + mint (32) + action_id (8) + amount (8)
  const bytes = concatBytes(
    tokenAccountBytes,
    mintBytes,
    actionIdBytes,
    amountBytes,
  );

  return keccak256(bytes);
}

/**
 * Calculate the output amount for a Convert operation.
 *
 * Formula: output_amount = (input_amount * rate_to) / rate_from
 *
 * @param inputAmount - The amount being converted
 * @param rateFrom - The rate of the input token
 * @param rateTo - The rate of the output token
 * @returns The output amount after conversion
 *
 * @example
 * ```typescript
 * const outputAmount = calculateConvertAmount(1000n, 1n, 2n);
 * console.log(outputAmount); // 2000n
 * ```
 */
export function calculateConvertAmount(
  inputAmount: bigint,
  rateFrom: bigint,
  rateTo: bigint,
): bigint {
  if (rateFrom === 0n) {
    throw new Error('rateFrom cannot be zero');
  }

  return (inputAmount * rateTo) / rateFrom;
}

/**
 * Calculate the output amount for a Split operation.
 *
 * Formula: output_amount = (input_amount * split_rate_to) / split_rate_from
 *
 * @param inputAmount - The amount being split
 * @param rateFrom - The numerator of the split rate
 * @param rateTo - The denominator of the split rate
 * @returns The output amount after split
 *
 * @example
 * ```typescript
 * // Split at 1:2 ratio (1 token becomes 2 tokens)
 * const outputAmount = calculateSplitAmount(1000n, 1n, 2n);
 * console.log(outputAmount); // 2000n
 * ```
 */
export function calculateSplitAmount(
  inputAmount: bigint,
  rateFrom: bigint,
  rateTo: bigint,
): bigint {
  // Split uses the same formula as convert
  return calculateConvertAmount(inputAmount, rateFrom, rateTo);
}

// Helper functions

/**
 * Concatenate multiple Uint8Arrays into a single Uint8Array
 */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

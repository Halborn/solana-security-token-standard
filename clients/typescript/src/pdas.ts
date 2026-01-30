/**
 * Program Derived Addresses (PDAs) for Security Token Program
 *
 * This module provides functions to derive all PDAs needed by the client
 * to construct instructions for the Security Token Program.
 */

import {
  Address,
  getAddressEncoder,
  getProgramDerivedAddress,
  getU64Encoder,
} from '@solana/kit';
import { SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS } from './generated';

// PDA Seeds
export const MINT_AUTHORITY_SEED = 'mint.authority';
export const FREEZE_AUTHORITY_SEED = 'mint.freeze_authority';
export const PAUSE_AUTHORITY_SEED = 'mint.pause_authority';
export const PERMANENT_DELEGATE_SEED = 'mint.permanent_delegate';
export const VERIFICATION_CONFIG_SEED = 'verification_config';
export const RATE_SEED = 'rate';
export const RECEIPT_SEED = 'receipt';
export const PROOF_SEED = 'proof';
export const DISTRIBUTION_ESCROW_AUTHORITY_SEED =
  'distribution_escrow_authority';

/**
 * Derive Mint Authority PDA
 * Seeds: ["mint.authority", mint, creator]
 *
 * @param mint - The mint address
 * @param creator - The creator address
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveMintAuthorityPda = ({
  mint,
  creator,
}: {
  mint: Address;
  creator: Address;
}) => {
  const addressEncoder = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      MINT_AUTHORITY_SEED,
      addressEncoder.encode(mint),
      addressEncoder.encode(creator),
    ],
  });
};

/**
 * Derive Verification Config PDA
 * Seeds: ["verification_config", mint, discriminator]
 *
 * @param mint - The mint address
 * @param discriminator - The instruction discriminator (0-255)
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveVerificationConfigPda = ({
  mint,
  discriminator,
}: {
  mint: Address;
  discriminator: number;
}) => {
  const addressEncoder = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      VERIFICATION_CONFIG_SEED,
      addressEncoder.encode(mint),
      new Uint8Array([discriminator]),
    ],
  });
};

/**
 * Derive Freeze Authority PDA
 * Seeds: ["mint.freeze_authority", mint]
 *
 * Used in Freeze and Thaw instructions.
 *
 * @param mint - The mint address
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveFreezeAuthorityPda = ({ mint }: { mint: Address }) => {
  const addressEncoder = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [FREEZE_AUTHORITY_SEED, addressEncoder.encode(mint)],
  });
};

/**
 * Derive Pause Authority PDA
 * Seeds: ["mint.pause_authority", mint]
 *
 * Used in Pause and Resume instructions.
 *
 * @param mint - The mint address
 * @returns Promise resolving to the PDA address and bump
 */
export const derivePauseAuthorityPda = ({ mint }: { mint: Address }) => {
  const addressEncoder = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [PAUSE_AUTHORITY_SEED, addressEncoder.encode(mint)],
  });
};

/**
 * Derive Permanent Delegate PDA
 * Seeds: ["mint.permanent_delegate", mint]
 *
 * Used in Split, Convert, and Claim instructions.
 *
 * @param mint - The mint address
 * @returns Promise resolving to the PDA address and bump
 */
export const derivePermanentDelegatePda = ({ mint }: { mint: Address }) => {
  const addressEncoder = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [PERMANENT_DELEGATE_SEED, addressEncoder.encode(mint)],
  });
};

/**
 * Derive Rate Account PDA
 * Seeds: ["rate", action_id, mint_from, mint_to]
 *
 * Used in CreateRateAccount, UpdateRateAccount, CloseRateAccount, Split, and Convert instructions.
 *
 * @param actionId - The action ID (u64)
 * @param mintFrom - The source mint address
 * @param mintTo - The destination mint address
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveRatePda = ({
  actionId,
  mintFrom,
  mintTo,
}: {
  actionId: bigint;
  mintFrom: Address;
  mintTo: Address;
}) => {
  if (actionId === 0n) {
    throw new Error('action_id must not be 0');
  }
  const addressEncoder = getAddressEncoder();
  const u64Encoder = getU64Encoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      RATE_SEED,
      u64Encoder.encode(actionId),
      addressEncoder.encode(mintFrom),
      addressEncoder.encode(mintTo),
    ],
  });
};

/**
 * Derive Common Action Receipt PDA
 * Seeds: ["receipt", mint, action_id]
 *
 * Used for Split and Convert operations.
 *
 * @param mint - The mint address
 * @param actionId - The action ID (u64)
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveCommonActionReceiptPda = ({
  mint,
  actionId,
}: {
  mint: Address;
  actionId: bigint;
}) => {
  if (actionId === 0n) {
    throw new Error('action_id must not be 0');
  }
  const addressEncoder = getAddressEncoder();
  const u64Encoder = getU64Encoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      RECEIPT_SEED,
      addressEncoder.encode(mint),
      u64Encoder.encode(actionId),
    ],
  });
};

/**
 * Derive Claim Receipt PDA
 * Seeds: ["receipt", mint, token_account, action_id, proof_hash]
 *
 * Used for ClaimDistribution operations. The proof_hash is computed from the merkle proof data.
 *
 * @param mint - The mint address
 * @param tokenAccount - The token account address
 * @param actionId - The action ID (u64)
 * @param proofHash - The 32-byte hash of the merkle proof data
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveClaimReceiptPda = ({
  mint,
  tokenAccount,
  actionId,
  proofHash,
}: {
  mint: Address;
  tokenAccount: Address;
  actionId: bigint;
  proofHash: Uint8Array;
}) => {
  if (actionId === 0n) {
    throw new Error('action_id must not be 0');
  }
  const addressEncoder = getAddressEncoder();
  const u64Encoder = getU64Encoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      RECEIPT_SEED,
      addressEncoder.encode(mint),
      addressEncoder.encode(tokenAccount),
      u64Encoder.encode(actionId),
      proofHash,
    ],
  });
};

/**
 * Derive Proof Account PDA
 * Seeds: ["proof", token_account, action_id]
 *
 * Used in CreateProofAccount, UpdateProofAccount, and ClaimDistribution instructions.
 *
 * @param tokenAccount - The token account address
 * @param actionId - The action ID (u64)
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveProofPda = ({
  tokenAccount,
  actionId,
}: {
  tokenAccount: Address;
  actionId: bigint;
}) => {
  if (actionId === 0n) {
    throw new Error('action_id must not be 0');
  }
  const addressEncoder = getAddressEncoder();
  const u64Encoder = getU64Encoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      PROOF_SEED,
      addressEncoder.encode(tokenAccount),
      u64Encoder.encode(actionId),
    ],
  });
};

/**
 * Derive Distribution Escrow Authority PDA
 * Seeds: ["distribution_escrow_authority", mint, action_id, merkle_root]
 *
 * Used in CreateDistributionEscrow as the authority for the escrow token account.
 *
 * @param mint - The mint address
 * @param actionId - The action ID (u64)
 * @param merkleRoot - The 32-byte merkle tree root
 * @returns Promise resolving to the PDA address and bump
 */
export const deriveDistributionEscrowAuthorityPda = ({
  mint,
  actionId,
  merkleRoot,
}: {
  mint: Address;
  actionId: bigint;
  merkleRoot: Uint8Array;
}) => {
  if (actionId === 0n) {
    throw new Error('action_id must not be 0');
  }
  const addressEncoder = getAddressEncoder();
  const u64Encoder = getU64Encoder();
  return getProgramDerivedAddress({
    programAddress: SECURITY_TOKEN_PROGRAM_PROGRAM_ADDRESS,
    seeds: [
      DISTRIBUTION_ESCROW_AUTHORITY_SEED,
      addressEncoder.encode(mint),
      u64Encoder.encode(actionId),
      merkleRoot,
    ],
  });
};

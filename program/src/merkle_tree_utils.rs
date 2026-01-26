use pinocchio::pubkey::{Pubkey, PUBKEY_BYTES};
use solana_keccak_hasher::hashv;

pub type MerkleTreeRoot = [u8; MERKLE_ROOT_LEN];
pub type MerkleTreeNode = [u8; MERKLE_TREE_NODE_LEN];
pub type ProofNode = MerkleTreeNode;
pub type ProofData = Vec<ProofNode>;

pub const MERKLE_TREE_NODE_LEN: usize = 32;
pub const MERKLE_ROOT_LEN: usize = 32;
/// Maximum number of levels (nodes) in a Merkle proof. 32 levels supports up to 2^32 (~4.3 billion) leaves.
pub const MAX_PROOF_LEVELS: usize = 32;
pub const EMPTY_MERKLE_TREE_NODE: ProofNode = [0u8; MERKLE_TREE_NODE_LEN];
pub const EMPTY_MERKLE_ROOT: MerkleTreeRoot = EMPTY_MERKLE_TREE_NODE;

/// Verifies a Merkle proof for a given leaf node and root
///
/// # Arguments
/// * `node` - The hash of the leaf node being verified
/// * `root` - The Merkle tree root hash
/// * `proof` - Array of sibling hashes forming the proof path
/// * `leaf_index` - The index of the leaf in the tree
///
/// # Returns
/// Returns `true` if the leaf is part of the Merkle tree with the given root, `false` otherwise
pub fn verify_merkle_proof(
    node: &MerkleTreeNode,
    root: &MerkleTreeRoot,
    proof: &ProofData,
    leaf_index: u32,
) -> bool {
    if !proof.is_empty() {
        let levels = proof.len();
        if levels > MAX_PROOF_LEVELS {
            return false;
        }
        let max_leaves = 1u64 << levels;
        if (leaf_index as u64) >= max_leaves {
            return false;
        }
    }

    let mut hash = *node;
    for (i, sibling) in proof.iter().enumerate() {
        if (leaf_index >> i) & 1 == 0 {
            hash = hashv(&[&hash, sibling]).to_bytes();
        } else {
            hash = hashv(&[sibling, &hash]).to_bytes();
        }
    }
    &hash == root
}

/// Creates a hashed leaf node from eligible claimer data
///
/// # Arguments
/// * `eligible_token_account` - Pubkey of the eligible token account
/// * `mint` - Pubkey of the mint
/// * `action_id` - The action identifier
/// * `amount` - Eligible amount to claim
///
/// # Returns
/// Returns `[u8; 32]` representing the leaf node hash
pub fn create_merkle_tree_leaf_node(
    eligible_token_account: &Pubkey,
    mint: &Pubkey,
    action_id: u64,
    amount: u64,
) -> MerkleTreeNode {
    // Capacity: eligible_token_account (32 bytes) + mint (32 bytes) + action_id (8 bytes) + amount (8 bytes)
    let mut bytes = Vec::with_capacity(PUBKEY_BYTES * 2 + 8 + 8);
    bytes.extend_from_slice(eligible_token_account.as_ref());
    bytes.extend_from_slice(mint.as_ref());
    bytes.extend_from_slice(action_id.to_le_bytes().as_ref());
    bytes.extend_from_slice(amount.to_le_bytes().as_ref());

    hashv(&[&bytes]).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{random_32_bytes, random_32_bytes_vec, random_pubkey};
    use rstest::rstest;
    use spl_merkle_tree_reference::MerkleTree;

    #[rstest]
    #[case(random_32_bytes_vec(2))]
    #[case(random_32_bytes_vec(4))]
    #[case(random_32_bytes_vec(8))]
    #[case(random_32_bytes_vec(28))]
    #[case(random_32_bytes_vec(32))]
    #[case(random_32_bytes_vec(44))]
    #[case(random_32_bytes_vec(64))]
    #[case(random_32_bytes_vec(72))]
    #[case(random_32_bytes_vec(86))]
    #[case(random_32_bytes_vec(100))]
    #[case(random_32_bytes_vec(122))]
    fn test_merkle_tree_utils_should_verify_merkle_proof(#[case] leaves: Vec<MerkleTreeNode>) {
        println!("Leaves len: {:?}", leaves.len());
        let merkle_tree = MerkleTree::new(&leaves);
        let root = merkle_tree.root;

        for idx in 0..leaves.len() {
            let node = merkle_tree.get_node(idx);
            assert_eq!(node, leaves[idx]);
            let proof = merkle_tree.get_proof_of_leaf(idx);
            let is_valid = verify_merkle_proof(&node, &root, &proof, idx as u32);
            assert!(is_valid, "Merkle proof should be valid at index {}", idx);
        }
    }

    #[rstest]
    #[case(random_32_bytes_vec(2))]
    #[case(random_32_bytes_vec(4))]
    #[case(random_32_bytes_vec(8))]
    #[case(random_32_bytes_vec(32))]
    #[case(random_32_bytes_vec(64))]
    #[case(random_32_bytes_vec(72))]
    #[case(random_32_bytes_vec(86))]
    #[case(random_32_bytes_vec(100))]
    #[case(random_32_bytes_vec(122))]
    fn test_merkle_tree_utils_should_not_verify_merkle_proof_unsorted(
        #[case] leaves: Vec<MerkleTreeNode>,
    ) {
        println!("Leaves len: {:?}", leaves.len());
        let merkle_tree = MerkleTree::new(&leaves);
        let root = merkle_tree.root;

        for idx in 0..leaves.len() {
            let node = merkle_tree.get_node(idx);
            assert_eq!(node, leaves[idx]);
            let proof = merkle_tree.get_proof_of_leaf(idx);
            // Ensure random leaf is invalid for this proof
            let random_hash = hashv(&[&random_32_bytes()]).to_bytes();
            let invalid_node = leaves.get(idx + 1).unwrap_or(&random_hash);
            let is_valid = verify_merkle_proof(&invalid_node, &root, &proof, idx as u32);
            assert!(
                !is_valid,
                "Merkle proof should not be valid at index {}",
                idx
            );
        }
    }

    #[test]
    fn test_merkle_tree_utils_should_reject_proof_exceeding_max_levels() {
        let node = random_32_bytes();
        let root = random_32_bytes();
        let leaf_index = 0u32;

        // 33 levels - exceeds MAX_PROOF_LEVELS (32)
        let proof_33_levels = random_32_bytes_vec(33);
        assert!(
            !verify_merkle_proof(&node, &root, &proof_33_levels, leaf_index),
            "Proof with 33 levels should be rejected"
        );

        // 64 levels - would overflow even u64
        let proof_64_levels = random_32_bytes_vec(64);
        assert!(
            !verify_merkle_proof(&node, &root, &proof_64_levels, leaf_index),
            "Proof with 64 levels should be rejected"
        );
    }

    #[test]
    fn test_merkle_tree_utils_should_accept_proof_at_max_levels() {
        // 32 levels is the maximum allowed (supports up to 2^32 leaves)
        let node = random_32_bytes();
        let proof_32_levels = random_32_bytes_vec(32);
        let leaf_index = 0u32;

        // Compute expected root by manually hashing through all 32 levels
        let mut expected_root = node;
        for sibling in &proof_32_levels {
            expected_root = hashv(&[&expected_root, sibling]).to_bytes();
        }

        // Verify the proof is accepted and computes correctly when given matching root
        assert!(
            verify_merkle_proof(&node, &expected_root, &proof_32_levels, leaf_index),
            "Proof with 32 levels should be accepted"
        );
    }

    #[test]
    fn test_merkle_tree_utils_should_create_and_verify_leaf_node() {
        let action_id = 42u64;
        let amount = 1000u64;
        let nodes = vec![
            create_merkle_tree_leaf_node(&random_pubkey(), &random_pubkey(), action_id, amount),
            create_merkle_tree_leaf_node(&random_pubkey(), &random_pubkey(), action_id, amount),
            create_merkle_tree_leaf_node(&random_pubkey(), &random_pubkey(), action_id, amount),
        ];
        let merkle_tree = MerkleTree::new(&nodes);
        let root = merkle_tree.root;
        let leaf_index = 1u32;
        let node = nodes[leaf_index as usize];
        let proof = merkle_tree.get_proof_of_leaf(leaf_index as usize);
        let invalid_node =
            create_merkle_tree_leaf_node(&random_pubkey(), &random_pubkey(), action_id, amount);

        assert!(
            !verify_merkle_proof(&invalid_node, &root, &proof, leaf_index),
            "Merkle proof should be invalid for incorrect node"
        );
        assert!(
            !verify_merkle_proof(&node, &root, &proof, 123u32),
            "Merkle proof should be invalid for incorrect leaf index"
        );
        assert!(
            !verify_merkle_proof(&node, &root, &vec![invalid_node], 123u32),
            "Merkle proof should be invalid for incorrect proof"
        );

        assert!(
            verify_merkle_proof(&node, &root, &proof, leaf_index),
            "Merkle proof should be valid"
        );
    }
}

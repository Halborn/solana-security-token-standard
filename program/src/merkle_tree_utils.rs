use solana_keccak_hasher::hashv;

use crate::constants::MERKLE_ROOT_LEN;

pub type MerkleTreeRoot = [u8; MERKLE_ROOT_LEN];

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
    node: &[u8; 32],
    root: &[u8; 32],
    proof: &[[u8; 32]],
    leaf_index: u32,
) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{random_32_bytes, random_32_bytes_vec};
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
    fn test_merkle_tree_utils_should_verify_merkle_proof(#[case] leaves: Vec<[u8; 32]>) {
        println!("Leaves len: {:?}", leaves.len());
        let hashed_leaves = leaves
            .iter()
            .map(|leaf| hashv(&[leaf]).to_bytes())
            .collect::<Vec<[u8; 32]>>();

        let merkle_tree = MerkleTree::new(&hashed_leaves);
        let root = merkle_tree.root;

        for idx in 0..hashed_leaves.len() {
            let node = merkle_tree.get_node(idx);
            assert_eq!(node, hashed_leaves[idx]);
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
        #[case] leaves: Vec<[u8; 32]>,
    ) {
        println!("Leaves len: {:?}", leaves.len());
        let hashed_leaves = leaves
            .iter()
            .map(|leaf| hashv(&[leaf]).to_bytes())
            .collect::<Vec<[u8; 32]>>();

        let merkle_tree = MerkleTree::new(&hashed_leaves);
        let root = merkle_tree.root;

        for idx in 0..hashed_leaves.len() {
            let node = merkle_tree.get_node(idx);
            assert_eq!(node, hashed_leaves[idx]);
            let proof = merkle_tree.get_proof_of_leaf(idx);
            // Ensure random leaf is invalid for this proof
            let random_hash = hashv(&[&random_32_bytes()]).to_bytes();
            let invalid_node = hashed_leaves.get(idx + 1).unwrap_or(&random_hash);

            let is_valid = verify_merkle_proof(&invalid_node, &root, &proof, idx as u32);
            assert!(
                !is_valid,
                "Merkle proof should not be valid at index {}",
                idx
            );
        }
    }
}

use solana_keccak_hasher::hashv;
use solana_pubkey::Pubkey;
use spl_merkle_tree_reference::{MerkleTree, Node};

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug)]
pub struct Leaf {
    pub eligible_token_account: Pubkey, // associated token account of eligible claimer
    pub mint: Pubkey,                   // security mint of the token being claimed
    pub action_id: u64,                 // identifier for the action associated with the claim
    pub amount: u64,                    // amount of tokens being claimed
}

impl Leaf {
    pub fn new(eligible_token_account: Pubkey, mint: Pubkey, action_id: u64, amount: u64) -> Self {
        Self {
            eligible_token_account,
            mint,
            action_id,
            amount,
        }
    }
}

/// Creates a Merkle tree from a list of leaves
pub fn create_merkle_tree(leaves: &[Leaf]) -> MerkleTree {
    let nodes: Vec<Node> = leaves.iter().map(leaf_to_node).collect();
    let merkle_tree = MerkleTree::new(nodes.as_ref());
    merkle_tree
}

/// Retrieves the Merkle root from an existing Merkle tree
pub fn get_merkle_root_from_tree(merkle_tree: &MerkleTree) -> Node {
    merkle_tree.get_root()
}

/// Creates a Merkle tree from leaves and returns the root node
pub fn get_merkle_root_from_leaves(leaves: &[Leaf]) -> Node {
    let merkle_tree = create_merkle_tree(leaves);
    merkle_tree.get_root()
}

/// Retrieves the Merkle proof for a given leaf index
pub fn get_proof_by_index(merkle_tree: &MerkleTree, idx: usize) -> Vec<Node> {
    merkle_tree.get_proof_of_leaf(idx)
}

/// Converts a Leaf struct into a Node for the Merkle tree
fn leaf_to_node(leaf: &Leaf) -> Node {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(leaf.eligible_token_account.as_ref());
    bytes.extend_from_slice(leaf.mint.as_ref());
    bytes.extend_from_slice(&leaf.action_id.to_le_bytes());
    bytes.extend_from_slice(&leaf.amount.to_le_bytes());

    hashv(&[&bytes]).to_bytes()
}

//! M8.3 native Merkle tree using `Rp64_256::merge`.
//!
//! This is the reference implementation. The STARK AIR proves that some
//! sequence of hash operations matches the tree-traversal computation
//! defined here, without revealing which leaf was spent.
//!
//! M8.9 (depth-20 sparse Merkle): the tree is conceptually fixed-depth
//! with 2^TREE_DEPTH leaf slots, but storage is sparse — only populated
//! leaves are stored. Empty subtrees use precomputed "zero subtree
//! hashes" at each level, so neither memory nor construction time scale
//! with 2^DEPTH.
//!
//! This is critical at depth 20: a dense implementation would require
//! 2^20 = 1M zero-digest entries at layer 0 and ~2M hash computations
//! per tree, which is infeasible. Sparse storage keeps everything to
//! O(populated_leaves * depth).

use std::collections::HashMap;

use winter_crypto::hashers::Rp64_256;
use winter_crypto::{Digest, Hasher};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

use super::native::DIGEST_SIZE;

/// Merkle tree depth. Anonymity set capacity = 2^TREE_DEPTH leaves.
///
/// History of this constant:
///   * M8.3 / M8.6 initial: depth 8 (256 leaves)
///   * M8.7 Gap C closure: depth 16 (65,536 leaves)
///   * **M8.9: depth 20 (1,048,576 leaves)** — matches the Tornado Cash
///     reference and lifts the cap to ~1M, well beyond any realistic
///     QChain demo scale.
///
/// Storage cost is O(populated_leaves * depth) thanks to the sparse
/// representation, NOT O(2^depth). Construction is also O(1).
pub const TREE_DEPTH: usize = 20;
pub const NUM_LEAVES: usize = 1 << TREE_DEPTH;

pub type Digest4 = [BaseElement; DIGEST_SIZE];

pub const ZERO_DIGEST: Digest4 = [BaseElement::ZERO; DIGEST_SIZE];

/// Convert Winterfell's ElementDigest into a fixed 4-element array.
fn to_digest4(d: <Rp64_256 as Hasher>::Digest) -> Digest4 {
    d.into()
}

/// Hash a note's contents into a leaf digest.
///
/// `leaf = Rp64_256(sk || r || value || 0 || 0 || 0 || 0 || 0)`
///
/// We use a fixed 3-element preimage (sk, r, value), padded to 8 elements
/// (the full rate width). Padding with zeros after the length prefix is
/// already what `hash_elements` does internally.
pub fn hash_leaf(sk: BaseElement, r: BaseElement, value: BaseElement) -> Digest4 {
    use winter_crypto::ElementHasher;
    let preimage = [sk, r, value];
    to_digest4(Rp64_256::hash_elements(&preimage))
}

/// Compute the nullifier for a spend.
///
/// `nullifier = Rp64_256(sk || leaf_idx || 0 || 0 || 0 || 0 || 0 || 0)`
///
/// Anyone who knows `sk` and `leaf_idx` can compute this. Double-spend
/// detection works because spending the same note twice produces the same
/// nullifier — but observers can't link the nullifier to a leaf without
/// the secret key.
pub fn compute_nullifier(sk: BaseElement, leaf_idx: u64) -> Digest4 {
    use winter_crypto::ElementHasher;
    let preimage = [sk, BaseElement::new(leaf_idx)];
    to_digest4(Rp64_256::hash_elements(&preimage))
}

/// Merge two children into a parent.
///
/// `parent = Rp64_256::merge(left, right)`
pub fn hash_inner(left: Digest4, right: Digest4) -> Digest4 {
    let l = <Rp64_256 as Hasher>::Digest::new(left);
    let r = <Rp64_256 as Hasher>::Digest::new(right);
    to_digest4(<Rp64_256 as Hasher>::merge(&[l, r]))
}

/// Precompute the hash of an all-zero subtree at each level.
///
/// `ZERO_SUBTREE_HASH[0]` is the zero leaf digest.
/// `ZERO_SUBTREE_HASH[k]` is `hash_inner(ZERO_SUBTREE_HASH[k-1], ZERO_SUBTREE_HASH[k-1])`.
///
/// This lets the sparse tree fill in empty siblings during path
/// generation without storing them. Computed once per process via OnceLock
/// (initialized at first MerkleTree construction).
fn zero_subtree_hashes() -> &'static [Digest4; TREE_DEPTH + 1] {
    use std::sync::OnceLock;
    static CACHE: OnceLock<[Digest4; TREE_DEPTH + 1]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut arr = [ZERO_DIGEST; TREE_DEPTH + 1];
        for k in 1..=TREE_DEPTH {
            arr[k] = hash_inner(arr[k - 1], arr[k - 1]);
        }
        arr
    })
}

/// A sparse Merkle tree of fixed depth TREE_DEPTH.
///
/// Conceptually has 2^TREE_DEPTH leaf slots; storage is O(populated).
/// Empty positions return the precomputed zero-subtree hash for their level.
#[derive(Clone)]
pub struct MerkleTree {
    /// Sparse storage: maps (level, index) to digest for every NON-empty node.
    /// Level 0 = leaves; level TREE_DEPTH = root.
    nodes: HashMap<(usize, usize), Digest4>,
    /// How many leaves have been set (used for capacity checks).
    populated_leaf_count: usize,
}

impl MerkleTree {
    /// Build a tree from a list of leaves (leaves go to positions 0..N).
    /// Empty positions remain at their zero-subtree-hash value.
    pub fn from_leaves(leaves: &[Digest4]) -> Self {
        assert!(leaves.len() <= NUM_LEAVES, "too many leaves for depth-{} tree", TREE_DEPTH);
        let mut tree = MerkleTree {
            nodes: HashMap::new(),
            populated_leaf_count: 0,
        };
        for (i, &leaf) in leaves.iter().enumerate() {
            tree.set_leaf(i, leaf);
        }
        tree
    }

    /// Set the leaf at `idx` to `leaf` and propagate updates up to the root.
    pub fn set_leaf(&mut self, idx: usize, leaf: Digest4) {
        assert!(idx < NUM_LEAVES);
        let was_empty = !self.nodes.contains_key(&(0, idx));
        self.nodes.insert((0, idx), leaf);
        if was_empty {
            self.populated_leaf_count += 1;
        }
        // Propagate up to root
        let mut cur_level = 0;
        let mut cur_idx = idx;
        while cur_level < TREE_DEPTH {
            let left_idx = cur_idx & !1;
            let right_idx = left_idx + 1;
            let left = self.get_node(cur_level, left_idx);
            let right = self.get_node(cur_level, right_idx);
            let parent = hash_inner(left, right);
            let parent_level = cur_level + 1;
            let parent_idx = cur_idx / 2;
            self.nodes.insert((parent_level, parent_idx), parent);
            cur_level = parent_level;
            cur_idx = parent_idx;
        }
    }

    /// Get the digest at (level, idx), falling back to the zero-subtree hash
    /// for that level when the position has never been populated.
    fn get_node(&self, level: usize, idx: usize) -> Digest4 {
        self.nodes
            .get(&(level, idx))
            .copied()
            .unwrap_or_else(|| zero_subtree_hashes()[level])
    }

    /// The Merkle root.
    pub fn root(&self) -> Digest4 {
        self.get_node(TREE_DEPTH, 0)
    }

    /// Get the authentication path for leaf at `idx`.
    ///
    /// Returns `TREE_DEPTH` (sibling, direction_bit) pairs from bottom to top.
    /// `direction_bit = 0` means current node is the LEFT child at that level
    ///                   (hash inputs are: current, sibling)
    /// `direction_bit = 1` means current node is the RIGHT child
    ///                   (hash inputs are: sibling, current)
    pub fn auth_path(&self, mut idx: usize) -> Vec<(Digest4, bool)> {
        assert!(idx < NUM_LEAVES);
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for level in 0..TREE_DEPTH {
            let is_right = (idx & 1) == 1;
            let sibling_idx = idx ^ 1;
            path.push((self.get_node(level, sibling_idx), is_right));
            idx /= 2;
        }
        path
    }

    /// Verify a path against the root. Used to test our own logic.
    pub fn verify_path(
        leaf: Digest4,
        path: &[(Digest4, bool)],
        root: Digest4,
    ) -> bool {
        let mut current = leaf;
        for &(sibling, is_right) in path {
            current = if is_right {
                hash_inner(sibling, current)
            } else {
                hash_inner(current, sibling)
            };
        }
        current == root
    }

    /// Number of populated leaves (informational).
    pub fn populated(&self) -> usize {
        self.populated_leaf_count
    }

    /// **Compat shim for existing tests that index `tree.layers[level][idx]`.**
    ///
    /// Returns the value at (level, idx), filling in zeros as needed.
    /// The legacy dense layout exposed `.layers: Vec<Vec<Digest4>>` —
    /// this method preserves call-sites that just want a single node.
    pub fn node_at(&self, level: usize, idx: usize) -> Digest4 {
        self.get_node(level, idx)
    }
}

/// **Compat shim for legacy code that accesses `tree.layers[level][idx]`
/// directly.** Some existing tests built on the dense representation
/// reach into `tree.layers` rather than going through `auth_path`.
/// We expose `.layers` as a method that materializes a slice on demand.
/// Materialization is expensive (O(2^level)) but only used in tests.
///
/// New code should use `node_at(level, idx)` or `auth_path(idx)` instead.
impl MerkleTree {
    /// Materialize layer at `level` into a Vec. **Only call this in tests.**
    /// Allocates O(2^(TREE_DEPTH - level)) entries.
    pub fn layer(&self, level: usize) -> Vec<Digest4> {
        assert!(level <= TREE_DEPTH);
        let size = 1 << (TREE_DEPTH - level);
        let mut out = Vec::with_capacity(size);
        for i in 0..size {
            out.push(self.get_node(level, i));
        }
        out
    }
}

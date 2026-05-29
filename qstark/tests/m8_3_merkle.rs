//! M8.3 native Merkle tree correctness.

use qstark::hash_air::merkle::{
    compute_nullifier, hash_inner, hash_leaf, MerkleTree, NUM_LEAVES, TREE_DEPTH,
    ZERO_DIGEST,
};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

fn make_leaves(n: usize) -> Vec<[BaseElement; 4]> {
    (0..n)
        .map(|i| {
            hash_leaf(
                BaseElement::new(1000 + i as u64),     // sk_i
                BaseElement::new(2000 + i as u64),     // randomness
                BaseElement::new(100 + i as u64),      // value
            )
        })
        .collect()
}

#[test]
fn tree_construction_is_deterministic() {
    let leaves = make_leaves(10);
    let t1 = MerkleTree::from_leaves(&leaves);
    let t2 = MerkleTree::from_leaves(&leaves);
    assert_eq!(t1.root(), t2.root());
}

#[test]
fn empty_tree_has_well_defined_root() {
    let tree = MerkleTree::from_leaves(&[]);
    // root should be H(H(H(...H(0,0)...)))
    let mut current = ZERO_DIGEST;
    for _ in 0..TREE_DEPTH {
        current = hash_inner(current, current);
    }
    assert_eq!(tree.root(), current);
}

#[test]
fn auth_path_verifies_for_every_leaf() {
    let leaves = make_leaves(20);
    let tree = MerkleTree::from_leaves(&leaves);
    let root = tree.root();
    for (idx, &leaf) in leaves.iter().enumerate() {
        let path = tree.auth_path(idx);
        assert_eq!(path.len(), TREE_DEPTH);
        assert!(
            MerkleTree::verify_path(leaf, &path, root),
            "auth path for leaf {} must verify against root", idx
        );
    }
}

#[test]
fn wrong_leaf_does_not_verify() {
    let leaves = make_leaves(10);
    let tree = MerkleTree::from_leaves(&leaves);
    let root = tree.root();
    let path = tree.auth_path(3);
    // Try to claim leaf 3's path with leaf 5's data
    assert!(!MerkleTree::verify_path(leaves[5], &path, root));
}

#[test]
fn wrong_direction_bit_does_not_verify() {
    let leaves = make_leaves(10);
    let tree = MerkleTree::from_leaves(&leaves);
    let root = tree.root();
    let mut path = tree.auth_path(3);
    path[0].1 = !path[0].1;
    assert!(!MerkleTree::verify_path(leaves[3], &path, root));
}

#[test]
fn nullifier_is_deterministic() {
    let sk = BaseElement::new(42);
    let n1 = compute_nullifier(sk, 7);
    let n2 = compute_nullifier(sk, 7);
    assert_eq!(n1, n2);
}

#[test]
fn nullifier_distinguishes_secret_keys() {
    let n1 = compute_nullifier(BaseElement::new(1), 7);
    let n2 = compute_nullifier(BaseElement::new(2), 7);
    assert_ne!(n1, n2);
}

#[test]
fn nullifier_distinguishes_leaf_indices() {
    let sk = BaseElement::new(42);
    let n1 = compute_nullifier(sk, 7);
    let n2 = compute_nullifier(sk, 8);
    assert_ne!(n1, n2);
}

#[test]
fn double_spend_yields_same_nullifier() {
    // The whole point of nullifiers: spending the same note twice produces
    // the same nullifier, so observers can detect double-spend.
    let sk = BaseElement::new(42);
    let idx = 100;
    assert_eq!(compute_nullifier(sk, idx), compute_nullifier(sk, idx));
}

#[test]
fn tree_capacity_matches_depth() {
    assert_eq!(NUM_LEAVES, 1 << TREE_DEPTH);
}

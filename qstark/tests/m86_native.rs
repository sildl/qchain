//! M8.6 native reference tests.

use qstark::hash_air::m86_native::{
    block_output, block_rows, compute_reference, merge_init_state, preimage_init_state,
    M86_MERKLE_DEPTH,
};
use qstark::hash_air::merkle::{hash_inner, hash_leaf, MerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

fn make_leaves(n: usize) -> Vec<[BaseElement; 4]> {
    (0..n).map(|i| hash_leaf(
        BaseElement::new(1000 + i as u64),
        BaseElement::new(2000 + i as u64),
        BaseElement::new(100 + i as u64),
    )).collect()
}

#[test]
fn compute_reference_matches_native_merkle() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);

    for idx in [0usize, 7, 15] {
        let sk = BaseElement::new(1000 + idx as u64);
        let r = BaseElement::new(2000 + idx as u64);
        let v = BaseElement::new(100 + idx as u64);

        let path = tree.auth_path(idx).into_iter().take(M86_MERKLE_DEPTH)
                       .collect::<Vec<_>>();
        let (leaf, root, nullifier) = compute_reference(sk, r, v, &path);

        // Leaf matches direct computation
        assert_eq!(leaf, hash_leaf(sk, r, v));

        // Root matches the level-MERKLE_DEPTH ancestor in the tree
        // (i.e., the actual root). At level MERKLE_DEPTH there's only
        // one node — the root itself.
        assert_eq!(root, tree.root());

        // Nullifier is correctly bound to (sk+1, r, v)
        let expected_nullifier = hash_leaf(sk + BaseElement::ONE, r, v);
        assert_eq!(nullifier, expected_nullifier);
    }
}

#[test]
fn nullifier_differs_from_leaf() {
    let sk = BaseElement::new(42);
    let r = BaseElement::new(100);
    let v = BaseElement::new(50);
    let leaf = hash_leaf(sk, r, v);
    let nullifier = hash_leaf(sk + BaseElement::ONE, r, v);
    assert_ne!(leaf, nullifier);
}

#[test]
fn preimage_block_produces_correct_leaf() {
    let sk = BaseElement::new(123);
    let r = BaseElement::new(456);
    let v = BaseElement::new(789);
    let initial = preimage_init_state(sk, r, v);
    let rows = block_rows(initial);
    let computed = block_output(&rows);
    let expected = hash_leaf(sk, r, v);
    assert_eq!(computed, expected);
}

#[test]
fn merge_block_produces_correct_inner_hash() {
    let left = [BaseElement::new(1), BaseElement::new(2),
                BaseElement::new(3), BaseElement::new(4)];
    let right = [BaseElement::new(5), BaseElement::new(6),
                 BaseElement::new(7), BaseElement::new(8)];
    let initial = merge_init_state(left, right);
    let rows = block_rows(initial);
    let computed = block_output(&rows);
    let expected = hash_inner(left, right);
    assert_eq!(computed, expected);
}

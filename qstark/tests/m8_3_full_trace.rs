//! Verify that our full-trace generator produces a trace whose final block's
//! output equals the actual Merkle root.

use qstark::hash_air::anon_full::{
    build_full_trace, FullMembershipWitness, ACTIVE_ROWS, COL_SIB_START, COL_DIR,
    FULL_TRACE_LEN, MERKLE_DEPTH, ROWS_PER_BLOCK,
};
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::Trace;

fn make_leaves(n: usize) -> Vec<[BaseElement; 4]> {
    (0..n).map(|i| hash_leaf(
        BaseElement::new(1000 + i as u64),
        BaseElement::new(2000 + i as u64),
        BaseElement::new(100 + i as u64),
    )).collect()
}

#[test]
fn full_trace_produces_correct_root() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);

    // Test a few positions to make sure both left-child and right-child cases work
    for &idx in &[0usize, 1, 5, 10, 15] {
        let witness = FullMembershipWitness::from_tree(&tree, idx);
        let trace = build_full_trace(&witness);

        // Extract the computed root from the last hash block's last row
        let last_active = ACTIVE_ROWS - 1;
        let mut computed_root = [BaseElement::ZERO; 4];
        for i in 0..4 {
            computed_root[i] = trace.get(4 + i, last_active);
        }

        // The full Merkle tree has depth TREE_DEPTH (= 20), but this M8.3
        // demo only proves MERKLE_DEPTH (= 4). The "root" we compare against
        // is the level-MERKLE_DEPTH ancestor of leaf `idx` — NOT the
        // full-tree root.
        let target = tree.node_at(MERKLE_DEPTH, idx >> MERKLE_DEPTH);
        assert_eq!(computed_root, target,
                   "trace for leaf {} produced wrong level-{} root", idx, MERKLE_DEPTH);
    }
}

#[test]
fn full_trace_has_correct_dimensions() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 7);
    let trace = build_full_trace(&witness);
    assert_eq!(trace.length(), FULL_TRACE_LEN);
    assert_eq!(trace.width(), 17);
}

#[test]
fn dir_and_sib_columns_are_constant_within_each_block() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 3);
    let trace = build_full_trace(&witness);

    for level in 0..MERKLE_DEPTH {
        let block_start = level * ROWS_PER_BLOCK;
        // Check direction is constant in this block
        let dir_at_start = trace.get(COL_DIR, block_start);
        for row in (block_start + 1)..(block_start + ROWS_PER_BLOCK) {
            assert_eq!(trace.get(COL_DIR, row), dir_at_start,
                       "dir column changes within block {} at row {}", level, row);
        }
        // Check siblings are constant
        for i in 0..4 {
            let s = trace.get(COL_SIB_START + i, block_start);
            for row in (block_start + 1)..(block_start + ROWS_PER_BLOCK) {
                assert_eq!(trace.get(COL_SIB_START + i, row), s);
            }
        }
    }
}

//! M8.6: Native reference for nullifier-bound Merkle membership.
//!
//! The computation we'll prove inside a STARK:
//!
//! Given witness (sk, r, v, leaf_idx, path):
//!   1. leaf = Rp64_256(sk, r, v)
//!   2. walk = leaf, then for each level: walk = merge(walk, sibling) or
//!      merge(sibling, walk) depending on dir bit. Final walk == root.
//!   3. nullifier = Rp64_256(sk+1, r, v)
//!
//! Public outputs: (root, nullifier).
//!
//! This module contains the deterministic reference. The AIR's transition
//! constraints will be checked against this reference both natively (via
//! the diagnostic test) and inside Winterfell.

use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

use super::merkle::{hash_inner, hash_leaf, Digest4};
use super::native::STATE_WIDTH;

pub const ROWS_PER_BLOCK: usize = 8;
pub const NUM_ROUNDS: usize = 7;

/// Trace dimensions for M8.6 + M8.11 + M8.9.
/// (1 input leaf-hash + MERKLE_DEPTH Merkle levels + 1 nullifier-hash
///  + 1 output leaf-hash for the change note) hash blocks.
///
/// M8.7-C bumped depth from 8 → 16.
/// M8.11 Phase 1 added the output leaf-hash block for partial spends.
/// **M8.9 bumped depth from 16 → 20.** Both AIR and the sparse Merkle
/// helper now support up to 2^20 = 1,048,576-note anonymity sets,
/// matching the Tornado Cash reference design.
///
///   depth=4  → 2^4  = 16        notes  ·  64-row trace (legacy)
///   depth=8  → 2^8  = 256       notes  · 128-row trace (legacy)
///   depth=12 → 2^12 = 4,096     notes  · 128-row trace (legacy bench)
///   depth=16 → 2^16 = 65,536    notes  · 256-row trace (M8.7-C)
///   depth=20 → 2^20 = 1,048,576 notes  · 256-row trace (M8.9 shipped)
///
/// CRITICAL: depths 16 AND 20 both fit in a 256-row trace. The active
/// row count grows from 152 to 184 (out of 256), so the polynomial
/// dimensions and FRI parameters are unchanged. This is why depth 20
/// is "free" on the AIR side — no constraint composition changes, no
/// proof size changes, the only cost is the longer trace activity.
pub const M86_MERKLE_DEPTH: usize = 20;
/// 1 (input leaf) + MERKLE_DEPTH (Merkle path) + 1 (nullifier) + 1 (output leaf)
pub const M86_NUM_BLOCKS: usize = 1 + M86_MERKLE_DEPTH + 1 + 1;
pub const M86_ACTIVE_ROWS: usize = M86_NUM_BLOCKS * ROWS_PER_BLOCK;

/// Next power of two ≥ active rows. Hardcoded table so the constant
/// stays a `const usize` (Rust doesn't allow custom const-fn loops in
/// stable for our toolchain version).
pub const M86_TRACE_LEN: usize = m86_trace_len_for_depth(M86_MERKLE_DEPTH);

const fn m86_trace_len_for_depth(depth: usize) -> usize {
    // 1 input leaf + depth Merkle levels + 1 nullifier + 1 output leaf
    let active = (1 + depth + 1 + 1) * ROWS_PER_BLOCK;
    // Next power of 2 ≥ active
    let mut p = 1;
    while p < active {
        p *= 2;
    }
    p
}

// Block kinds (used to drive the AIR's per-block setup):
//   - Block 0:                       PREIMAGE — input is (sk, r, v), length=3
//   - Blocks 1..=M86_MERKLE_DEPTH:   MERGE    — input is (left, right), length=8
//   - Block M86_MERKLE_DEPTH+1:      PREIMAGE — input is (sk+1, r, v), length=3
//   - Block M86_MERKLE_DEPTH+2:      PREIMAGE — input is (sk_out, r_out, v_out)
pub const M86_INIT_BLOCK_INDICES: [usize; 3] = [0, M86_MERKLE_DEPTH + 1, M86_MERKLE_DEPTH + 2];

/// Compute the entire reference for an M8.6 spend.
/// Returns (leaf, root, nullifier) for testing.
pub fn compute_reference(
    sk: BaseElement,
    r: BaseElement,
    v: BaseElement,
    path: &[(Digest4, bool)],
) -> (Digest4, Digest4, Digest4) {
    assert_eq!(path.len(), M86_MERKLE_DEPTH);
    let leaf = hash_leaf(sk, r, v);
    let mut current = leaf;
    for &(sibling, is_right) in path {
        current = if is_right {
            hash_inner(sibling, current)
        } else {
            hash_inner(current, sibling)
        };
    }
    let root = current;
    let nullifier = hash_leaf(sk + BaseElement::ONE, r, v);
    (leaf, root, nullifier)
}

/// Build a 12-element state row for the start of a PREIMAGE block.
/// state = [3, 0, 0, 0, p0, p1, p2, 0, 0, 0, 0, 0]
pub fn preimage_init_state(p0: BaseElement, p1: BaseElement, p2: BaseElement)
    -> [BaseElement; STATE_WIDTH]
{
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[0] = BaseElement::new(3);
    state[4] = p0;
    state[5] = p1;
    state[6] = p2;
    state
}

/// Build a 12-element state row for the start of a MERGE block.
/// state = [8, 0, 0, 0, L0, L1, L2, L3, R0, R1, R2, R3]
pub fn merge_init_state(left: Digest4, right: Digest4)
    -> [BaseElement; STATE_WIDTH]
{
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[0] = BaseElement::new(8);
    for i in 0..4 {
        state[4 + i] = left[i];
        state[8 + i] = right[i];
    }
    state
}

/// Run a single hash block: produces all 8 rows from an initial state.
pub fn block_rows(initial: [BaseElement; STATE_WIDTH])
    -> Vec<[BaseElement; STATE_WIDTH]>
{
    let mut state = initial;
    let mut rows = Vec::with_capacity(ROWS_PER_BLOCK);
    rows.push(state);
    for round in 0..NUM_ROUNDS {
        Rp64_256::apply_round(&mut state, round);
        rows.push(state);
    }
    rows
}

/// Compute the digest at the end of a block (state[4..8] of the last row).
pub fn block_output(rows: &[[BaseElement; STATE_WIDTH]]) -> Digest4 {
    let last = rows.last().expect("non-empty block");
    [last[4], last[5], last[6], last[7]]
}

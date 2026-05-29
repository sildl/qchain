//! M8.6: Nullifier-bound Merkle membership zk-STARK.
//!
//! Closes the M8.5 nullifier-binding gap. Proves, in a single STARK:
//!
//!   1. leaf = H(sk, r, v)
//!   2. leaf is in the Merkle tree with public root R
//!   3. nullifier = H(sk+1, r, v)
//!
//! Public:   (root, nullifier)
//! Witness:  (sk, r, v, leaf_idx, sibling path, direction bits)
//!
//! ## Trace layout (20 columns × 64 rows)
//!
//! Columns:
//!   0..12: Rescue-Prime state
//!   12:    direction bit (Merkle-block scoped; ignored for preimage blocks)
//!   13..17: sibling digest (same)
//!   17:    sk (constant across active trace — witness)
//!   18:    r  (constant across active trace — witness)
//!   19:    v  (constant across active trace — witness)
//!
//! Rows:
//!   0..7   : leaf block (preimage = (sk, r, v))
//!   8..15  : Merkle level 0
//!   16..23 : Merkle level 1
//!   24..31 : Merkle level 2
//!   32..39 : Merkle level 3 (output = root)
//!   40..47 : nullifier block (preimage = (sk+1, r, v))
//!   48..63 : padding
//!
//! ## Constraint groups
//!
//! 1. **Hash round** (12 cs, deg 8): M8.2/M8.3 constraint. Active on
//!    within-block transitions (`is_active * (1 - is_boundary)`).
//!
//! 2. **Merge boundary** (12 cs, deg 4): M8.3's swap-by-dir logic.
//!    Active when `is_boundary * (1 - is_nullifier_boundary)`.
//!    For block transitions 7→8, 15→16, 23→24, 31→32.
//!
//! 3. **Nullifier boundary** (12 cs, deg 3): force next block's state to
//!    (3, 0,0,0, sk+1, r, v, 0,0,0,0,0). Active only at row 39→40.
//!
//! 4. **Direction bit binary** (1 c, deg 2): `dir(dir-1) = 0`.
//!
//! 5. **Within-block static** (5 cs, deg 2): dir + 4 siblings stay
//!    constant within each block.
//!
//! 6. **Global witness static** (3 cs, deg 2): sk, r, v stay constant
//!    across the active trace.
//!
//! Total: 12+12+12+1+5+3 = 45 transition constraints.
//!
//! ## Boundary assertions
//!
//! * Row 0: state[0]=3, state[1..4]=0, state[4]=sk, state[5]=r, state[6]=v,
//!          state[7..12]=0   (leaf block initial state, with sk,r,v from
//!          witness columns 17,18,19 of row 0 — these are equality
//!          constraints between trace cells)
//! * Row 39 (last row of last Merkle block): state[4..8] = public root
//! * Row 47 (last row of nullifier block): state[4..8] = public nullifier

use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::{FieldElement, ToElements};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxTraceRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, ProofOptions, Prover, Serializable, StarkDomain,
    StarkProof, Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use super::m86_native::{
    block_rows, merge_init_state, preimage_init_state, ROWS_PER_BLOCK,
    M86_ACTIVE_ROWS, M86_MERKLE_DEPTH, M86_NUM_BLOCKS, M86_TRACE_LEN,
};
use super::merkle::{Digest4, MerkleTree};
use super::native::{DIGEST_SIZE, NUM_ROUNDS, STATE_WIDTH};

type Felt = BaseElement;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COL_STATE_START: usize = 0;
pub const COL_DIR: usize = 12;
pub const COL_SIB_START: usize = 13;
pub const COL_SK: usize = 17;
pub const COL_R: usize = 18;
pub const COL_V: usize = 19;
// M8.8-A1 Gap A range proof: 64 bit columns at indices 20..84.
// b[i] = (v >> i) & 1. These satisfy:
//   * b[i] * (b[i] - 1) = 0  (binary, on all active rows)
//   * v = Σ b[i] * 2^i at row 0 (decomposition)
// And the public input `unshield_amount + fee` is asserted to equal v.
// Together these enforce 0 ≤ v < 2^64 and bind v to a chain-known amount.
pub const COL_BIT_START: usize = 20;
pub const COL_BIT_END: usize = 84;
pub const NUM_VALUE_BITS: usize = 64;

// M8.11 Phase 1: output (change) note witness columns + bit decomposition.
// The output leaf hash H(sk_out, r_out, v_out) is added to the STARK pool
// when this tx is mined. The chain only sees the hash; the spender retains
// the (sk_out, r_out, v_out) secrets to spend the change note later.
pub const COL_SK_OUT: usize = 84;
pub const COL_R_OUT: usize = 85;
pub const COL_V_OUT: usize = 86;
pub const COL_BIT_OUT_START: usize = 87;
pub const COL_BIT_OUT_END: usize = 151;
pub const M86_WIDTH: usize = 151;

// Block indices.
// Layout (M8.11):
//   block 0:               input leaf hash    (preimage init)
//   blocks 1..=MERKLE_DEPTH:  Merkle path     (merge init)
//   block MERKLE_DEPTH + 1: nullifier hash    (preimage init with sk+1)
//   block MERKLE_DEPTH + 2: output leaf hash  (preimage init with sk_out, r_out, v_out)
// M86_NUM_BLOCKS = MERKLE_DEPTH + 3.
pub const LEAF_BLOCK: usize = 0;
pub const NULLIFIER_BLOCK: usize = M86_MERKLE_DEPTH + 1;
pub const OUTPUT_LEAF_BLOCK: usize = M86_MERKLE_DEPTH + 2;  // = M86_NUM_BLOCKS - 1

// Important row positions (all derived from MERKLE_DEPTH so bumping depth works).
// Root comes out of the last Merkle block, which is block index MERKLE_DEPTH.
// Its last row is (MERKLE_DEPTH + 1) * 8 - 1.
pub const ROOT_ROW: usize = (M86_MERKLE_DEPTH + 1) * ROWS_PER_BLOCK - 1;
// Transition into the nullifier block: row (NULLIFIER_BLOCK * 8 - 1) → next.
pub const NULLIFIER_BOUNDARY_ROW: usize = NULLIFIER_BLOCK * ROWS_PER_BLOCK - 1;
// Last row of the nullifier block (where the nullifier digest sits in state[4..8]).
pub const NULLIFIER_LAST_ROW: usize = (NULLIFIER_BLOCK + 1) * ROWS_PER_BLOCK - 1;
// M8.11: transition INTO the output leaf block.
pub const OUTPUT_BOUNDARY_ROW: usize = OUTPUT_LEAF_BLOCK * ROWS_PER_BLOCK - 1;
// Last row of the output leaf block (where the output leaf digest sits in state[4..8]).
pub const OUTPUT_LEAF_LAST_ROW: usize = M86_ACTIVE_ROWS - 1;

// ---------------------------------------------------------------------------
// Public inputs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct M86Inputs {
    pub root: Digest4,
    pub nullifier: Digest4,
    /// M8.8-A1: declared unshield amount. Bound to leaf value via range proof.
    /// Must be a non-negative u64 < 2^64.
    pub unshield_amount: u64,
    /// M8.8-A1: declared fee. Bound to leaf value via range proof.
    /// `unshield_amount + fee + v_out == v_in` is enforced at row 0.
    pub fee: u64,
    /// M8.11 Phase 1: hash of the output (change) note. The chain appends
    /// this to the STARK pool when the tx is mined. The proof attests
    /// `output_leaf == H(sk_out, r_out, v_out)` for some spender-chosen
    /// preimage, with `v_out` range-proved.
    pub output_leaf: Digest4,
}

impl ToElements<Felt> for M86Inputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut v = Vec::with_capacity(14);
        v.extend_from_slice(&self.root);
        v.extend_from_slice(&self.nullifier);
        v.push(Felt::new(self.unshield_amount));
        v.push(Felt::new(self.fee));
        v.extend_from_slice(&self.output_leaf);
        v
    }
}

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct M86Witness {
    pub sk: Felt,
    pub r: Felt,
    pub v: Felt,
    /// (sibling, is_right) per Merkle level, bottom-up.
    pub path: Vec<(Digest4, bool)>,
    /// M8.8-A1: declared unshield amount. Must satisfy
    /// `unshield_amount + fee + v_out == v` (field arithmetic).
    pub unshield_amount: u64,
    /// M8.8-A1: declared fee.
    pub fee: u64,
    /// M8.11: change-note secret key (spender chooses freely).
    pub sk_out: Felt,
    /// M8.11: change-note blinding randomness.
    pub r_out: Felt,
    /// M8.11: change-note value. Must satisfy
    /// `v.as_int() == unshield_amount + fee + v_out.as_int()` exactly.
    /// Setting `v_out = 0` recovers the M8.8-A1 full-spend behavior.
    pub v_out: Felt,
}

impl M86Witness {
    /// Convenience: build a witness from a real Merkle tree at a given leaf index.
    /// Caller must ensure leaves[idx] = hash_leaf(sk, r, v).
    /// Convenience: build a witness from a real Merkle tree at a given leaf index.
    /// Caller must ensure leaves[idx] = hash_leaf(sk, r, v).
    /// M8.8-A1: requires `unshield_amount + fee + v_out == v.as_int()` exactly.
    /// M8.11: caller picks (sk_out, r_out, v_out) for the change note.
    /// Pass `v_out = 0` (with matching zero sk_out, r_out OK) to recover the
    /// "full spend with no change" pattern from M8.8-A1.
    pub fn from_tree(
        sk: Felt, r: Felt, v: Felt,
        tree: &MerkleTree, idx: usize,
        unshield_amount: u64, fee: u64,
        sk_out: Felt, r_out: Felt, v_out: Felt,
    ) -> Self {
        let full_path = tree.auth_path(idx);
        let path: Vec<_> = full_path.into_iter().take(M86_MERKLE_DEPTH).collect();
        M86Witness {
            sk, r, v, path, unshield_amount, fee,
            sk_out, r_out, v_out,
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

pub fn build_m86_trace(w: &M86Witness) -> TraceTable<Felt> {
    assert_eq!(w.path.len(), M86_MERKLE_DEPTH);

    // M8.8-A1 + M8.11: range-proof witness sanity. v and v_out must be valid
    // u64-representable field elements. The AIR's bit-decomposition enforces
    // this; we catch programmer errors early.
    let v_int = w.v.as_int();
    assert!(
        Felt::new(v_int) == w.v,
        "value witness v must be canonical < 2^64"
    );
    let v_out_int = w.v_out.as_int();
    assert!(
        Felt::new(v_out_int) == w.v_out,
        "change-note value witness v_out must be canonical < 2^64"
    );
    // M8.11: declared (unshield_amount, fee, v_out) must sum to v in field
    // arithmetic. The AIR's row-0 value-conservation constraint enforces
    // this — failing here saves the wasted proving cycle.
    let expected_sum = Felt::new(w.unshield_amount) + Felt::new(w.fee) + w.v_out;
    assert_eq!(
        w.v, expected_sum,
        "witness inconsistency: v != unshield_amount + fee + v_out \
         (v={}, amount={}, fee={}, v_out={})",
        v_int, w.unshield_amount, w.fee, v_out_int
    );

    // 1. Leaf block: preimage = (sk, r, v)
    let mut all_state_rows: Vec<[Felt; STATE_WIDTH]> = Vec::with_capacity(M86_TRACE_LEN);
    let leaf_initial = preimage_init_state(w.sk, w.r, w.v);
    let leaf_block = block_rows(leaf_initial);
    let leaf_digest: Digest4 = [
        leaf_block[ROWS_PER_BLOCK - 1][4],
        leaf_block[ROWS_PER_BLOCK - 1][5],
        leaf_block[ROWS_PER_BLOCK - 1][6],
        leaf_block[ROWS_PER_BLOCK - 1][7],
    ];
    all_state_rows.extend_from_slice(&leaf_block);

    // 2. Merkle blocks
    let mut current = leaf_digest;
    let mut merkle_block_dirs_and_sibs: Vec<(bool, Digest4)> = Vec::new();
    for level in 0..M86_MERKLE_DEPTH {
        let (sibling, is_right) = w.path[level];
        merkle_block_dirs_and_sibs.push((is_right, sibling));
        let (left, right) = if is_right { (sibling, current) } else { (current, sibling) };
        let merge_initial = merge_init_state(left, right);
        let merge_block = block_rows(merge_initial);
        let block_out: Digest4 = [
            merge_block[ROWS_PER_BLOCK - 1][4],
            merge_block[ROWS_PER_BLOCK - 1][5],
            merge_block[ROWS_PER_BLOCK - 1][6],
            merge_block[ROWS_PER_BLOCK - 1][7],
        ];
        all_state_rows.extend_from_slice(&merge_block);
        current = block_out;
    }
    // `current` is now the root.

    // 3. Nullifier block: preimage = (sk+1, r, v)
    let null_initial = preimage_init_state(w.sk + Felt::ONE, w.r, w.v);
    let null_block = block_rows(null_initial);
    all_state_rows.extend_from_slice(&null_block);

    // 4. M8.11 Phase 1: Output leaf block: preimage = (sk_out, r_out, v_out).
    // The block_rows function computes the Rescue-Prime hash, and its
    // state[4..8] at the last row IS the output leaf digest — the public
    // value the chain commits to.
    let out_initial = preimage_init_state(w.sk_out, w.r_out, w.v_out);
    let out_block = block_rows(out_initial);
    all_state_rows.extend_from_slice(&out_block);

    assert_eq!(all_state_rows.len(), M86_ACTIVE_ROWS);

    // 4. Pad to M86_TRACE_LEN
    let pad_template = *all_state_rows.last().unwrap();
    while all_state_rows.len() < M86_TRACE_LEN {
        all_state_rows.push(pad_template);
    }

    // 5. Build the wide trace (20 columns)
    //    For each row, fill state cols (0..12), then dir + sibs (12..17),
    //    then sk, r, v (17, 18, 19).
    let mut wide: Vec<[Felt; M86_WIDTH]> = Vec::with_capacity(M86_TRACE_LEN);
    for (row_idx, state) in all_state_rows.iter().enumerate() {
        let mut row = [Felt::ZERO; M86_WIDTH];
        // State
        for j in 0..STATE_WIDTH { row[j] = state[j]; }
        // Determine which block we're in
        let block_idx = row_idx / ROWS_PER_BLOCK;
        // Dir / sibs: only meaningful for Merkle blocks (1..=MERKLE_DEPTH)
        if block_idx >= 1 && block_idx <= M86_MERKLE_DEPTH {
            let level = block_idx - 1;
            let (is_right, sibling) = merkle_block_dirs_and_sibs[level];
            row[COL_DIR] = if is_right { Felt::ONE } else { Felt::ZERO };
            for i in 0..DIGEST_SIZE { row[COL_SIB_START + i] = sibling[i]; }
        } else if row_idx < M86_ACTIVE_ROWS {
            // For leaf and nullifier blocks: dir=0, sib=0 (don't care, but
            // must be constant within block to satisfy static constraints)
            row[COL_DIR] = Felt::ZERO;
            // sibs already zero from initialization
        } else {
            // Padding: copy from the last active row
            let last_active = &wide[M86_ACTIVE_ROWS - 1];
            row[COL_DIR] = last_active[COL_DIR];
            for i in 0..DIGEST_SIZE {
                row[COL_SIB_START + i] = last_active[COL_SIB_START + i];
            }
        }
        // sk, r, v constant across active trace; carry through padding too
        row[COL_SK] = w.sk;
        row[COL_R] = w.r;
        row[COL_V] = w.v;

        // M8.8-A1: bit decomposition of v. Same on every row — these are
        // constant witness columns. The decomposition constraint at row 0
        // and the binary constraint on every active row pin them down.
        let v_u64: u64 = w.v.as_int();
        for i in 0..NUM_VALUE_BITS {
            let bit = (v_u64 >> i) & 1;
            row[COL_BIT_START + i] = Felt::new(bit);
        }

        // M8.11: output (change) note witness — also constant across the trace.
        // The output leaf-block-init constraint at row OUTPUT_BOUNDARY_ROW pins
        // state[4..7] at that transition to these witness values.
        row[COL_SK_OUT] = w.sk_out;
        row[COL_R_OUT] = w.r_out;
        row[COL_V_OUT] = w.v_out;
        let v_out_u64: u64 = w.v_out.as_int();
        for i in 0..NUM_VALUE_BITS {
            let bit = (v_out_u64 >> i) & 1;
            row[COL_BIT_OUT_START + i] = Felt::new(bit);
        }

        wide.push(row);
    }

    let mut trace = TraceTable::new(M86_WIDTH, M86_TRACE_LEN);
    trace.fill(
        |state| { state.copy_from_slice(&wide[0]); },
        |step, state| { state.copy_from_slice(&wide[step + 1]); },
    );
    trace
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub struct M86Air {
    context: AirContext<Felt>,
    root: Digest4,
    nullifier: Digest4,
    /// M8.11: hash of the change note H(sk_out, r_out, v_out).
    /// Asserted to match state[4..8] at OUTPUT_LEAF_LAST_ROW.
    output_leaf: Digest4,
    /// M8.8-A1: `unshield_amount + fee` as a field element. Used in the
    /// value-conservation transition constraint at row 0:
    ///   state[6] at row 0 (= v_in) == amount_plus_fee + COL_V_OUT.
    /// Combined with bit-decomposition + binary constraints on both v and
    /// v_out, this binds v_in to (unshield + fee + v_out) with full range
    /// proofs on the input value and the change value.
    amount_plus_fee: Felt,
}

impl Air for M86Air {
    type BaseField = Felt;
    type PublicInputs = M86Inputs;

    fn new(trace_info: TraceInfo, pub_inputs: M86Inputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), M86_WIDTH);
        assert_eq!(trace_info.length(), M86_TRACE_LEN);

        let cycle_8 = ROWS_PER_BLOCK;        // 8
        let cycle_full = M86_TRACE_LEN;       // 256 at depth 16

        let mut degrees = Vec::new();
        // Group 1: Hash round (12 cs, base 7, cycles [full, 8])
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(7, vec![cycle_full, cycle_8]));
        }
        // Group 2: Merge boundary (12 cs, base 2)
        // M8.11: gated by (1 - is_nullifier_boundary) AND (1 - is_output_boundary),
        // so it needs two extra cycle_full factors compared to M8.6.
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2, vec![cycle_full, cycle_8, cycle_full, cycle_full],
            ));
        }
        // Group 3: Nullifier boundary (12 cs, base 1, cycles [full, 8, full])
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full, cycle_8, cycle_full]));
        }
        // M8.11 Group 3.5: Output-leaf boundary (12 cs, base 1, cycles [full, 8, full])
        // Mirrors Group 3 but uses is_output_boundary instead of is_nullifier_boundary.
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full, cycle_8, cycle_full]));
        }
        // Group 4: Dir binary (1 c, base 2, cycles [full])
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![cycle_full]));
        // Group 5: Within-block static (5 cs, base 1, cycles [full, 8])
        for _ in 0..5 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full, cycle_8]));
        }
        // Group 6: Global witness static (6 cs, base 1, cycles [full])
        // M8.11: extended from 3 → 6 to also pin sk_out, r_out, v_out as static.
        for _ in 0..6 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full]));
        }
        // Group 7: Leaf-block binding (3 cs, base 1, cycles [full])
        // At row 0 only, enforces state[4..7] = (sk, r, v) from witness cols.
        // The OUTPUT leaf block doesn't need a separate Group 7 binding —
        // Group 3.5 already pins state[4..7] at OUTPUT_BOUNDARY_ROW+1 to
        // (sk_out, r_out, v_out) via the boundary constraints.
        for _ in 0..3 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full]));
        }
        // M8.8-A1 Group 8: Bit binary, extended in M8.11
        // 64 for v_in bits + 64 for v_out bits, all gated by is_active.
        for _ in 0..(2 * NUM_VALUE_BITS) {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![cycle_full]));
        }
        // M8.8-A1 Group 9: Value decomposition (2 cs)
        // 1 for v_in decomp at row 0, 1 for v_out decomp at row 0.
        for _ in 0..2 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full]));
        }
        // M8.11 Group 10: Value conservation (1 c, base 1, cycles [full])
        // At row 0: v_in - v_out - amount_plus_fee == 0 (field arithmetic).
        // Combined with G8+G9 range proofs on v_in AND v_out, the chain's
        // u64-overflow defense, and Fiat-Shamir over public inputs, this
        // binds the spend value to (amount + fee + change_value) cleanly.
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full]));
        // Total: 12 + 12 + 12 + 12 + 1 + 5 + 6 + 3 + 128 + 2 + 1 = 194

        // Assertions:
        //   4 capacity (state[0..4] at row 0)
        //   4 root (state[4..8] at ROOT_ROW)
        //   4 nullifier (state[4..8] at NULLIFIER_LAST_ROW)
        //   4 output leaf (state[4..8] at OUTPUT_LEAF_LAST_ROW)  ← M8.11
        // = 16 assertions. The M8.8-A1 amount-sum assertion is REMOVED and
        // replaced by Group 10 transition constraint (which is more
        // expressive since it can reference cell-minus-cell).
        let num_assertions = 4 + 4 + 4 + 4;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        let amount_plus_fee = Felt::new(pub_inputs.unshield_amount) + Felt::new(pub_inputs.fee);
        M86Air {
            context,
            root: pub_inputs.root,
            nullifier: pub_inputs.nullifier,
            output_leaf: pub_inputs.output_leaf,
            amount_plus_fee,
        }
    }

    fn context(&self) -> &AirContext<Felt> { &self.context }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns: Vec<Vec<Felt>> = Vec::new();

        // ARK1, ARK2 (24 cols, period 8)
        for slot in 0..(2 * STATE_WIDTH) {
            let mut col = vec![Felt::ZERO; ROWS_PER_BLOCK];
            for round in 0..NUM_ROUNDS {
                if slot < STATE_WIDTH {
                    col[round] = Rp64_256::ARK1[round][slot];
                } else {
                    col[round] = Rp64_256::ARK2[round][slot - STATE_WIDTH];
                }
            }
            columns.push(col);
        }

        // is_boundary: 1 at row 7-mod-8, period 8
        let mut is_boundary = vec![Felt::ZERO; ROWS_PER_BLOCK];
        is_boundary[ROWS_PER_BLOCK - 1] = Felt::ONE;
        columns.push(is_boundary);

        // is_active: 1 for rows 0..M86_ACTIVE_ROWS-1, 0 else
        // (Gates off the transition out of the last active row.)
        let mut is_active = vec![Felt::ZERO; M86_TRACE_LEN];
        for i in 0..(M86_ACTIVE_ROWS - 1) {
            is_active[i] = Felt::ONE;
        }
        columns.push(is_active);

        // is_nullifier_boundary: 1 at NULLIFIER_BOUNDARY_ROW, 0 else
        let mut is_nb = vec![Felt::ZERO; M86_TRACE_LEN];
        is_nb[NULLIFIER_BOUNDARY_ROW] = Felt::ONE;
        columns.push(is_nb);

        // is_row_0: 1 at row 0, 0 else
        let mut is_row_0 = vec![Felt::ZERO; M86_TRACE_LEN];
        is_row_0[0] = Felt::ONE;
        columns.push(is_row_0);

        // M8.11: is_output_boundary: 1 at OUTPUT_BOUNDARY_ROW, 0 else.
        // Drives the output-leaf init group (mirrors is_nullifier_boundary).
        // Also added as a factor to merge-boundary gating so the merge
        // constraint group doesn't accidentally fire at the output transition.
        let mut is_ob = vec![Felt::ZERO; M86_TRACE_LEN];
        is_ob[OUTPUT_BOUNDARY_ROW] = Felt::ONE;
        columns.push(is_ob);

        columns
    }

    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic: &[E],
        result: &mut [E],
    ) {
        let curr = frame.current();
        let next = frame.next();

        let ark1 = &periodic[0..STATE_WIDTH];
        let ark2 = &periodic[STATE_WIDTH..2 * STATE_WIDTH];
        let is_boundary = periodic[2 * STATE_WIDTH];
        let is_active = periodic[2 * STATE_WIDTH + 1];
        let is_nullifier_boundary = periodic[2 * STATE_WIDTH + 2];
        let is_row_0 = periodic[2 * STATE_WIDTH + 3];
        // M8.11: new periodic. Fires at OUTPUT_BOUNDARY_ROW (= 143 at depth 16).
        let is_output_boundary = periodic[2 * STATE_WIDTH + 4];

        let one = E::ONE;
        let active_round = is_active * (one - is_boundary);
        // M8.11: merge boundary must NOT fire at the nullifier OR the
        // output-leaf transitions.
        let active_merge_boundary =
            is_active * is_boundary * (one - is_nullifier_boundary) * (one - is_output_boundary);
        let active_nullifier_boundary = is_active * is_boundary * is_nullifier_boundary;
        let active_output_boundary = is_active * is_boundary * is_output_boundary;

        // ----- Group 1: Hash round (12 cs) — UNCHANGED -----
        let mut curr_sbox = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            let c2 = curr[i].square();
            let c4 = c2.square();
            curr_sbox[i] = c4 * c2 * curr[i];
        }
        let mut rhs = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                rhs[i] += E::from(Rp64_256::MDS[i][j]) * curr_sbox[j];
            }
            rhs[i] += ark1[i];
        }
        let mut e_vec = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            e_vec[i] = next[i] - ark2[i];
        }
        let mut d_vec = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                d_vec[i] += E::from(Rp64_256::INV_MDS[i][j]) * e_vec[j];
            }
        }
        let mut lhs = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            let d2 = d_vec[i].square();
            let d4 = d2.square();
            lhs[i] = d4 * d2 * d_vec[i];
        }
        for i in 0..STATE_WIDTH {
            result[i] = active_round * (lhs[i] - rhs[i]);
        }

        // ----- Group 2: Merge boundary (12 cs) — gating updated for M8.11 -----
        let dir_next = next[COL_DIR];
        let sib_next = [
            next[COL_SIB_START], next[COL_SIB_START + 1],
            next[COL_SIB_START + 2], next[COL_SIB_START + 3],
        ];
        let prev_output = [curr[4], curr[5], curr[6], curr[7]];

        let mut merge_res = [E::ZERO; STATE_WIDTH];
        merge_res[0] = next[0] - E::from(Felt::new(8));
        merge_res[1] = next[1];
        merge_res[2] = next[2];
        merge_res[3] = next[3];
        for i in 0..4 {
            let target_left = (one - dir_next) * prev_output[i] + dir_next * sib_next[i];
            let target_right = dir_next * prev_output[i] + (one - dir_next) * sib_next[i];
            merge_res[4 + i] = next[4 + i] - target_left;
            merge_res[8 + i] = next[8 + i] - target_right;
        }
        for i in 0..STATE_WIDTH {
            result[STATE_WIDTH + i] = active_merge_boundary * merge_res[i];
        }

        // ----- Group 3: Nullifier boundary (12 cs) — UNCHANGED -----
        let sk_next = next[COL_SK];
        let r_next = next[COL_R];
        let v_next = next[COL_V];

        let mut null_res = [E::ZERO; STATE_WIDTH];
        null_res[0] = next[0] - E::from(Felt::new(3));
        null_res[1] = next[1];
        null_res[2] = next[2];
        null_res[3] = next[3];
        null_res[4] = next[4] - (sk_next + one);
        null_res[5] = next[5] - r_next;
        null_res[6] = next[6] - v_next;
        null_res[7] = next[7];
        null_res[8] = next[8];
        null_res[9] = next[9];
        null_res[10] = next[10];
        null_res[11] = next[11];
        for i in 0..STATE_WIDTH {
            result[2 * STATE_WIDTH + i] = active_nullifier_boundary * null_res[i];
        }

        // ----- M8.11 Group 3.5: Output-leaf boundary (12 cs) -----
        // At row OUTPUT_BOUNDARY_ROW → OUTPUT_BOUNDARY_ROW + 1: next state
        // must be (3, 0, 0, 0, sk_out, r_out, v_out, 0, 0, 0, 0, 0).
        // Mirrors the nullifier-boundary group exactly, but reads the output
        // witness columns instead.
        let sk_out_next = next[COL_SK_OUT];
        let r_out_next = next[COL_R_OUT];
        let v_out_next = next[COL_V_OUT];
        let mut out_res = [E::ZERO; STATE_WIDTH];
        out_res[0] = next[0] - E::from(Felt::new(3));
        out_res[1] = next[1];
        out_res[2] = next[2];
        out_res[3] = next[3];
        out_res[4] = next[4] - sk_out_next;
        out_res[5] = next[5] - r_out_next;
        out_res[6] = next[6] - v_out_next;
        out_res[7] = next[7];
        out_res[8] = next[8];
        out_res[9] = next[9];
        out_res[10] = next[10];
        out_res[11] = next[11];
        for i in 0..STATE_WIDTH {
            result[3 * STATE_WIDTH + i] = active_output_boundary * out_res[i];
        }
        // Offsets after Group 3.5: result[4*STATE_WIDTH] = result[48] is next.

        // ----- Group 4: Dir binary (1 c) -----
        let dir_curr = curr[COL_DIR];
        result[4 * STATE_WIDTH] = is_active * (dir_curr * (dir_curr - one));

        // ----- Group 5: Within-block static (5 cs) -----
        let static_cols = [
            COL_DIR,
            COL_SIB_START,
            COL_SIB_START + 1,
            COL_SIB_START + 2,
            COL_SIB_START + 3,
        ];
        for (k, &col) in static_cols.iter().enumerate() {
            result[4 * STATE_WIDTH + 1 + k] = active_round * (next[col] - curr[col]);
        }

        // ----- Group 6: Global witness static (6 cs) -----
        // sk, r, v, sk_out, r_out, v_out must stay constant across active trace.
        let g6_offset = 4 * STATE_WIDTH + 6;  // = 54
        result[g6_offset    ] = is_active * (next[COL_SK]     - curr[COL_SK]);
        result[g6_offset + 1] = is_active * (next[COL_R]      - curr[COL_R]);
        result[g6_offset + 2] = is_active * (next[COL_V]      - curr[COL_V]);
        result[g6_offset + 3] = is_active * (next[COL_SK_OUT] - curr[COL_SK_OUT]);
        result[g6_offset + 4] = is_active * (next[COL_R_OUT]  - curr[COL_R_OUT]);
        result[g6_offset + 5] = is_active * (next[COL_V_OUT]  - curr[COL_V_OUT]);

        // ----- Group 7: Leaf-block binding (3 cs) — UNCHANGED -----
        // At row 0 only: state[4..7] at row 0 must equal (sk, r, v) from
        // witness cols. The output-block binding is handled by Group 3.5.
        let g7_offset = g6_offset + 6;  // = 60
        result[g7_offset    ] = is_row_0 * (curr[4] - curr[COL_SK]);
        result[g7_offset + 1] = is_row_0 * (curr[5] - curr[COL_R]);
        result[g7_offset + 2] = is_row_0 * (curr[6] - curr[COL_V]);

        // ----- M8.8-A1 Group 8: Bit binary (128 cs) -----
        // Each bit column (v_in bits + v_out bits) ∈ {0, 1} on every active row.
        let g8_offset = g7_offset + 3;  // = 63
        for i in 0..NUM_VALUE_BITS {
            let b = curr[COL_BIT_START + i];
            result[g8_offset + i] = is_active * b * (b - one);
        }
        for i in 0..NUM_VALUE_BITS {
            let b = curr[COL_BIT_OUT_START + i];
            result[g8_offset + NUM_VALUE_BITS + i] = is_active * b * (b - one);
        }

        // ----- M8.8-A1 Group 9: Value decomposition (2 cs) -----
        // At row 0: v_in == Σ b_in[i] * 2^i  AND  v_out == Σ b_out[i] * 2^i.
        let g9_offset = g8_offset + 2 * NUM_VALUE_BITS;  // = 191
        let mut v_in_sum = E::ZERO;
        let mut v_out_sum = E::ZERO;
        let mut pow = E::ONE;
        let two = one + one;
        for i in 0..NUM_VALUE_BITS {
            v_in_sum  += curr[COL_BIT_START + i] * pow;
            v_out_sum += curr[COL_BIT_OUT_START + i] * pow;
            pow *= two;
        }
        result[g9_offset    ] = is_row_0 * (curr[COL_V]     - v_in_sum);
        result[g9_offset + 1] = is_row_0 * (curr[COL_V_OUT] - v_out_sum);

        // ----- M8.11 Group 10: Value conservation (1 c) -----
        // At row 0: v_in == amount_plus_fee + v_out.
        // Equivalently: v_in - v_out - amount_plus_fee == 0.
        // The chain enforces no u64-overflow on (amount + fee + v_out) at
        // construction; combined with G8+G9 ranges on v_in and v_out, this
        // proves full value conservation in u64 arithmetic.
        let g10_offset = g9_offset + 2;  // = 193
        let apf: E = E::from(self.amount_plus_fee);
        result[g10_offset] = is_row_0 * (curr[COL_V] - curr[COL_V_OUT] - apf);
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = Vec::new();
        // Row 0 capacity portion: state[0] = 3, state[1..4] = 0
        assertions.push(Assertion::single(0, 0, Felt::new(3)));
        assertions.push(Assertion::single(1, 0, Felt::ZERO));
        assertions.push(Assertion::single(2, 0, Felt::ZERO));
        assertions.push(Assertion::single(3, 0, Felt::ZERO));
        // Root at end of last Merkle block (row 39): state[4..8]
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(4 + i, ROOT_ROW, self.root[i]));
        }
        // Nullifier at the last row of the nullifier block: state[4..8]
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(4 + i, NULLIFIER_LAST_ROW, self.nullifier[i]));
        }
        // M8.11: Output leaf hash at the last row of the output block.
        // This is the new shielded note H(sk_out, r_out, v_out) that the
        // chain will append to the STARK pool when the tx is mined.
        // The M8.8-A1 amount-sum assertion (state[6] at row 0 == amount + fee)
        // is REMOVED — replaced by Group 10 transition constraint, which is
        // more expressive since it can reference state[6] minus state[COL_V_OUT].
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(4 + i, OUTPUT_LEAF_LAST_ROW, self.output_leaf[i]));
        }
        assertions
    }
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

pub struct M86Prover {
    options: ProofOptions,
    witness: M86Witness,
}

impl M86Prover {
    pub fn new(options: ProofOptions, witness: M86Witness) -> Self {
        Self { options, witness }
    }

    pub fn build_trace(&self) -> TraceTable<Felt> {
        build_m86_trace(&self.witness)
    }
}

impl Prover for M86Prover {
    type BaseField = Felt;
    type Air = M86Air;
    type Trace = TraceTable<Felt>;
    type HashFn = Blake3_256<Felt>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, M86Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> M86Inputs {
        let mut root = [Felt::ZERO; DIGEST_SIZE];
        let mut nullifier = [Felt::ZERO; DIGEST_SIZE];
        let mut output_leaf = [Felt::ZERO; DIGEST_SIZE];
        for i in 0..DIGEST_SIZE {
            root[i] = trace.get(4 + i, ROOT_ROW);
            nullifier[i] = trace.get(4 + i, NULLIFIER_LAST_ROW);
            output_leaf[i] = trace.get(4 + i, OUTPUT_LEAF_LAST_ROW);
        }
        M86Inputs {
            root,
            nullifier,
            unshield_amount: self.witness.unshield_amount,
            fee: self.witness.fee,
            output_leaf,
        }
    }

    fn options(&self) -> &ProofOptions { &self.options }

    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a M86Air,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ---------------------------------------------------------------------------
// High-level API
// ---------------------------------------------------------------------------

pub fn default_options() -> ProofOptions {
    // Degree-8 constraints need blowup factor ≥ 16
    ProofOptions::new(54, 16, 0, FieldExtension::None, 8, 31)
}

pub fn prove_m86(witness: M86Witness) -> Result<(Vec<u8>, M86Inputs), String> {
    let prover = M86Prover::new(default_options(), witness);
    let trace = prover.build_trace();
    let pub_inputs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).map_err(|e| format!("prove failed: {}", e))?;
    let mut bytes = Vec::new();
    proof.write_into(&mut bytes);
    Ok((bytes, pub_inputs))
}

pub fn verify_m86(proof_bytes: &[u8], pub_inputs: M86Inputs) -> Result<(), String> {
    let proof = StarkProof::from_bytes(proof_bytes)
        .map_err(|e| format!("deserialize failed: {}", e))?;
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(50);
    winterfell::verify::<M86Air, Blake3_256<Felt>, DefaultRandomCoin<Blake3_256<Felt>>>(
        proof, pub_inputs, &min_opts
    ).map_err(|e| format!("verification failed: {}", e))
}

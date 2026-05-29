//! M8.6 constraint diagnostic.
//! Manually evaluates each constraint at each row of an honest trace.
//! Must report zero violations BEFORE we try to run Winterfell on it.

use qstark::hash_air::m86_air::{
    build_m86_trace, M86Witness,
    COL_BIT_OUT_START, COL_BIT_START, COL_DIR, COL_R, COL_R_OUT, COL_SIB_START,
    COL_SK, COL_SK_OUT, COL_V, COL_V_OUT,
    M86_WIDTH, NULLIFIER_BOUNDARY_ROW, NULLIFIER_LAST_ROW, NUM_VALUE_BITS,
    OUTPUT_BOUNDARY_ROW, OUTPUT_LEAF_LAST_ROW, ROOT_ROW,
};
use qstark::hash_air::m86_native::{
    M86_ACTIVE_ROWS, M86_MERKLE_DEPTH, M86_TRACE_LEN, ROWS_PER_BLOCK,
};
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use qstark::hash_air::native::STATE_WIDTH;
use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::Trace;

fn make_leaves(n: usize, sk_start: u64) -> Vec<[BaseElement; 4]> {
    (0..n)
        .map(|i| {
            hash_leaf(
                BaseElement::new(sk_start + i as u64),
                BaseElement::new(2000 + i as u64),
                BaseElement::new(100 + i as u64),
            )
        })
        .collect()
}

#[test]
fn manual_constraint_evaluation_m86() {
    let leaves = make_leaves(16, 1000);
    let tree = MerkleTree::from_leaves(&leaves);

    let idx = 7usize;
    let sk = BaseElement::new(1000 + idx as u64);
    let r = BaseElement::new(2000 + idx as u64);
    let v = BaseElement::new(100 + idx as u64);
    let path: Vec<_> = tree.auth_path(idx).into_iter().take(M86_MERKLE_DEPTH).collect();

    let w = M86Witness {
        sk, r, v, path,
        unshield_amount: v.as_int(), fee: 0,
        sk_out: BaseElement::ZERO, r_out: BaseElement::ZERO, v_out: BaseElement::ZERO,
    };
    let trace = build_m86_trace(&w);

    // Extract every row from the trace
    let mut rows: Vec<[BaseElement; M86_WIDTH]> = Vec::with_capacity(M86_TRACE_LEN);
    for ri in 0..M86_TRACE_LEN {
        let mut row = [BaseElement::ZERO; M86_WIDTH];
        for c in 0..M86_WIDTH {
            row[c] = trace.get(c, ri);
        }
        rows.push(row);
    }

    let mut violations: Vec<String> = Vec::new();

    for r in 0..(M86_TRACE_LEN - 1) {
        let curr = &rows[r];
        let next = &rows[r + 1];

        let is_boundary = if r % ROWS_PER_BLOCK == ROWS_PER_BLOCK - 1 { 1 } else { 0 };
        let is_active = if r < M86_ACTIVE_ROWS - 1 { 1 } else { 0 };
        let is_nb = if r == NULLIFIER_BOUNDARY_ROW { 1 } else { 0 };
        // M8.11: output-leaf boundary periodic, fires at row OUTPUT_BOUNDARY_ROW (=143 at depth 16)
        let is_ob = if r == OUTPUT_BOUNDARY_ROW { 1 } else { 0 };
        let is_row_0 = if r == 0 { 1 } else { 0 };

        let active_round = is_active * (1 - is_boundary);
        // M8.11: merge boundary must NOT fire at nullifier or output transitions
        let active_merge_boundary = is_active * is_boundary * (1 - is_nb) * (1 - is_ob);
        let active_nullifier_boundary = is_active * is_boundary * is_nb;
        let active_output_boundary = is_active * is_boundary * is_ob;

        let round = r % ROWS_PER_BLOCK;

        // Group 1: Hash round
        if active_round == 1 {
            let mut curr_state = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH { curr_state[i] = curr[i]; }
            let mut next_state = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH { next_state[i] = next[i]; }

            let mut sbox = curr_state;
            for s in sbox.iter_mut() {
                let s2 = s.square();
                let s4 = s2.square();
                *s = s4 * s2 * *s;
            }
            let mut rhs = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                for j in 0..STATE_WIDTH {
                    rhs[i] += Rp64_256::MDS[i][j] * sbox[j];
                }
                rhs[i] += Rp64_256::ARK1[round][i];
            }
            let mut e = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                e[i] = next_state[i] - Rp64_256::ARK2[round][i];
            }
            let mut d = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                for j in 0..STATE_WIDTH {
                    d[i] += Rp64_256::INV_MDS[i][j] * e[j];
                }
            }
            let mut lhs = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                let d2 = d[i].square();
                let d4 = d2.square();
                lhs[i] = d4 * d2 * d[i];
            }
            for i in 0..STATE_WIDTH {
                if lhs[i] - rhs[i] != BaseElement::ZERO {
                    violations.push(format!("HashRound[r={},col={}]: nonzero", r, i));
                }
            }
        }

        // Group 2: Merge boundary
        if active_merge_boundary == 1 {
            let dir = next[COL_DIR];
            let sib = [next[COL_SIB_START], next[COL_SIB_START+1],
                       next[COL_SIB_START+2], next[COL_SIB_START+3]];
            let prev = [curr[4], curr[5], curr[6], curr[7]];
            let one = BaseElement::ONE;

            if next[0] - BaseElement::new(8) != BaseElement::ZERO {
                violations.push(format!("MergeBoundary[r={}]: next[0] != 8", r));
            }
            for k in 1..4 {
                if next[k] != BaseElement::ZERO {
                    violations.push(format!("MergeBoundary[r={},col={}]: != 0", r, k));
                }
            }
            for i in 0..4 {
                let tl = (one - dir) * prev[i] + dir * sib[i];
                let tr = dir * prev[i] + (one - dir) * sib[i];
                if next[4 + i] - tl != BaseElement::ZERO {
                    violations.push(format!("MergeBoundary[r={},col={}]: !=tl", r, 4+i));
                }
                if next[8 + i] - tr != BaseElement::ZERO {
                    violations.push(format!("MergeBoundary[r={},col={}]: !=tr", r, 8+i));
                }
            }
        }

        // Group 3: Nullifier boundary
        if active_nullifier_boundary == 1 {
            let sk_next = next[COL_SK];
            let r_next = next[COL_R];
            let v_next = next[COL_V];
            let one = BaseElement::ONE;

            if next[0] - BaseElement::new(3) != BaseElement::ZERO {
                violations.push(format!("NullBoundary[r={}]: next[0] != 3", r));
            }
            for k in 1..4 {
                if next[k] != BaseElement::ZERO {
                    violations.push(format!("NullBoundary[r={},col={}]: != 0", r, k));
                }
            }
            if next[4] - (sk_next + one) != BaseElement::ZERO {
                violations.push(format!("NullBoundary[r={}]: next[4] != sk+1", r));
            }
            if next[5] - r_next != BaseElement::ZERO {
                violations.push(format!("NullBoundary[r={}]: next[5] != r", r));
            }
            if next[6] - v_next != BaseElement::ZERO {
                violations.push(format!("NullBoundary[r={}]: next[6] != v", r));
            }
            for k in 7..STATE_WIDTH {
                if next[k] != BaseElement::ZERO {
                    violations.push(format!("NullBoundary[r={},col={}]: != 0", r, k));
                }
            }
        }

        // M8.11 Group 3.5: Output-leaf boundary.
        // At row OUTPUT_BOUNDARY_ROW → OUTPUT_BOUNDARY_ROW+1: next state must be
        // (3, 0, 0, 0, sk_out, r_out, v_out, 0, 0, 0, 0, 0). Mirrors Group 3
        // exactly but reads sk_out/r_out/v_out witness columns instead.
        if active_output_boundary == 1 {
            let sk_out_next = next[COL_SK_OUT];
            let r_out_next = next[COL_R_OUT];
            let v_out_next = next[COL_V_OUT];

            if next[0] - BaseElement::new(3) != BaseElement::ZERO {
                violations.push(format!("OutBoundary[r={}]: next[0] != 3", r));
            }
            for k in 1..4 {
                if next[k] != BaseElement::ZERO {
                    violations.push(format!("OutBoundary[r={},col={}]: != 0", r, k));
                }
            }
            if next[4] - sk_out_next != BaseElement::ZERO {
                violations.push(format!("OutBoundary[r={}]: next[4] != sk_out", r));
            }
            if next[5] - r_out_next != BaseElement::ZERO {
                violations.push(format!("OutBoundary[r={}]: next[5] != r_out", r));
            }
            if next[6] - v_out_next != BaseElement::ZERO {
                violations.push(format!("OutBoundary[r={}]: next[6] != v_out", r));
            }
            for k in 7..STATE_WIDTH {
                if next[k] != BaseElement::ZERO {
                    violations.push(format!("OutBoundary[r={},col={}]: != 0", r, k));
                }
            }
        }

        // Group 4: Dir binary
        let dir = curr[COL_DIR];
        if is_active == 1 {
            if dir * (dir - BaseElement::ONE) != BaseElement::ZERO {
                violations.push(format!("DirBin[r={}]: dir not 0/1", r));
            }
        }

        // Group 5: Within-block static
        if active_round == 1 {
            if next[COL_DIR] - curr[COL_DIR] != BaseElement::ZERO {
                violations.push(format!("Static[r={}]: dir changed", r));
            }
            for i in 0..4 {
                if next[COL_SIB_START + i] - curr[COL_SIB_START + i] != BaseElement::ZERO {
                    violations.push(format!("Static[r={}]: sib[{}] changed", r, i));
                }
            }
        }

        // Group 6: Global witness static
        // M8.11: extended to also pin sk_out/r_out/v_out static across active trace.
        if is_active == 1 {
            if next[COL_SK] - curr[COL_SK] != BaseElement::ZERO {
                violations.push(format!("Global[r={}]: sk changed", r));
            }
            if next[COL_R] - curr[COL_R] != BaseElement::ZERO {
                violations.push(format!("Global[r={}]: r changed", r));
            }
            if next[COL_V] - curr[COL_V] != BaseElement::ZERO {
                violations.push(format!("Global[r={}]: v changed", r));
            }
            if next[COL_SK_OUT] - curr[COL_SK_OUT] != BaseElement::ZERO {
                violations.push(format!("Global[r={}]: sk_out changed", r));
            }
            if next[COL_R_OUT] - curr[COL_R_OUT] != BaseElement::ZERO {
                violations.push(format!("Global[r={}]: r_out changed", r));
            }
            if next[COL_V_OUT] - curr[COL_V_OUT] != BaseElement::ZERO {
                violations.push(format!("Global[r={}]: v_out changed", r));
            }
        }

        // Group 7: Leaf-block binding (at row 0 only)
        if is_row_0 == 1 {
            if curr[4] - curr[COL_SK] != BaseElement::ZERO {
                violations.push(format!("LeafBind[r={}]: state[4] != sk", r));
            }
            if curr[5] - curr[COL_R] != BaseElement::ZERO {
                violations.push(format!("LeafBind[r={}]: state[5] != r", r));
            }
            if curr[6] - curr[COL_V] != BaseElement::ZERO {
                violations.push(format!("LeafBind[r={}]: state[6] != v", r));
            }
        }

        // M8.8-A1 Group 8: Bit binary — each b[i] ∈ {0,1} on every active row.
        // M8.11: extended to also cover v_out's 64 bit columns.
        if is_active == 1 {
            for i in 0..NUM_VALUE_BITS {
                let b = curr[COL_BIT_START + i];
                if b * (b - BaseElement::ONE) != BaseElement::ZERO {
                    violations.push(format!("BitBin[r={},bit={}]: b not 0/1 (val={})", r, i, b.as_int()));
                }
                let b_out = curr[COL_BIT_OUT_START + i];
                if b_out * (b_out - BaseElement::ONE) != BaseElement::ZERO {
                    violations.push(format!("BitBinOut[r={},bit={}]: b_out not 0/1 (val={})", r, i, b_out.as_int()));
                }
            }
        }

        // M8.8-A1 Group 9: Decomposition — at row 0, v == Σ b[i] * 2^i.
        // M8.11: extended to also check v_out's decomposition at row 0.
        if is_row_0 == 1 {
            let mut sum = BaseElement::ZERO;
            let mut sum_out = BaseElement::ZERO;
            let mut pow = BaseElement::ONE;
            let two = BaseElement::new(2);
            for i in 0..NUM_VALUE_BITS {
                sum += curr[COL_BIT_START + i] * pow;
                sum_out += curr[COL_BIT_OUT_START + i] * pow;
                pow *= two;
            }
            if curr[COL_V] - sum != BaseElement::ZERO {
                violations.push(format!(
                    "Decomp[r=0]: v={} but Σ b[i]*2^i = {}",
                    curr[COL_V].as_int(), sum.as_int()
                ));
            }
            if curr[COL_V_OUT] - sum_out != BaseElement::ZERO {
                violations.push(format!(
                    "DecompOut[r=0]: v_out={} but Σ b_out[i]*2^i = {}",
                    curr[COL_V_OUT].as_int(), sum_out.as_int()
                ));
            }
        }

        // M8.11 Group 10: Value conservation at row 0.
        // v_in - v_out - amount_plus_fee == 0 (field arithmetic).
        // Replaces the M8.8-A1 amount-sum assertion (now removed below).
        if is_row_0 == 1 {
            let apf = BaseElement::new(w.unshield_amount) + BaseElement::new(w.fee);
            let lhs = curr[COL_V] - curr[COL_V_OUT] - apf;
            if lhs != BaseElement::ZERO {
                violations.push(format!(
                    "ValueConservation[r=0]: v_in - v_out - (unshield+fee) = {} (expected 0). \
                     v_in={}, v_out={}, unshield={}, fee={}",
                    lhs.as_int(),
                    curr[COL_V].as_int(), curr[COL_V_OUT].as_int(),
                    w.unshield_amount, w.fee
                ));
            }
        }
    }

    // M8.11: Output-leaf assertion replaces the old amount-sum assertion.
    // At row OUTPUT_LEAF_LAST_ROW (=151), state[4..8] holds H(sk_out, r_out, v_out).
    // The chain commits to this as a public input; the AIR asserts the trace
    // produced it correctly. We don't have the expected hash precomputed in
    // diag (it'd duplicate the AIR's work), but we can sanity-check that
    // state[4..8] at that row is NOT all-zero (which would mean the output
    // block never ran). Compute it the same way the trace did and compare.
    let row_out = &rows[OUTPUT_LEAF_LAST_ROW];
    let out_leaf = hash_leaf(w.sk_out, w.r_out, w.v_out);
    for i in 0..4 {
        if row_out[4 + i] != out_leaf[i] {
            violations.push(format!(
                "OutputLeafAssert[r={},col={}]: trace has {} but H(sk_out,r_out,v_out)[{}]={}",
                OUTPUT_LEAF_LAST_ROW, 4+i,
                row_out[4 + i].as_int(), i, out_leaf[i].as_int()
            ));
        }
    }

    // Sanity check: the nullifier still lands at the right row.
    // (No assertion needed beyond what the AIR enforces, but useful for diag.)
    let row_null = &rows[NULLIFIER_LAST_ROW];
    let null_expected = hash_leaf(w.sk + BaseElement::ONE, w.r, w.v);
    for i in 0..4 {
        if row_null[4 + i] != null_expected[i] {
            violations.push(format!(
                "NullifierAssert[r={},col={}]: trace has {} but H(sk+1,r,v)[{}]={}",
                NULLIFIER_LAST_ROW, 4+i,
                row_null[4 + i].as_int(), i, null_expected[i].as_int()
            ));
        }
    }

    // Sanity check: the root lands at ROOT_ROW.
    // Use the SAME tree the witness traversed (set up at the top of the test).
    let row_root = &rows[ROOT_ROW];
    let expected_root = tree.root();
    for i in 0..4 {
        if row_root[4 + i] != expected_root[i] {
            violations.push(format!(
                "RootAssert[r={},col={}]: trace has {} but expected_root[{}]={}",
                ROOT_ROW, 4+i,
                row_root[4 + i].as_int(), i, expected_root[i].as_int()
            ));
        }
    }

    if !violations.is_empty() {
        for v in violations.iter().take(30) {
            println!("VIOLATION: {}", v);
        }
        panic!("{} constraint violations found", violations.len());
    } else {
        println!(
            "All M8.6 + M8.8-A1 + M8.11 constraints satisfied across all rows!\n  \
             - 8 M8.6 groups (hash round, merge boundary, nullifier boundary,\n    \
                output-leaf boundary [M8.11], dir binary, within-block static,\n    \
                global witness static, leaf-block binding)\n  \
             - 2 M8.8-A1 groups (bit binary × {} bits + v_out bits,\n    \
                value decomposition for v_in and v_out)\n  \
             - 1 M8.11 value-conservation transition (v_in - v_out - (unshield+fee) at row 0)\n  \
             - 3 boundary assertion sanity checks (root, nullifier, output_leaf)",
            NUM_VALUE_BITS
        );
    }
}

//! Diagnose: manually evaluate every constraint at every row.
//! Should all be zero for an honest trace.

use qstark::hash_air::anon_full::{
    build_full_trace, FullMembershipWitness, ACTIVE_ROWS, COL_DIR, COL_SIB_START,
    FULL_TRACE_LEN, FULL_WIDTH, ROWS_PER_BLOCK,
};
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use qstark::hash_air::native::{STATE_WIDTH, NUM_ROUNDS};
use winter_crypto::hashers::Rp64_256;
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
fn manual_constraint_evaluation() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 7);
    let trace = build_full_trace(&witness);

    // Build row arrays
    let mut rows: Vec<[BaseElement; FULL_WIDTH]> = Vec::with_capacity(FULL_TRACE_LEN);
    for r in 0..FULL_TRACE_LEN {
        let mut row = [BaseElement::ZERO; FULL_WIDTH];
        for c in 0..FULL_WIDTH {
            row[c] = trace.get(c, r);
        }
        rows.push(row);
    }

    // Compute is_boundary and is_active for each row
    let mut violations: Vec<String> = Vec::new();
    for r in 0..(FULL_TRACE_LEN - 1) {
        let curr = &rows[r];
        let next = &rows[r + 1];

        let is_boundary = if r % ROWS_PER_BLOCK == ROWS_PER_BLOCK - 1 { 1 } else { 0 };
        let is_active = if r < ACTIVE_ROWS - 1 { 1 } else { 0 };
        let active_round = is_active * (1 - is_boundary);
        let active_boundary = is_active * is_boundary;

        let round = r % ROWS_PER_BLOCK;  // 0..7 within a block

        // Hash round constraint
        if active_round == 1 {
            // (INV_MDS * (next[0..12] - ARK2[round]))^7 == MDS * curr[0..12]^7 + ARK1[round]
            let mut curr_state = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH { curr_state[i] = curr[i]; }
            let mut next_state = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH { next_state[i] = next[i]; }

            // Compute RHS: MDS * curr^7 + ARK1
            let mut curr_sbox = curr_state;
            for s in curr_sbox.iter_mut() {
                let s2 = s.square();
                let s4 = s2.square();
                *s = s4 * s2 * *s;
            }
            let mut rhs = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                for j in 0..STATE_WIDTH {
                    rhs[i] += Rp64_256::MDS[i][j] * curr_sbox[j];
                }
                rhs[i] += Rp64_256::ARK1[round][i];
            }
            // Compute LHS: (INV_MDS * (next - ARK2))^7
            let mut e_vec = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                e_vec[i] = next_state[i] - Rp64_256::ARK2[round][i];
            }
            let mut d_vec = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                for j in 0..STATE_WIDTH {
                    d_vec[i] += Rp64_256::INV_MDS[i][j] * e_vec[j];
                }
            }
            let mut lhs = [BaseElement::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                let d2 = d_vec[i].square();
                let d4 = d2.square();
                lhs[i] = d4 * d2 * d_vec[i];
            }
            for i in 0..STATE_WIDTH {
                if lhs[i] - rhs[i] != BaseElement::ZERO {
                    violations.push(format!("HashRound[r={},col={}]: lhs - rhs != 0", r, i));
                }
            }
        }

        // Block boundary constraint
        if active_boundary == 1 {
            let dir = next[COL_DIR];
            let sib = [next[COL_SIB_START], next[COL_SIB_START+1],
                       next[COL_SIB_START+2], next[COL_SIB_START+3]];
            let prev_output = [curr[4], curr[5], curr[6], curr[7]];
            let one = BaseElement::ONE;

            // Check next[0] = 8
            if next[0] - BaseElement::new(8) != BaseElement::ZERO {
                violations.push(format!("Boundary[r={},col=0]: next[0] != 8", r));
            }
            for k in 1..4 {
                if next[k] != BaseElement::ZERO {
                    violations.push(format!("Boundary[r={},col={}]: next[{}] != 0", r, k, k));
                }
            }
            for i in 0..4 {
                let target_left = (one - dir) * prev_output[i] + dir * sib[i];
                let target_right = dir * prev_output[i] + (one - dir) * sib[i];
                if next[4 + i] - target_left != BaseElement::ZERO {
                    violations.push(format!("Boundary[r={},col={}]: next[{}] != target_left",
                                            r, 4+i, 4+i));
                }
                if next[8 + i] - target_right != BaseElement::ZERO {
                    violations.push(format!("Boundary[r={},col={}]: next[{}] != target_right",
                                            r, 8+i, 8+i));
                }
            }
        }

        // dir binary
        let dir = curr[COL_DIR];
        if is_active == 1 {
            if dir * (dir - BaseElement::ONE) != BaseElement::ZERO {
                violations.push(format!("DirBin[r={}]: dir*(dir-1) != 0 (dir={:?})", r, dir));
            }
        }

        // Witness-static
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
    }

    if !violations.is_empty() {
        for v in violations.iter().take(20) {
            println!("VIOLATION: {}", v);
        }
        panic!("{} constraint violations found", violations.len());
    } else {
        println!("All constraints satisfied across all rows!");
    }
}

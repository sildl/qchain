//! M8.3 full: Multi-level Merkle membership zk-STARK.
//!
//! Proves: "I know `(leaf, path, dir_bits)` such that traversing the Merkle
//! tree from `leaf` using `path` and `dir_bits` reaches public root `R`."
//!
//! Everything except `R` is in the witness. The verifier learns NOTHING
//! about leaf, position, or path siblings.
//!
//! ## Trace layout
//!
//! `WIDTH = 17` columns:
//!   * cols  0..12: Rescue state (12 elements, same as M8.2)
//!   * col   12:    direction bit for this hash block (constant across 8 rows)
//!   * cols  13..17: sibling digest for this hash block (constant across 8 rows)
//!
//! `LENGTH = 64` rows for `MERKLE_DEPTH = 4`:
//!   * Rows 0..7   : level 0 hash
//!   * Rows 8..15  : level 1 hash
//!   * Rows 16..23 : level 2 hash
//!   * Rows 24..31 : level 3 hash
//!   * Rows 32..63 : padding (state unchanged)
//!
//! ## Constraint architecture
//!
//! Selector-based: a periodic column `is_boundary` has values
//!   [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, ...]
//! cycling every 8 rows. It's 1 only at row 7-mod-8 (the LAST row of each
//! hash block, where the transition is "set up next block's initial state").
//!
//! There are two transition constraint groups:
//!
//! 1. **Hash round** (degree 7, multiplied by `1 - is_boundary` → degree 8):
//!    The M8.2 round equation. Active on within-block transitions.
//!
//! 2. **Block boundary** (degree 2, multiplied by `is_boundary` → degree 3):
//!    The next block's initial state encodes the swap-by-direction logic.
//!
//! 3. **Witness-static** (degree 1, multiplied by `1 - is_boundary` → degree 2):
//!    `dir` and `sib` columns stay constant within each block.
//!
//! 4. **Direction bit binary** (degree 2):
//!    `dir * (dir - 1) = 0` at every row.
//!
//! ## Honest scope reality check
//!
//! Constraint degree-8 needs blowup factor ≥ 8, which the default options
//! provide. We'll set it explicitly.

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

use super::merkle::{Digest4, MerkleTree};
use super::native::{DIGEST_SIZE, NUM_ROUNDS, STATE_WIDTH};

type Felt = BaseElement;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of Merkle levels we prove. Anonymity set = 2^MERKLE_DEPTH.
pub const MERKLE_DEPTH: usize = 4;

/// Rows per hash block (1 initial + 7 round-transitions).
pub const ROWS_PER_BLOCK: usize = 8;

/// Active rows = MERKLE_DEPTH * ROWS_PER_BLOCK = 32
pub const ACTIVE_ROWS: usize = MERKLE_DEPTH * ROWS_PER_BLOCK;

/// Padded trace length: next power of 2 ≥ ACTIVE_ROWS.
pub const FULL_TRACE_LEN: usize = 64;

// Trace columns
pub const COL_STATE_START: usize = 0;         // 0..12
pub const COL_DIR: usize = 12;
pub const COL_SIB_START: usize = 13;          // 13..17
pub const FULL_WIDTH: usize = 17;

// ---------------------------------------------------------------------------
// Public inputs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FullMembershipInputs {
    pub root: Digest4,
}

impl ToElements<Felt> for FullMembershipInputs {
    fn to_elements(&self) -> Vec<Felt> { self.root.to_vec() }
}

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FullMembershipWitness {
    pub leaf: Digest4,
    /// (sibling, is_right) per level. `is_right=true` means current is on
    /// the right side of the pair (so hash inputs are: sibling, current).
    pub path: Vec<(Digest4, bool)>,
}

impl FullMembershipWitness {
    pub fn from_tree(tree: &MerkleTree, idx: usize) -> Self {
        let full_path = tree.auth_path(idx);
        let path = full_path.into_iter().take(MERKLE_DEPTH).collect::<Vec<_>>();
        let leaf = tree.node_at(0, idx);
        FullMembershipWitness { leaf, path }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// Build one hash block (8 rows) computing merge(left, right). Records each
/// row's full state.
fn block_rows(left: Digest4, right: Digest4) -> Vec<[Felt; STATE_WIDTH]> {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[0] = Felt::new(8);
    for i in 0..DIGEST_SIZE {
        state[4 + i] = left[i];
        state[8 + i] = right[i];
    }
    let mut rows = Vec::with_capacity(ROWS_PER_BLOCK);
    rows.push(state);
    for round in 0..NUM_ROUNDS {
        Rp64_256::apply_round(&mut state, round);
        rows.push(state);
    }
    rows
}

/// Build the full 17-column trace.
pub fn build_full_trace(witness: &FullMembershipWitness) -> TraceTable<Felt> {
    assert_eq!(witness.path.len(), MERKLE_DEPTH);

    // Compute the row-by-row data
    let mut current = witness.leaf;
    // For each block we have 8 state rows + the constant (dir, sib) for that block
    let mut all_rows: Vec<[Felt; FULL_WIDTH]> = Vec::with_capacity(FULL_TRACE_LEN);

    for level in 0..MERKLE_DEPTH {
        let (sibling, is_right) = witness.path[level];
        let (left, right) = if is_right {
            (sibling, current)
        } else {
            (current, sibling)
        };
        let state_rows = block_rows(left, right);
        for row in state_rows.iter() {
            let mut full = [Felt::ZERO; FULL_WIDTH];
            full[..STATE_WIDTH].copy_from_slice(row);
            full[COL_DIR] = if is_right { Felt::ONE } else { Felt::ZERO };
            full[COL_SIB_START..COL_SIB_START + DIGEST_SIZE].copy_from_slice(&sibling);
            all_rows.push(full);
        }
        // Update current to this block's output
        let last = &state_rows[ROWS_PER_BLOCK - 1];
        for i in 0..DIGEST_SIZE {
            current[i] = last[4 + i];
        }
    }
    // The final `current` is now the computed root.

    // Pad to FULL_TRACE_LEN with the last active row
    let pad_template = *all_rows.last().unwrap();
    while all_rows.len() < FULL_TRACE_LEN {
        all_rows.push(pad_template);
    }

    // Convert to TraceTable
    let mut trace = TraceTable::new(FULL_WIDTH, FULL_TRACE_LEN);
    trace.fill(
        |state| { state.copy_from_slice(&all_rows[0]); },
        |step, state| { state.copy_from_slice(&all_rows[step + 1]); },
    );
    trace
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub struct FullMembershipAir {
    context: AirContext<Felt>,
    root: Digest4,
}

impl Air for FullMembershipAir {
    type BaseField = Felt;
    type PublicInputs = FullMembershipInputs;

    fn new(trace_info: TraceInfo, pub_inputs: FullMembershipInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), FULL_WIDTH);
        assert_eq!(trace_info.length(), FULL_TRACE_LEN);

        // Constraint count and degrees:
        // The degree descriptor must include both the base degree (from
        // multiplying trace columns) AND any periodic column cycles that
        // multiply in. Winterfell uses this to size the LDE properly.
        //
        // is_boundary cycles every 8 rows.
        // is_active is full-length (64 in our case); we treat it as a cycle
        // of length 64 = FULL_TRACE_LEN.
        //
        //   * 12 hash-round constraints, base 7, multiplied by
        //     is_active * (1 - is_boundary) = degree 7, two periodic cycles
        //   * 12 block-boundary state constraints, base 2 (it's max of
        //     {next - 8 (deg 1), next - swap_target (deg 2 from dir*x)}),
        //     multiplied by is_active * is_boundary = base 2, two cycles
        //   * 1 direction-bit binary constraint, base 2, multiplied by is_active = base 2, one cycle
        //   * 5 witness-static constraints (dir + 4 siblings), base 1,
        //     multiplied by is_active * (1 - is_boundary) = base 1, two cycles
        let cycle_8 = ROWS_PER_BLOCK;
        let cycle_full = FULL_TRACE_LEN;
        let mut degrees = Vec::new();
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(7, vec![cycle_full, cycle_8]));
        }
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![cycle_full, cycle_8]));
        }
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![cycle_full]));
        for _ in 0..5 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![cycle_full, cycle_8]));
        }
        // = 12 + 12 + 1 + 5 = 30 degrees

        // Assertions: 4 for the final root + 4 for the very first row's
        // capacity (state[0]=8, state[1..4]=0) = 8 total
        let num_assertions = 4 + 4;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        FullMembershipAir { context, root: pub_inputs.root }
    }

    fn context(&self) -> &AirContext<Felt> { &self.context }

    /// Periodic columns:
    ///   * 12 columns for ARK1 (one per state element)
    ///   * 12 columns for ARK2
    ///   * 1 column `is_boundary`: 0 on within-block rows, 1 on block-end row
    ///   * 1 column `is_padding`: 0 on active rows, 1 on padding rows
    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns: Vec<Vec<Felt>> = Vec::new();

        // ARK1, ARK2 (24 columns) with period 8
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

        // is_boundary: 1 only at row 7 within an 8-row cycle
        let mut is_boundary = vec![Felt::ZERO; ROWS_PER_BLOCK];
        is_boundary[ROWS_PER_BLOCK - 1] = Felt::ONE;
        columns.push(is_boundary);

        // is_active_transition: 1 for rows whose outgoing transition we
        // want to constrain. The last active row is row ACTIVE_ROWS-1 = 31,
        // and its outgoing transition goes to padding (row 32). We don't
        // want any constraint to fire there. So is_active is 1 on rows
        // 0..ACTIVE_ROWS-1 = 0..30, and 0 on rows 31..63.
        let mut is_active = vec![Felt::ZERO; FULL_TRACE_LEN];
        for i in 0..(ACTIVE_ROWS - 1) {
            is_active[i] = Felt::ONE;
        }
        columns.push(is_active);

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

        // Selectors:
        //   active_round  = is_active * (1 - is_boundary)  — within block, in active region
        //   active_boundary = is_active * is_boundary       — block boundary, in active region
        // Outside the active region, all constraints are gated off.
        let one = E::ONE;
        let active_round = is_active * (one - is_boundary);
        let active_boundary = is_active * is_boundary;

        // -------------------------------------------------------------------
        // Constraint group 1: Hash round (12 constraints, degree 8)
        // -------------------------------------------------------------------
        //   active_round * ((INV_MDS * (next[0..12] - ARK2))^7 - MDS * curr[0..12]^7 - ARK1) = 0
        //
        // Same form as M8.2 but multiplied by selector.
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

        // -------------------------------------------------------------------
        // Constraint group 2: Block boundary (12 constraints)
        // -------------------------------------------------------------------
        // At a block boundary (curr is row 7 of block N, next is row 0 of block N+1):
        //   prev_output = curr[4..8]   (output of just-completed block N)
        //   dir, sib    = next[COL_DIR], next[COL_SIB..] (witness for block N+1)
        //   next[0] = 8   (length marker)
        //   next[1..4] = 0  (capacity padding)
        //   If dir = 0:  next[4..8] = prev_output, next[8..12] = sibling
        //   If dir = 1:  next[4..8] = sibling,     next[8..12] = prev_output
        //
        // We read dir/sib from `next` because they describe how the NEXT
        // block's input is constructed.
        let dir_next = next[COL_DIR];
        let sib_next_block = [
            next[COL_SIB_START], next[COL_SIB_START + 1],
            next[COL_SIB_START + 2], next[COL_SIB_START + 3],
        ];
        let prev_output = [curr[4], curr[5], curr[6], curr[7]];

        // residual for next[0..12]:
        let mut boundary_res = [E::ZERO; STATE_WIDTH];
        boundary_res[0] = next[0] - E::from(Felt::new(8));
        boundary_res[1] = next[1];
        boundary_res[2] = next[2];
        boundary_res[3] = next[3];
        for i in 0..4 {
            let target_left = (one - dir_next) * prev_output[i] + dir_next * sib_next_block[i];
            let target_right = dir_next * prev_output[i] + (one - dir_next) * sib_next_block[i];
            boundary_res[4 + i] = next[4 + i] - target_left;
            boundary_res[8 + i] = next[8 + i] - target_right;
        }
        for i in 0..STATE_WIDTH {
            result[STATE_WIDTH + i] = active_boundary * boundary_res[i];
        }

        // -------------------------------------------------------------------
        // Constraint group 3: dir binary (1 constraint, degree 2)
        // -------------------------------------------------------------------
        let dir_curr = curr[COL_DIR];
        result[2 * STATE_WIDTH] = is_active * (dir_curr * (dir_curr - one));

        // -------------------------------------------------------------------
        // Constraint group 4: dir/sib static within a block (5 constraints)
        //   active_round * (next[col] - curr[col]) = 0  for col ∈ {dir, sib0..sib3}
        // -------------------------------------------------------------------
        let static_cols = [
            COL_DIR,
            COL_SIB_START,
            COL_SIB_START + 1,
            COL_SIB_START + 2,
            COL_SIB_START + 3,
        ];
        for (k, &col) in static_cols.iter().enumerate() {
            result[2 * STATE_WIDTH + 1 + k] = active_round * (next[col] - curr[col]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = Vec::new();
        // First row: capacity slot 0 = 8, slots 1..4 = 0
        assertions.push(Assertion::single(0, 0, Felt::new(8)));
        assertions.push(Assertion::single(1, 0, Felt::ZERO));
        assertions.push(Assertion::single(2, 0, Felt::ZERO));
        assertions.push(Assertion::single(3, 0, Felt::ZERO));
        // Last active row: state[4..8] = public root
        let root_row = ACTIVE_ROWS - 1;
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(4 + i, root_row, self.root[i]));
        }
        assertions
    }
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

pub struct FullMembershipProver {
    options: ProofOptions,
    witness: FullMembershipWitness,
}

impl FullMembershipProver {
    pub fn new(options: ProofOptions, witness: FullMembershipWitness) -> Self {
        Self { options, witness }
    }

    pub fn build_trace(&self) -> TraceTable<Felt> {
        build_full_trace(&self.witness)
    }
}

impl Prover for FullMembershipProver {
    type BaseField = Felt;
    type Air = FullMembershipAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Blake3_256<Felt>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, FullMembershipAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> FullMembershipInputs {
        let root_row = ACTIVE_ROWS - 1;
        let mut root = [Felt::ZERO; DIGEST_SIZE];
        for i in 0..DIGEST_SIZE {
            root[i] = trace.get(4 + i, root_row);
        }
        FullMembershipInputs { root }
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
        air: &'a FullMembershipAir,
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
    // Degree-8 constraints need blowup factor >= 16
    ProofOptions::new(54, 16, 0, FieldExtension::None, 8, 31)
}

pub fn prove_full_membership(
    witness: FullMembershipWitness,
) -> Result<(Vec<u8>, FullMembershipInputs), String> {
    let prover = FullMembershipProver::new(default_options(), witness);
    let trace = prover.build_trace();
    let pub_inputs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).map_err(|e| format!("prove failed: {}", e))?;
    let mut bytes = Vec::new();
    proof.write_into(&mut bytes);
    Ok((bytes, pub_inputs))
}

pub fn verify_full_membership(
    proof_bytes: &[u8],
    pub_inputs: FullMembershipInputs,
) -> Result<(), String> {
    let proof = StarkProof::from_bytes(proof_bytes)
        .map_err(|e| format!("deserialize failed: {}", e))?;
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(50);
    winterfell::verify::<FullMembershipAir,
                         Blake3_256<Felt>,
                         DefaultRandomCoin<Blake3_256<Felt>>>(proof, pub_inputs, &min_opts)
        .map_err(|e| format!("verification failed: {}", e))
}

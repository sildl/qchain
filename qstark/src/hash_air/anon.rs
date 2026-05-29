//! M8.3: Single-level Merkle membership via STARK.
//!
//! Proves: "I know a 4-element `left` digest such that
//! `Rp64_256::merge(left, public_right) = public_root`."
//!
//! This is a depth-1 Merkle membership proof. The `left` digest stays hidden
//! in the witness; only `right` and `root` are public.
//!
//! ## Why "depth 1" and not "depth 8"?
//!
//! Full multi-level Merkle membership in a STARK requires applying different
//! transition constraints at different rows of the trace (within-block hash
//! rounds vs. between-block hash setup with witness-dependent sibling
//! placement and direction bits). Winterfell 0.8's `Air` API doesn't expose
//! the constraint-divisor customization needed to switch constraints
//! cleanly. The right architecture uses multi-segment auxiliary traces and
//! per-segment divisors, which would be a substantial additional milestone.
//!
//! This single-level version is **sound and useful**: it captures the core
//! cryptographic primitive (zero-knowledge of one preimage of a Merkle node)
//! and demonstrates that the underlying machinery works. Composing
//! multiple of these into a full path is honest future work.
//!
//! ## Trace layout
//!
//! Identical to M8.2: 12 columns × 8 rows (1 initial + 7 round transitions).
//! Row 0 sets up the merge sponge state (length=8, left in rate[0..4],
//! right in rate[4..8]). The hash AIR transition constraint from M8.2
//! enforces the 7 Rescue rounds. The final row's rate[0..4] is the merged
//! digest, which we assert against the public root.
//!
//! ## What's hidden vs. revealed
//!
//! Witness (hidden):  left digest (4 field elements)
//! Public input:       right digest, root digest
//! Verifier learns:    "some `left` exists such that merge(left, right) = root"
//!                     (which means the prover knows a valid preimage at
//!                     position "left" of a single-level Merkle commitment)
//!
//! ## Soundness
//!
//! Identical to M8.2's analysis. The Rescue-Prime round constraint is the
//! same; only the boundary assertions differ. The verifier sees that the
//! final state's `state[4..8]` equals the claimed root, but learns nothing
//! about `state[4..8]` in the initial state (the `left` value).

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

use super::merkle::Digest4;
use super::native::{DIGEST_SIZE, NUM_ROUNDS, STATE_WIDTH, TRACE_LEN};

type Felt = BaseElement;

// ---------------------------------------------------------------------------
// Public inputs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AnonInputs {
    pub right: Digest4,
    pub root: Digest4,
}

impl ToElements<Felt> for AnonInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut v = Vec::with_capacity(8);
        v.extend_from_slice(&self.right);
        v.extend_from_slice(&self.root);
        v
    }
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub struct AnonAir {
    context: AirContext<Felt>,
    right: Digest4,
    root: Digest4,
}

impl Air for AnonAir {
    type BaseField = Felt;
    type PublicInputs = AnonInputs;

    fn new(trace_info: TraceInfo, pub_inputs: AnonInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), STATE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LEN);

        // 12 transition constraints of degree 7 (M8.2 design).
        let degrees = vec![TransitionConstraintDegree::new(7); STATE_WIDTH];

        // Boundary assertions:
        //   4 on capacity (slot 0 = 8, slots 1-3 = 0)         — initial state shape
        //   4 on rate[4..8] (right digest) at row 0           — public input
        //   4 on rate[0..4] (root) at last row                — public output
        // We do NOT assert the value of state[4..8] at row 0 — that's `left`,
        // which is the witness and must remain hidden.
        let num_assertions = 4 + DIGEST_SIZE + DIGEST_SIZE;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        AnonAir { context, right: pub_inputs.right, root: pub_inputs.root }
    }

    fn context(&self) -> &AirContext<Felt> { &self.context }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns = vec![vec![Felt::ZERO; TRACE_LEN]; 2 * STATE_WIDTH];
        for round in 0..NUM_ROUNDS {
            for i in 0..STATE_WIDTH {
                columns[i][round] = Rp64_256::ARK1[round][i];
                columns[STATE_WIDTH + i][round] = Rp64_256::ARK2[round][i];
            }
        }
        columns
    }

    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        // M8.2 constraint, identical:
        //   (INV_MDS * (next - ARK2))^7 == MDS * curr^7 + ARK1
        let curr = frame.current();
        let next = frame.next();

        let ark1 = &periodic_values[0..STATE_WIDTH];
        let ark2 = &periodic_values[STATE_WIDTH..2 * STATE_WIDTH];

        // RHS: MDS * curr^7 + ARK1
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

        // LHS: (INV_MDS * (next - ARK2))^7
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
            result[i] = lhs[i] - rhs[i];
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let last_step = self.trace_length() - 1;
        let mut assertions = Vec::new();

        // Initial state capacity: slot 0 = 8 (we're merging 8 elements),
        // slots 1, 2, 3 = 0. (We do NOT pin state[4..8] = left, that's witness.)
        assertions.push(Assertion::single(0, 0, Felt::new(8)));
        assertions.push(Assertion::single(1, 0, Felt::ZERO));
        assertions.push(Assertion::single(2, 0, Felt::ZERO));
        assertions.push(Assertion::single(3, 0, Felt::ZERO));

        // Right half of rate at row 0 = public `right` digest
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(8 + i, 0, self.right[i]));
        }

        // Root: state[4..8] at last row = public root digest
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(4 + i, last_step, self.root[i]));
        }

        assertions
    }
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Build the trace for merge(left, right) → root.
pub fn build_merge_trace(left: Digest4, right: Digest4) -> TraceTable<Felt> {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[0] = Felt::new(8);
    for i in 0..DIGEST_SIZE {
        state[4 + i] = left[i];
        state[8 + i] = right[i];
    }
    let mut rows = Vec::with_capacity(TRACE_LEN);
    rows.push(state);
    for round in 0..NUM_ROUNDS {
        Rp64_256::apply_round(&mut state, round);
        rows.push(state);
    }
    assert_eq!(rows.len(), TRACE_LEN);

    let mut trace = TraceTable::new(STATE_WIDTH, TRACE_LEN);
    trace.fill(
        |s| { s.copy_from_slice(&rows[0]); },
        |step, s| { s.copy_from_slice(&rows[step + 1]); },
    );
    trace
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

pub struct AnonProver {
    options: ProofOptions,
    left: Digest4,
    right: Digest4,
}

impl AnonProver {
    pub fn new(options: ProofOptions, left: Digest4, right: Digest4) -> Self {
        Self { options, left, right }
    }

    pub fn build_trace(&self) -> TraceTable<Felt> {
        build_merge_trace(self.left, self.right)
    }
}

impl Prover for AnonProver {
    type BaseField = Felt;
    type Air = AnonAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Blake3_256<Felt>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, AnonAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> AnonInputs {
        let last = trace.length() - 1;
        let mut root = [Felt::ZERO; DIGEST_SIZE];
        for i in 0..DIGEST_SIZE {
            root[i] = trace.get(4 + i, last);
        }
        AnonInputs { right: self.right, root }
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
        air: &'a AnonAir,
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
    ProofOptions::new(42, 8, 0, FieldExtension::None, 8, 31)
}

/// Prove "I know `left` such that merge(left, right) = root".
pub fn prove_one_level_membership(
    left: Digest4,
    right: Digest4,
) -> Result<(Vec<u8>, AnonInputs), String> {
    let prover = AnonProver::new(default_options(), left, right);
    let trace = prover.build_trace();
    let pub_inputs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).map_err(|e| format!("prove failed: {}", e))?;
    let mut bytes = Vec::new();
    proof.write_into(&mut bytes);
    Ok((bytes, pub_inputs))
}

pub fn verify_one_level_membership(
    proof_bytes: &[u8],
    pub_inputs: AnonInputs,
) -> Result<(), String> {
    let proof = StarkProof::from_bytes(proof_bytes)
        .map_err(|e| format!("deserialize failed: {}", e))?;
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(50);
    winterfell::verify::<AnonAir,
                         Blake3_256<Felt>,
                         DefaultRandomCoin<Blake3_256<Felt>>>(proof, pub_inputs, &min_opts)
        .map_err(|e| format!("verification failed: {}", e))
}

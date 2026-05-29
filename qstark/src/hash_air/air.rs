//! The STARK AIR for Rescue-Prime preimage proofs.
//!
//! Proves: "I know `x` such that `Rp64_256(x) = y`".
//!
//! - `x` is the witness (secret to the prover, contained in the trace)
//! - `y` is the public input (the verifier checks the proof against it)
//!
//! See `native.rs` for the constraint design and why this works.

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

use super::native::{
    build_trace, digest_from_trace, initial_state, DIGEST_SIZE, DIGEST_START, NUM_ROUNDS,
    STATE_WIDTH, TRACE_LEN,
};

type Felt = BaseElement;

// ---------------------------------------------------------------------------
// Public inputs — what the verifier sees
// ---------------------------------------------------------------------------

/// Public input is the claimed digest. The preimage stays in the witness.
#[derive(Clone, Debug)]
pub struct HashInputs {
    pub digest: [Felt; DIGEST_SIZE],
}

impl ToElements<Felt> for HashInputs {
    fn to_elements(&self) -> Vec<Felt> { self.digest.to_vec() }
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub struct RescueAir {
    context: AirContext<Felt>,
    digest: [Felt; DIGEST_SIZE],
}

impl Air for RescueAir {
    type BaseField = Felt;
    type PublicInputs = HashInputs;

    fn new(trace_info: TraceInfo, pub_inputs: HashInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), STATE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LEN);

        // 12 transition constraints (one per state element), each degree 7.
        // The degree-7 comes from `D^7` on the LHS of our equation:
        //   (INV_MDS * (S_next - ARK2))^7 == MDS * S^7 + ARK1
        // INV_MDS and S_next are degree 1 each (S_next being the next-row state).
        // (·)^7 makes the LHS degree 7. RHS is degree 7 in S.
        let degrees = vec![TransitionConstraintDegree::new(7); STATE_WIDTH];

        // Boundary assertions:
        //   4 on the initial state (the capacity portion: slot 0 = length, slots
        //     1, 2, 3 = 0). The preimage in the rate stays WITNESS — we don't
        //     assert it, that would reveal it.
        //   4 on the final state's digest portion (must equal claimed digest).
        let num_assertions = 4 + DIGEST_SIZE;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        RescueAir { context, digest: pub_inputs.digest }
    }

    fn context(&self) -> &AirContext<Felt> { &self.context }

    /// Provide the round constants as periodic columns.
    ///
    /// Each of 24 = 2*12 columns has TRACE_LEN=8 entries: 7 valid + 1 padding.
    /// At row r the columns hold ARK1[r] in entries 0..12 and ARK2[r] in
    /// entries 12..24. We treat row 7 as a no-op (the last row has no outgoing
    /// transition).
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

    /// Transition constraints:
    ///   `(INV_MDS * (S_next - ARK2))^7 == MDS * S^7 + ARK1`
    /// componentwise, for the 12 state elements.
    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let curr = frame.current();
        let next = frame.next();

        // ARK1[round] is periodic_values[0..12], ARK2[round] is [12..24]
        let ark1 = &periodic_values[0..STATE_WIDTH];
        let ark2 = &periodic_values[STATE_WIDTH..2 * STATE_WIDTH];

        // RHS: MDS * curr^7 + ARK1
        let mut curr_sbox = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            let c2 = curr[i].square();
            let c4 = c2.square();
            curr_sbox[i] = c4 * c2 * curr[i];   // curr[i]^7
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
            lhs[i] = d4 * d2 * d_vec[i];        // d_vec[i]^7
        }

        // Residuals: LHS - RHS, should be all zero
        for i in 0..STATE_WIDTH {
            result[i] = lhs[i] - rhs[i];
        }
    }

    /// Boundary assertions:
    ///   - Initial state: capacity slot 0 = length, slots 1, 2, 3 = 0.
    ///   - Final state: digest in slots 4-7 = claimed digest.
    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let last_step = self.trace_length() - 1;
        let mut assertions = Vec::new();
        // Initial: capacity[1..4] = 0. We DON'T pin capacity[0] (length) here
        // because it must equal preimage length, which we expose separately
        // (or default to 1 for our M8.2 demo case). For now we hardcode
        // length-1 to keep the API simple — generalized in M8.3.
        assertions.push(Assertion::single(0, 0, Felt::ONE));  // length = 1
        assertions.push(Assertion::single(1, 0, Felt::ZERO));
        assertions.push(Assertion::single(2, 0, Felt::ZERO));
        assertions.push(Assertion::single(3, 0, Felt::ZERO));
        // Final: digest
        for i in 0..DIGEST_SIZE {
            assertions.push(Assertion::single(DIGEST_START + i, last_step, self.digest[i]));
        }
        assertions
    }
}

// ---------------------------------------------------------------------------
// The prover
// ---------------------------------------------------------------------------

pub struct RescueProver {
    options: ProofOptions,
    preimage: Vec<Felt>,
}

impl RescueProver {
    pub fn new(options: ProofOptions, preimage: Vec<Felt>) -> Self {
        assert_eq!(preimage.len(), 1, "M8.2 currently restricted to single-element preimages");
        Self { options, preimage }
    }

    pub fn build_trace(&self) -> TraceTable<Felt> {
        let rows = build_trace(&self.preimage);
        // Convert Vec<[Felt; STATE_WIDTH]> to TraceTable
        let mut trace = TraceTable::new(STATE_WIDTH, TRACE_LEN);
        trace.fill(
            |state| { state.copy_from_slice(&rows[0]); },
            |step, state| { state.copy_from_slice(&rows[step + 1]); },
        );
        trace
    }
}

impl Prover for RescueProver {
    type BaseField = Felt;
    type Air = RescueAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Blake3_256<Felt>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, RescueAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> HashInputs {
        let last = trace.length() - 1;
        let mut digest = [Felt::ZERO; DIGEST_SIZE];
        for i in 0..DIGEST_SIZE {
            digest[i] = trace.get(DIGEST_START + i, last);
        }
        HashInputs { digest }
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
        air: &'a RescueAir,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ---------------------------------------------------------------------------
// High-level API
// ---------------------------------------------------------------------------

/// Standard proof options. For a single-hash trace (only 8 rows), we can't
/// reach full 128-bit security — the LDE domain is too small. We aim for
/// ~50-bit conjectured security on the demo. In production this same AIR
/// would be batched over many hashes in a much larger trace.
pub fn default_options() -> ProofOptions {
    // num_queries=42 + blowup=8 gives ~57-bit security on this tiny trace.
    // Acceptable for the M8.2 demo with explicit labeling.
    ProofOptions::new(42, 8, 0, FieldExtension::None, 8, 31)
}

/// Prove "I know `preimage` such that `Rp64_256(preimage) = y`".
/// Returns the serialized proof and the digest `y` (the public input).
pub fn prove_preimage(preimage: Felt) -> Result<(Vec<u8>, HashInputs), String> {
    let prover = RescueProver::new(default_options(), vec![preimage]);
    let trace = prover.build_trace();
    let pub_inputs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).map_err(|e| format!("prove failed: {}", e))?;
    let mut bytes = Vec::new();
    proof.write_into(&mut bytes);
    Ok((bytes, pub_inputs))
}

/// Verify a preimage proof against a claimed digest.
pub fn verify_preimage(proof_bytes: &[u8], pub_inputs: HashInputs) -> Result<(), String> {
    let proof = StarkProof::from_bytes(proof_bytes)
        .map_err(|e| format!("deserialize failed: {}", e))?;
    // 50-bit conjectured security: low for production but reasonable for
    // demonstrating a single-hash AIR. The same AIR scales to 100+ bits when
    // batched over thousands of hash invocations in a longer trace.
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(50);
    winterfell::verify::<RescueAir,
                         Blake3_256<Felt>,
                         DefaultRandomCoin<Blake3_256<Felt>>>(proof, pub_inputs, &min_opts)
        .map_err(|e| format!("verification failed: {}", e))
}

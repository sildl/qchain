//! Fibonacci AIR — the "hello world" of STARKs.
//!
//! Proves that a public output `result` is the n-th value in the Fibonacci
//! sequence, without revealing the intermediate trace.
//!
//! Why Fibonacci? It's the smallest non-trivial computation that exercises
//! every part of a STARK system:
//!   - state transition (current row → next row, multi-register)
//!   - boundary constraints (a_0 = 1, b_0 = 1)
//!   - public inputs (only the final result is revealed)
//!
//! If this works end-to-end, our toolchain is sound. We then build real
//! cryptographic AIRs on the same foundation.

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxTraceRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, ProofOptions, Prover, Serializable, StarkDomain,
    StarkProof, Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

// The field we work over. f128 is winterfell's 128-bit field — easy starting
// point. For production we'd typically use the 64-bit Goldilocks field.
type Felt = BaseElement;

// ---------------------------------------------------------------------------
// Public inputs — what the verifier sees, in addition to the proof
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FibInputs {
    pub result: Felt,
}

impl ToElements<Felt> for FibInputs {
    fn to_elements(&self) -> Vec<Felt> {
        vec![self.result]
    }
}

// ---------------------------------------------------------------------------
// The AIR — the cryptographic heart of the STARK
// ---------------------------------------------------------------------------

pub struct FibAir {
    context: AirContext<Felt>,
    result: Felt,
}

impl Air for FibAir {
    type BaseField = Felt;
    type PublicInputs = FibInputs;

    fn new(trace_info: TraceInfo, pub_inputs: FibInputs, options: ProofOptions) -> Self {
        // Two transition constraints, both degree 1 (linear in the trace cells).
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        let num_assertions = 3;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        FibAir { context, result: pub_inputs.result }
    }

    fn context(&self) -> &AirContext<Felt> { &self.context }

    /// Transition constraints.
    ///
    /// `frame` exposes the current row and next row of the trace.
    /// Each value in `result` should be zero when the transition is honest.
    /// The STARK proves these are zero almost everywhere — anywhere they
    /// aren't, the verifier rejects.
    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // Register 0 = a, register 1 = b. Next row should be: [b, a + b].
        result[0] = next[0] - current[1];                  // a_next == b_curr
        result[1] = next[1] - (current[0] + current[1]);   // b_next == a + b
    }

    /// Boundary assertions — pin specific trace cells to specific values.
    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let last_step = self.trace_length() - 1;
        vec![
            // Start: (1, 1)
            Assertion::single(0, 0, Felt::ONE),
            Assertion::single(1, 0, Felt::ONE),
            // End: register 1 at the last row holds `result`
            Assertion::single(1, last_step, self.result),
        ]
    }
}

// ---------------------------------------------------------------------------
// The prover
// ---------------------------------------------------------------------------

pub struct FibProver { options: ProofOptions }

impl FibProver {
    pub fn new(options: ProofOptions) -> Self { Self { options } }

    /// Build the execution trace (the *witness*). The prover knows it,
    /// the verifier never sees it.
    pub fn build_trace(&self, n_steps: usize) -> TraceTable<Felt> {
        assert!(n_steps.is_power_of_two() && n_steps >= 8,
                "n_steps must be a power of two >= 8");
        let mut trace = TraceTable::new(2, n_steps);
        trace.fill(
            |state| {
                state[0] = Felt::ONE;
                state[1] = Felt::ONE;
            },
            |_, state| {
                let next_a = state[1];
                let next_b = state[0] + state[1];
                state[0] = next_a;
                state[1] = next_b;
            },
        );
        trace
    }
}

impl Prover for FibProver {
    type BaseField = Felt;
    type Air = FibAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Blake3_256<Felt>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, FibAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> FibInputs {
        let last_step = trace.length() - 1;
        FibInputs { result: trace.get(1, last_step) }
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
        air: &'a FibAir,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ---------------------------------------------------------------------------
// Convenience API
// ---------------------------------------------------------------------------

/// Standard ~96-bit-security proof options for our demos.
pub fn default_options() -> ProofOptions {
    // num_queries, blowup, grinding, field_extension, fri_folding, fri_max_remainder_deg
    ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31)
}

/// Compute the n-th Fibonacci number natively (for testing/witness).
pub fn fib_native(n_steps: usize) -> Felt {
    let mut a = Felt::ONE;
    let mut b = Felt::ONE;
    for _ in 1..n_steps {
        let next_a = b;
        let next_b = a + b;
        a = next_a;
        b = next_b;
    }
    b
}

/// Prove fib(n) and return (serialized_proof, public_inputs).
pub fn prove_fib(n_steps: usize) -> Result<(Vec<u8>, FibInputs), String> {
    let options = default_options();
    let prover = FibProver::new(options);
    let trace = prover.build_trace(n_steps);
    let last_step = trace.length() - 1;
    let pub_inputs = FibInputs { result: trace.get(1, last_step) };
    let proof = prover.prove(trace).map_err(|e| format!("prove failed: {}", e))?;
    let mut bytes = Vec::new();
    proof.write_into(&mut bytes);
    Ok((bytes, pub_inputs))
}

/// Verify a serialized proof against public inputs.
pub fn verify_fib(proof_bytes: &[u8], pub_inputs: FibInputs) -> Result<(), String> {
    let proof = StarkProof::from_bytes(proof_bytes)
        .map_err(|e| format!("deserialize failed: {}", e))?;
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<FibAir,
                         Blake3_256<Felt>,
                         DefaultRandomCoin<Blake3_256<Felt>>>(proof, pub_inputs, &min_opts)
        .map_err(|e| format!("verification failed: {}", e))
}

// M8.2: Rescue-Prime hash AIR
pub mod hash_air;

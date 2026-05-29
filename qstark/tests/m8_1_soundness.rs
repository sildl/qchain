//! M8.1 soundness tests.
//!
//! A STARK system that passes only the "happy path" tells you nothing —
//! a no-op verifier passes those too. The interesting question is:
//! "Does it REJECT bad proofs?" This file tests that.

use qstark::{prove_fib, verify_fib, fib_native, FibInputs};
use winterfell::math::{fields::f128::BaseElement, FieldElement};

#[test]
fn happy_path_fib_1024() {
    let (proof, pub_inputs) = prove_fib(1024).expect("prove");
    verify_fib(&proof, pub_inputs).expect("verify should succeed");
}

#[test]
fn happy_path_fib_8192() {
    let (proof, pub_inputs) = prove_fib(8192).expect("prove");
    verify_fib(&proof, pub_inputs).expect("verify should succeed");
}

#[test]
fn happy_path_varies_size() {
    // STARKs need trace_length a power of two, >= 8 (our floor)
    for &n in &[8usize, 16, 32, 64, 128, 256, 512] {
        let (proof, pub_inputs) = prove_fib(n).expect("prove");
        assert_eq!(pub_inputs.result, fib_native(n), "native vs trace mismatch n={}", n);
        verify_fib(&proof, pub_inputs).expect("verify");
    }
}

#[test]
fn rejects_wrong_public_input() {
    // The prover proves fib(1024) = X. We then lie to the verifier
    // by claiming fib(1024) = X + 1.
    let (proof, real_inputs) = prove_fib(1024).expect("prove");
    let lying_inputs = FibInputs {
        result: real_inputs.result + BaseElement::ONE,
    };
    let res = verify_fib(&proof, lying_inputs);
    assert!(res.is_err(), "verifier MUST reject wrong public input, got Ok");
}

#[test]
fn rejects_garbage_public_input() {
    // A claim that has nothing to do with the actual computation.
    let (proof, _) = prove_fib(1024).expect("prove");
    let lying_inputs = FibInputs { result: BaseElement::new(42) };
    let res = verify_fib(&proof, lying_inputs);
    assert!(res.is_err(), "verifier MUST reject garbage public input, got Ok");
}

#[test]
fn rejects_tampered_proof_byte() {
    // Flip a random byte in the middle of the proof. Should fail to deserialize
    // or fail to verify.
    let (mut proof, pub_inputs) = prove_fib(1024).expect("prove");
    // Flip a byte well inside the body
    let target = proof.len() / 2;
    proof[target] ^= 0xFF;
    let res = verify_fib(&proof, pub_inputs);
    assert!(res.is_err(), "verifier MUST reject tampered proof, got Ok");
}

#[test]
fn rejects_truncated_proof() {
    let (proof, pub_inputs) = prove_fib(1024).expect("prove");
    let truncated = &proof[..proof.len() - 100];
    let res = verify_fib(truncated, pub_inputs);
    assert!(res.is_err(), "verifier MUST reject truncated proof, got Ok");
}

#[test]
fn rejects_empty_proof() {
    let pub_inputs = FibInputs { result: BaseElement::new(1) };
    let res = verify_fib(&[], pub_inputs);
    assert!(res.is_err(), "verifier MUST reject empty proof, got Ok");
}

#[test]
fn rejects_proof_of_one_size_for_another() {
    // A proof for fib(1024) shouldn't verify with a claim about fib(2048).
    // The proof is bound to its trace size internally.
    let (proof_1024, _) = prove_fib(1024).expect("prove");
    let fib_2048 = fib_native(2048);
    let lying_inputs = FibInputs { result: fib_2048 };
    let res = verify_fib(&proof_1024, lying_inputs);
    assert!(res.is_err(), "verifier MUST reject when claim and proof disagree on size");
}

#[test]
fn many_random_tampers_all_rejected() {
    // Stronger soundness: 50 different random byte-flips should ALL be rejected.
    // Helps catch the case where one specific byte happens to be in a header
    // field that the verifier doesn't actually check.
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    let mut rng_state = seed as u64;
    let next_random = |rng_state: &mut u64| -> u64 {
        // Tiny PCG-ish hash for reproducibility from a u64
        *rng_state = rng_state.wrapping_mul(6364136223846793005)
                              .wrapping_add(1442695040888963407);
        *rng_state
    };

    let (proof, pub_inputs) = prove_fib(1024).expect("prove");
    let mut accepted_bad = 0;
    for _ in 0..50 {
        let mut bad = proof.clone();
        let idx = (next_random(&mut rng_state) as usize) % bad.len();
        let flip = (next_random(&mut rng_state) & 0xFF) as u8 | 1; // non-zero
        bad[idx] ^= flip;
        if verify_fib(&bad, pub_inputs.clone()).is_ok() {
            accepted_bad += 1;
        }
    }
    assert_eq!(accepted_bad, 0,
               "verifier MUST reject all 50 random byte-flips, accepted {}",
               accepted_bad);
}

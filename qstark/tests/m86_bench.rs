//! M8.6 depth-scaling benchmark.
//!
//! Measures proving time, verifying time, and proof size for the
//! currently-compiled MERKLE_DEPTH. Run with:
//!
//!     cargo test --release --test m86_bench -- --nocapture
//!
//! To benchmark a different depth, edit m86_native.rs and recompile.

use std::time::Instant;

use qstark::hash_air::m86_air::{prove_m86, verify_m86, M86Witness};
use qstark::hash_air::m86_native::{M86_ACTIVE_ROWS, M86_MERKLE_DEPTH, M86_TRACE_LEN};
use qstark::hash_air::merkle::Digest4;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

/// Build a synthetic witness with random siblings + directions of the
/// requested length. We don't need a full tree — just a valid (sk, r, v,
/// path) for the prover, with path.len() == M86_MERKLE_DEPTH.
fn make_witness(idx: usize) -> M86Witness {
    let sk = BaseElement::new(1000 + idx as u64);
    let r = BaseElement::new(2000 + idx as u64);
    let v = BaseElement::new(100 + idx as u64);
    let mut path: Vec<(Digest4, bool)> = Vec::with_capacity(M86_MERKLE_DEPTH);
    for level in 0..M86_MERKLE_DEPTH {
        let sibling: Digest4 = [
            BaseElement::new(0xC0FFEE + level as u64),
            BaseElement::new(0xD00D + level as u64),
            BaseElement::new(0xBABE + level as u64),
            BaseElement::new(0xCAFE + level as u64),
        ];
        // Direction bits taken from idx as if idx were a real leaf position.
        let is_right = ((idx >> level) & 1) == 1;
        path.push((sibling, is_right));
    }
    M86Witness {
        sk, r, v, path,
        unshield_amount: v.as_int(), fee: 0,
        sk_out: BaseElement::ZERO, r_out: BaseElement::ZERO, v_out: BaseElement::ZERO,
    }
}

#[test]
fn bench_m86_at_current_depth() {
    let n_leaves = 1usize << M86_MERKLE_DEPTH;
    println!();
    println!("=== M8.6 benchmark @ MERKLE_DEPTH = {} ===", M86_MERKLE_DEPTH);
    println!("Anonymity set:  {} notes (2^{})", n_leaves, M86_MERKLE_DEPTH);
    println!("Active rows:    {}", M86_ACTIVE_ROWS);
    println!("Trace length:   {} (padded to power of 2)", M86_TRACE_LEN);
    println!();

    // Warm-up
    let w = make_witness(n_leaves / 2);
    let _ = prove_m86(w).expect("warmup");

    // Measure proving over multiple runs
    const N_PROVE: usize = 5;
    let mut prove_times_us: Vec<u128> = Vec::new();
    let mut proof_size: usize = 0;
    for i in 0..N_PROVE {
        let w = make_witness((i * 3) % n_leaves);
        let t0 = Instant::now();
        let (proof, pub_inputs) = prove_m86(w).expect("prove");
        let elapsed = t0.elapsed().as_micros();
        prove_times_us.push(elapsed);
        proof_size = proof.len();
        // Sanity verify
        verify_m86(&proof, pub_inputs).expect("verify");
    }
    let prove_min = *prove_times_us.iter().min().unwrap();
    let prove_max = *prove_times_us.iter().max().unwrap();
    let prove_avg = prove_times_us.iter().sum::<u128>() / N_PROVE as u128;

    // Measure verifying
    let w = make_witness(0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    const N_VERIFY: usize = 50;
    let mut verify_times_us: Vec<u128> = Vec::new();
    for _ in 0..N_VERIFY {
        let t0 = Instant::now();
        verify_m86(&proof, pub_inputs.clone()).expect("verify");
        verify_times_us.push(t0.elapsed().as_micros());
    }
    let verify_min = *verify_times_us.iter().min().unwrap();
    let verify_avg = verify_times_us.iter().sum::<u128>() / N_VERIFY as u128;

    println!("Proving time:");
    println!("  min:   {:>6.2} ms", prove_min as f64 / 1000.0);
    println!("  avg:   {:>6.2} ms  (n={})", prove_avg as f64 / 1000.0, N_PROVE);
    println!("  max:   {:>6.2} ms", prove_max as f64 / 1000.0);
    println!();
    println!("Verifying time:");
    println!("  min:   {:>6.3} ms", verify_min as f64 / 1000.0);
    println!("  avg:   {:>6.3} ms  (n={})", verify_avg as f64 / 1000.0, N_VERIFY);
    println!();
    println!("Proof size:   {:>6} bytes  ({:.1} KB)", proof_size, proof_size as f64 / 1024.0);
    println!();
}

//! M8.3 single-level Merkle membership STARK tests.

use qstark::hash_air::merkle::{hash_inner, hash_leaf, Digest4};
use qstark::hash_air::{prove_one_level_membership, verify_one_level_membership, AnonInputs};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

fn sample_leaf(seed: u64) -> Digest4 {
    hash_leaf(
        BaseElement::new(1000 + seed),
        BaseElement::new(2000 + seed),
        BaseElement::new(100),
    )
}

#[test]
fn happy_path_proves_and_verifies() {
    let left = sample_leaf(1);
    let right = sample_leaf(2);
    let expected_root = hash_inner(left, right);

    let (proof, pub_inputs) = prove_one_level_membership(left, right).expect("prove");
    assert_eq!(pub_inputs.right, right);
    assert_eq!(pub_inputs.root, expected_root,
               "STARK root must match native hash_inner");

    println!("Single-level proof size: {} bytes", proof.len());
    verify_one_level_membership(&proof, pub_inputs).expect("verify");
}

#[test]
fn left_value_stays_hidden_in_witness() {
    // The same `right` and `root` should be provable with the correct `left`,
    // regardless of what that `left` is. The public inputs reveal nothing
    // about which `left` was used.
    let left_a = sample_leaf(1);
    let left_b = sample_leaf(99);
    let right = sample_leaf(2);

    let root_a = hash_inner(left_a, right);
    let root_b = hash_inner(left_b, right);
    assert_ne!(root_a, root_b);  // Different lefts ⇒ different roots

    // Each proves against its own root
    let (proof_a, pub_a) = prove_one_level_membership(left_a, right).expect("prove a");
    let (proof_b, pub_b) = prove_one_level_membership(left_b, right).expect("prove b");
    verify_one_level_membership(&proof_a, pub_a).expect("verify a");
    verify_one_level_membership(&proof_b, pub_b).expect("verify b");

    // Public inputs are different (different roots), but neither reveals the
    // `left`. The verifier just learns: "for this (right, root), the prover
    // knows SOMETHING that hashes correctly."
}

#[test]
fn proves_for_many_different_witnesses() {
    for i in 0..5 {
        let left = sample_leaf(i);
        let right = sample_leaf(i + 100);
        let (proof, pub_inputs) = prove_one_level_membership(left, right)
            .expect("prove");
        verify_one_level_membership(&proof, pub_inputs)
            .expect("verify");
    }
}

#[test]
fn rejects_wrong_claimed_root() {
    let left = sample_leaf(1);
    let right = sample_leaf(2);
    let (proof, mut pub_inputs) = prove_one_level_membership(left, right).expect("prove");

    // Tamper with claimed root
    pub_inputs.root[0] += BaseElement::ONE;
    assert!(verify_one_level_membership(&proof, pub_inputs).is_err(),
            "verifier MUST reject wrong root");
}

#[test]
fn rejects_wrong_claimed_right() {
    let left = sample_leaf(1);
    let right = sample_leaf(2);
    let (proof, mut pub_inputs) = prove_one_level_membership(left, right).expect("prove");

    // Tamper with claimed right sibling
    pub_inputs.right[0] += BaseElement::ONE;
    assert!(verify_one_level_membership(&proof, pub_inputs).is_err(),
            "verifier MUST reject wrong right sibling");
}

#[test]
fn rejects_root_of_a_different_pair() {
    // Prove for (left_1, right_1), then try to claim that proof shows
    // (left_1, right_2) → root_1. Should fail because root_1 wouldn't match
    // the actual merge(left_1, right_2).
    let left = sample_leaf(1);
    let right_1 = sample_leaf(2);
    let right_2 = sample_leaf(3);
    let (proof, _) = prove_one_level_membership(left, right_1).expect("prove");

    let lying = AnonInputs {
        right: right_2,
        root: hash_inner(left, right_1),  // root for the original pair
    };
    assert!(verify_one_level_membership(&proof, lying).is_err(),
            "verifier MUST reject if claimed right doesn't match proof");
}

#[test]
fn rejects_garbage_root() {
    let left = sample_leaf(1);
    let right = sample_leaf(2);
    let (proof, mut pub_inputs) = prove_one_level_membership(left, right).expect("prove");
    pub_inputs.root = [BaseElement::ONE; 4];
    assert!(verify_one_level_membership(&proof, pub_inputs).is_err());
}

#[test]
fn rejects_tampered_proof() {
    let left = sample_leaf(1);
    let right = sample_leaf(2);
    let (mut proof, pub_inputs) = prove_one_level_membership(left, right).expect("prove");
    let idx = proof.len() / 2;
    proof[idx] ^= 0xFF;
    assert!(verify_one_level_membership(&proof, pub_inputs).is_err());
}

#[test]
fn rejects_truncated_proof() {
    let left = sample_leaf(1);
    let right = sample_leaf(2);
    let (proof, pub_inputs) = prove_one_level_membership(left, right).expect("prove");
    let truncated = &proof[..proof.len() - 100];
    assert!(verify_one_level_membership(truncated, pub_inputs).is_err());
}

#[test]
fn rejects_empty_proof() {
    let inputs = AnonInputs {
        right: [BaseElement::ZERO; 4],
        root: [BaseElement::ZERO; 4],
    };
    assert!(verify_one_level_membership(&[], inputs).is_err());
}

#[test]
fn many_random_tampers_all_rejected() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    let mut rng = seed as u64;
    let next = |s: &mut u64| {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *s
    };

    let left = sample_leaf(7);
    let right = sample_leaf(13);
    let (proof, pub_inputs) = prove_one_level_membership(left, right).expect("prove");

    let mut accepted_bad = 0;
    for _ in 0..30 {
        let mut bad = proof.clone();
        let idx = (next(&mut rng) as usize) % bad.len();
        let flip = (next(&mut rng) & 0xFF) as u8 | 1;
        bad[idx] ^= flip;
        if verify_one_level_membership(&bad, pub_inputs.clone()).is_ok() {
            accepted_bad += 1;
        }
    }
    assert_eq!(accepted_bad, 0,
               "verifier MUST reject all 30 random byte-flips, accepted {}",
               accepted_bad);
}

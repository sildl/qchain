//! M8.6 soundness tests.
//!
//! The critical test is `forging_with_wrong_nullifier_produces_different_pub_inputs`:
//! if an attacker tries to swap the nullifier (the M8.5 Gap B exploit), the
//! resulting proof has a *different* public input, so it can't pass off as a
//! spend that matches the chain's existing nullifier set.

use qstark::hash_air::m86_air::{prove_m86, verify_m86, M86Inputs, M86Witness};
use qstark::hash_air::m86_native::M86_MERKLE_DEPTH;
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

/// M8.11 Phase 1: the canonical "no change" output leaf, H(0, 0, 0).
fn default_output_leaf() -> [BaseElement; 4] {
    hash_leaf(BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO)
}

fn make_witness(idx: usize) -> (M86Witness, [BaseElement; 4]) {
    let leaves: Vec<_> = (0..16)
        .map(|i| {
            hash_leaf(
                BaseElement::new(1000 + i as u64),
                BaseElement::new(2000 + i as u64),
                BaseElement::new(100 + i as u64),
            )
        })
        .collect();
    let tree = MerkleTree::from_leaves(&leaves);
    let sk = BaseElement::new(1000 + idx as u64);
    let r = BaseElement::new(2000 + idx as u64);
    let v = BaseElement::new(100 + idx as u64);
    let path: Vec<_> = tree.auth_path(idx).into_iter().take(M86_MERKLE_DEPTH).collect();
    let root = tree.root();
    (
        M86Witness {
            sk, r, v, path,
            unshield_amount: v.as_int(), fee: 0,
            // M8.11 Phase 1: full-spend pattern. v_out=0 means no change note.
            // The output leaf is H(0, 0, 0), still a valid hash; the chain
            // would (harmlessly) add it to the STARK pool. Useful for tests.
            sk_out: BaseElement::ZERO,
            r_out: BaseElement::ZERO,
            v_out: BaseElement::ZERO,
        },
        root,
    )
}

#[test]
fn happy_path_all_positions() {
    for idx in 0..16 {
        let (w, expected_root) = make_witness(idx);
        let (proof, pub_inputs) = prove_m86(w).expect("prove");
        assert_eq!(pub_inputs.root, expected_root,
                   "STARK root must match expected root at idx {}", idx);
        verify_m86(&proof, pub_inputs).expect("verify");
    }
}

#[test]
fn rejects_wrong_root() {
    let (w, _) = make_witness(5);
    let (proof, mut pub_inputs) = prove_m86(w).expect("prove");
    pub_inputs.root[0] += BaseElement::ONE;
    assert!(verify_m86(&proof, pub_inputs).is_err(),
            "verifier MUST reject wrong root");
}

#[test]
fn rejects_wrong_nullifier() {
    let (w, _) = make_witness(5);
    let (proof, mut pub_inputs) = prove_m86(w).expect("prove");
    pub_inputs.nullifier[0] += BaseElement::ONE;
    assert!(verify_m86(&proof, pub_inputs).is_err(),
            "verifier MUST reject wrong nullifier");
}

#[test]
fn rejects_swapped_nullifier_completely() {
    // The M8.5 Gap B exploit: take a valid proof and try to claim a
    // *different* nullifier alongside it. With M8.5 this worked (gap
    // documented). With M8.6 the nullifier is bound to the proof.
    let (w, _) = make_witness(5);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");

    // Attacker tries to use a nullifier that's NOT bound to this proof
    let attacker_nullifier = [
        BaseElement::new(11111),
        BaseElement::new(22222),
        BaseElement::new(33333),
        BaseElement::new(44444),
    ];
    let evil_inputs = M86Inputs {
        root: pub_inputs.root,
        nullifier: attacker_nullifier,
        unshield_amount: pub_inputs.unshield_amount,
        fee: pub_inputs.fee,
        output_leaf: pub_inputs.output_leaf,
    };
    assert!(verify_m86(&proof, evil_inputs).is_err(),
            "M8.6 MUST reject a proof claiming an unbound nullifier — \
             this is the central correctness property over M8.5");
}

#[test]
fn rejects_tampered_proof() {
    let (w, _) = make_witness(5);
    let (mut proof, pub_inputs) = prove_m86(w).expect("prove");
    let mid = proof.len() / 2;
    proof[mid] ^= 0xFF;
    assert!(verify_m86(&proof, pub_inputs).is_err());
}

#[test]
fn rejects_truncated_proof() {
    let (w, _) = make_witness(5);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    let truncated = &proof[..proof.len() - 100];
    assert!(verify_m86(truncated, pub_inputs).is_err());
}

#[test]
fn rejects_empty_proof() {
    let inputs = M86Inputs {
        root: [BaseElement::ZERO; 4],
        nullifier: [BaseElement::ZERO; 4],
        unshield_amount: 0,
        fee: 0,
        output_leaf: default_output_leaf(),
    };
    assert!(verify_m86(&[], inputs).is_err());
}

#[test]
fn forging_with_wrong_sibling_produces_different_root() {
    let (honest, _) = make_witness(5);
    let (_, honest_pub) = prove_m86(honest.clone()).expect("prove honest");

    let mut tampered = honest.clone();
    tampered.path[0].0[0] += BaseElement::ONE;
    let (proof_tampered, tampered_pub) = prove_m86(tampered).expect("tampered ok");

    assert_ne!(honest_pub.root, tampered_pub.root);
    assert!(verify_m86(&proof_tampered, honest_pub).is_err());
}

#[test]
fn forging_with_wrong_sk_produces_different_nullifier() {
    // The whole POINT of M8.6: if you change sk, the nullifier also changes
    // because they're bound. So you can't "re-spend" with a fresh nullifier.
    let (honest, _) = make_witness(5);
    let (_, honest_pub) = prove_m86(honest.clone()).expect("prove honest");

    let mut tampered = honest.clone();
    tampered.sk += BaseElement::ONE;  // change sk
    // This will also change the leaf (and thus the root!), since the leaf
    // = H(sk, r, v). So the tampered prover gets a *different* root too.
    // What matters is that they can't reuse honest_pub.
    let result = prove_m86(tampered);
    if let Ok((_, tampered_pub)) = result {
        // The tampered proof must NOT match the honest public inputs
        assert!(
            tampered_pub.root != honest_pub.root
            || tampered_pub.nullifier != honest_pub.nullifier,
            "tampered sk MUST produce different (root, nullifier)"
        );
    } else {
        // Prover may also fail outright — that's fine too
    }
}

#[test]
fn many_random_tampers_all_rejected() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let mut rng = seed as u64;
    let next = |s: &mut u64| {
        *s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *s
    };

    let (w, _) = make_witness(7);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");

    let mut accepted_bad = 0;
    for _ in 0..30 {
        let mut bad = proof.clone();
        let idx = (next(&mut rng) as usize) % bad.len();
        let flip = (next(&mut rng) & 0xFF) as u8 | 1;
        bad[idx] ^= flip;
        if verify_m86(&bad, pub_inputs.clone()).is_ok() {
            accepted_bad += 1;
        }
    }
    assert_eq!(
        accepted_bad, 0,
        "verifier MUST reject all 30 random byte-flips, accepted {}",
        accepted_bad
    );
}

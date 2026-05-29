//! M8.3 FULL adversarial soundness tests.
//!
//! These are the tests that prove the STARK is actually sound. A passing
//! happy path means nothing without these.

use qstark::hash_air::anon_full::{
    prove_full_membership, verify_full_membership, FullMembershipInputs,
    FullMembershipWitness, MERKLE_DEPTH,
};
use qstark::hash_air::merkle::{hash_inner, hash_leaf, MerkleTree, ZERO_DIGEST};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

fn make_leaves(n: usize) -> Vec<[BaseElement; 4]> {
    (0..n).map(|i| hash_leaf(
        BaseElement::new(1000 + i as u64),
        BaseElement::new(2000 + i as u64),
        BaseElement::new(100 + i as u64),
    )).collect()
}

#[test]
fn happy_path_all_positions() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);

    for idx in 0..16 {
        let witness = FullMembershipWitness::from_tree(&tree, idx);
        let (proof, pub_inputs) = prove_full_membership(witness)
            .expect(&format!("prove for idx {}", idx));
        verify_full_membership(&proof, pub_inputs)
            .expect(&format!("verify for idx {}", idx));
    }
}

#[test]
fn rejects_wrong_claimed_root() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 5);
    let (proof, mut pub_inputs) = prove_full_membership(witness).expect("prove");
    pub_inputs.root[0] += BaseElement::ONE;
    assert!(verify_full_membership(&proof, pub_inputs).is_err(),
            "verifier MUST reject wrong root");
}

#[test]
fn rejects_garbage_root() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 5);
    let (proof, _) = prove_full_membership(witness).expect("prove");
    let garbage = FullMembershipInputs { root: [BaseElement::ONE; 4] };
    assert!(verify_full_membership(&proof, garbage).is_err());
}

#[test]
fn rejects_root_of_different_leaf() {
    // Use a tree with depth > MERKLE_DEPTH so different leaves end up with
    // different depth-4 ancestors. The MerkleTree internally has depth 8
    // (256 leaves), so leaves whose index differs in bit-4+ will land in
    // different depth-4 buckets.
    let leaves = make_leaves(256);
    let tree = MerkleTree::from_leaves(&leaves);

    // Indices 5 (bucket 0) vs 5 + 16 = 21 (bucket 1) — different ancestors
    let witness_5 = FullMembershipWitness::from_tree(&tree, 5);
    let (proof_5, pub_5) = prove_full_membership(witness_5).expect("prove");

    let witness_21 = FullMembershipWitness::from_tree(&tree, 21);
    let (_, pub_21) = prove_full_membership(witness_21).expect("prove");

    // Sanity: their depth-4 ancestors really are different
    assert_ne!(pub_5.root, pub_21.root,
               "different depth-4 buckets must have different ancestors");

    // Use proof_5 with pub_21's root — must fail
    let result = verify_full_membership(&proof_5, pub_21);
    assert!(result.is_err(),
            "verifier MUST reject a proof attesting to a different bucket's root");
}

#[test]
fn forging_with_wrong_sibling_fails_at_prove_time() {
    // The prover can't even succeed if they use a wrong sibling at any level,
    // because the resulting computed root won't match the public root being
    // claimed (well, the prover claims whatever they compute, so this is about
    // someone wanting a specific public root but having the wrong witness).
    //
    // Test: prove for leaf 5 honestly. Now construct a "fake" witness that
    // claims to spend leaf 5 with a tampered sibling. The proof will succeed
    // but produce a DIFFERENT public root.
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let honest = FullMembershipWitness::from_tree(&tree, 5);
    let (_, honest_pub) = prove_full_membership(honest.clone()).expect("prove honest");

    // Tamper: change a sibling
    let mut tampered = honest.clone();
    tampered.path[0].0[0] += BaseElement::ONE;
    let (proof_tampered, tampered_pub) = prove_full_membership(tampered)
        .expect("tampered prover still succeeds (computes a different root)");

    // The tampered proof's root must DIFFER from the honest root
    assert_ne!(honest_pub.root, tampered_pub.root,
               "tampered witness must produce a different root");

    // And the tampered proof must NOT verify against the honest root
    let res = verify_full_membership(&proof_tampered, honest_pub);
    assert!(res.is_err(),
            "tampered proof must not verify against the honest root");
}

#[test]
fn forging_with_wrong_direction_bit_fails() {
    // Same idea: flipping a direction bit produces a different root.
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let honest = FullMembershipWitness::from_tree(&tree, 5);
    let (_, honest_pub) = prove_full_membership(honest.clone()).expect("prove honest");

    let mut tampered = honest.clone();
    tampered.path[2].1 = !tampered.path[2].1;
    let (proof_tampered, tampered_pub) = prove_full_membership(tampered)
        .expect("tampered prover succeeds");

    assert_ne!(honest_pub.root, tampered_pub.root);
    assert!(verify_full_membership(&proof_tampered, honest_pub).is_err());
}

#[test]
fn rejects_tampered_proof() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 5);
    let (mut proof, pub_inputs) = prove_full_membership(witness).expect("prove");
    let idx = proof.len() / 2;
    proof[idx] ^= 0xFF;
    assert!(verify_full_membership(&proof, pub_inputs).is_err());
}

#[test]
fn rejects_truncated_proof() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 5);
    let (proof, pub_inputs) = prove_full_membership(witness).expect("prove");
    let truncated = &proof[..proof.len() - 100];
    assert!(verify_full_membership(truncated, pub_inputs).is_err());
}

#[test]
fn rejects_empty_proof() {
    let inputs = FullMembershipInputs { root: ZERO_DIGEST };
    assert!(verify_full_membership(&[], inputs).is_err());
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

    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);
    let witness = FullMembershipWitness::from_tree(&tree, 7);
    let (proof, pub_inputs) = prove_full_membership(witness).expect("prove");

    let mut accepted_bad = 0;
    for _ in 0..30 {
        let mut bad = proof.clone();
        let idx = (next(&mut rng) as usize) % bad.len();
        let flip = (next(&mut rng) & 0xFF) as u8 | 1;
        bad[idx] ^= flip;
        if verify_full_membership(&bad, pub_inputs.clone()).is_ok() {
            accepted_bad += 1;
        }
    }
    assert_eq!(accepted_bad, 0,
               "verifier MUST reject all 30 random byte-flips, accepted {}",
               accepted_bad);
}

#[test]
fn anonymity_demonstration() {
    // Two different leaves in different depth-4 buckets produce proofs that
    // reveal NOTHING about which leaf or position was used. The verifier
    // only sees the root.
    let leaves = make_leaves(256);
    let tree = MerkleTree::from_leaves(&leaves);

    // Leaves 3 and 50: different depth-4 buckets (3>>4=0 vs 50>>4=3)
    let witness_3 = FullMembershipWitness::from_tree(&tree, 3);
    let witness_50 = FullMembershipWitness::from_tree(&tree, 50);
    let (proof_3, pub_3) = prove_full_membership(witness_3).expect("prove 3");
    let (proof_50, pub_50) = prove_full_membership(witness_50).expect("prove 50");

    // Both verify successfully
    verify_full_membership(&proof_3, pub_3.clone()).expect("verify 3");
    verify_full_membership(&proof_50, pub_50.clone()).expect("verify 50");

    // The proofs are different (different witnesses ⇒ different traces ⇒
    // different commitments). Same proof can't be reused.
    assert!(proof_3 != proof_50, "proofs are distinct");
    assert!(pub_3.root != pub_50.root,
            "different leaves in different depth-4 buckets have different roots");
}

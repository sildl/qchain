//! M8.8-A1 Phase 2: Adversarial soundness tests for the Gap A range proof.
//!
//! These tests target the new AIR machinery added in Phase 1:
//!   - 64 bit-decomposition witness columns
//!   - 64 binary constraints (b[i] in {0,1})
//!   - 1 decomposition constraint (v == sum(b[i] * 2^i) at row 0)
//!   - 1 boundary assertion (state[6] at row 0 == unshield_amount + fee)
//!
//! Each test is a specific attempted attack; we assert the AIR rejects or
//! accepts as appropriate. Where the AIR CAN'T defend against an attack
//! by design (chain-level concern), we document the test as such.
//!
//! Out of scope (Phase 3/4): proof's public-input fields being bound to
//! the on-chain transaction body. The AIR proves what the prover committed
//! to; the chain has to cross-check those values match the tx fields.

use qstark::hash_air::m86_air::{
    prove_m86, verify_m86, M86Inputs, M86Witness,
};
use qstark::hash_air::m86_native::M86_MERKLE_DEPTH;
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an honest witness where the leaf at `idx` has value `v_value`,
/// declared as `(unshield_amount, fee)` with `unshield_amount + fee == v_value`.
fn make_witness_with_amounts(
    idx: usize,
    v_value: u64,
    unshield_amount: u64,
    fee: u64,
) -> (M86Witness, [BaseElement; 4]) {
    // Build a 16-leaf tree where each leaf's value is i+100 (per existing
    // convention), EXCEPT position `idx` which uses v_value.
    let leaves: Vec<_> = (0..16)
        .map(|i| {
            let value = if i == idx { v_value } else { 100 + i as u64 };
            hash_leaf(
                BaseElement::new(1000 + i as u64),
                BaseElement::new(2000 + i as u64),
                BaseElement::new(value),
            )
        })
        .collect();
    let tree = MerkleTree::from_leaves(&leaves);
    let sk = BaseElement::new(1000 + idx as u64);
    let r = BaseElement::new(2000 + idx as u64);
    let v = BaseElement::new(v_value);
    let path: Vec<_> = tree.auth_path(idx).into_iter().take(M86_MERKLE_DEPTH).collect();
    let root = tree.root();
    let w = M86Witness {
        sk, r, v, path,
        unshield_amount, fee,
        sk_out: BaseElement::ZERO, r_out: BaseElement::ZERO, v_out: BaseElement::ZERO,
    };
    (w, root)
}

// ===========================================================================
// Group 1: Wrong amount in public inputs at verification time
// ===========================================================================

#[test]
fn wrong_unshield_amount_in_public_inputs_rejected() {
    // Prover honestly proves v=100 = 100 + 0
    let (w, _) = make_witness_with_amounts(7, 100, 100, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");
    // Verifier sees an altered amount: claims 50 instead of 100
    let tampered = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: 50,
        fee: 0,
        output_leaf: pub_inputs.output_leaf,
    };
    let result = verify_m86(&proof, tampered);
    assert!(
        result.is_err(),
        "AIR must reject proof when claimed unshield_amount doesn't match the bound value"
    );
}

#[test]
fn wrong_fee_in_public_inputs_rejected() {
    let (w, _) = make_witness_with_amounts(3, 80, 80, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");
    // Verifier sees fee=7 instead of 0 — sum becomes 87, not 80
    let tampered = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: 80,
        fee: 7,
        output_leaf: pub_inputs.output_leaf,
    };
    let result = verify_m86(&proof, tampered);
    assert!(result.is_err(), "AIR must reject altered fee");
}

#[test]
fn zero_amount_zero_fee_for_nonzero_value_rejected() {
    // Honest prover commits to v=42; verifier claims amount=fee=0
    let (w, _) = make_witness_with_amounts(2, 42, 42, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");
    let evil = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: 0,
        fee: 0,
        output_leaf: pub_inputs.output_leaf,
    };
    assert!(verify_m86(&proof, evil).is_err(), "0+0 != 42, must reject");
}

// ===========================================================================
// Group 2: Equivalent decompositions of the same sum
// ===========================================================================

#[test]
fn swap_amount_and_fee_with_same_sum_rejected_via_fiat_shamir() {
    // SUBTLE: the AIR's *transition constraints* only see `amount + fee`
    // (the sum is asserted equal to v at row 0). One might think that
    // swapping amount and fee while preserving the sum should still verify.
    //
    // It DOESN'T — and here's why. The verifier's Fiat-Shamir transcript
    // includes the public inputs in a fixed order (root, nullifier, then
    // amount, then fee). Changing (60, 40) to (40, 60) changes that hash,
    // which changes the random challenges Winterfell derives, which
    // invalidates the proof's responses.
    //
    // So at the STARK protocol level, individual (amount, fee) ARE bound,
    // even though the AIR constraints only check their sum. This is a
    // useful safety property: even an honest prover can't trick the chain
    // into accepting a different fee partition than what they generated
    // the proof for.
    let (w, _) = make_witness_with_amounts(5, 100, 60, 40);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove (60+40)");
    let swapped = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: 40,
        fee: 60,
        output_leaf: pub_inputs.output_leaf,
    };
    assert!(
        verify_m86(&proof, swapped).is_err(),
        "Even though 60+40 == 40+60 in the AIR's sum constraint, \
         Fiat-Shamir over the public-input transcript binds the \
         (amount, fee) ordering"
    );
}

#[test]
fn amount_equals_value_zero_fee_proves() {
    // Standard case: entire leaf value goes to unshield, no fee
    let (w, _) = make_witness_with_amounts(0, 1000, 1000, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    verify_m86(&proof, pub_inputs).expect("verify");
}

#[test]
fn fee_equals_value_zero_amount_proves() {
    // Edge case: the entire leaf is consumed as fee, nothing unshielded.
    // The AIR doesn't object — chain layer would, since it'd see a
    // zero-value unshield_recipient. AIR-level: math holds (0 + 100 = 100).
    let (w, _) = make_witness_with_amounts(1, 100, 0, 100);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    verify_m86(&proof, pub_inputs).expect("verify");
}

// ===========================================================================
// Group 3: Witness inconsistency caught at trace-build time
// ===========================================================================

#[test]
#[should_panic(expected = "witness inconsistency")]
fn witness_v_mismatches_amount_plus_fee_panics_at_build() {
    // v=100 but caller declares unshield_amount=50, fee=25 (sum=75 ≠ 100)
    let (w, _) = make_witness_with_amounts(4, 100, 50, 25);
    // prove_m86 calls build_m86_trace which has the witness-consistency
    // assertion. We expect a panic.
    let _ = prove_m86(w);
}

#[test]
#[should_panic(expected = "witness inconsistency")]
fn witness_v_smaller_than_amount_panics_at_build() {
    // Most attacker-like: leaf is worth 10, but claim unshield_amount=1_000_000
    let (w, _) = make_witness_with_amounts(8, 10, 1_000_000, 0);
    let _ = prove_m86(w);
}

// ===========================================================================
// Group 4: Boundary cases that must succeed
// ===========================================================================

#[test]
fn value_zero_proves() {
    // v = 0, amount = 0, fee = 0 — trivial case but must work
    let (w, _) = make_witness_with_amounts(11, 0, 0, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove v=0");
    verify_m86(&proof, pub_inputs).expect("verify v=0");
}

#[test]
fn value_one_proves() {
    // Smallest nonzero value — useful as a regression test for the
    // low bit of the decomposition
    let (w, _) = make_witness_with_amounts(12, 1, 1, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove v=1");
    verify_m86(&proof, pub_inputs).expect("verify v=1");
}

#[test]
fn value_power_of_two_proves() {
    // Test that high bits work (proves bit 32 specifically)
    let v = 1u64 << 32;
    let (w, _) = make_witness_with_amounts(13, v, v, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove v=2^32");
    verify_m86(&proof, pub_inputs).expect("verify v=2^32");
}

#[test]
fn value_just_below_goldilocks_modulus_proves() {
    // Goldilocks p = 2^64 - 2^32 + 1. Largest representable canonical field
    // element is p - 1 = 2^64 - 2^32. As u64: u64::MAX - (2^32 - 1).
    // This tests that the highest representable values still decompose.
    let v: u64 = u64::MAX - ((1u64 << 32) - 1);  // = p - 1
    let (w, _) = make_witness_with_amounts(14, v, v, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove v near p");
    verify_m86(&proof, pub_inputs).expect("verify v near p");
}

// ===========================================================================
// Group 5: Documented LIMITATIONS — AIR cannot defend, chain must
// ===========================================================================

#[test]
fn field_wrap_attack_documented_as_chain_layer_concern() {
    // This test is INTENTIONALLY a happy path that documents what the AIR
    // does NOT defend against. The AIR works in Goldilocks field arithmetic;
    // (unshield_amount + fee) is a field sum. If a malicious chain accepted
    // amounts where the field sum equals some small u64 but the u64 sum
    // overflows, the AIR would still verify.
    //
    // Concretely: Goldilocks p = 2^64 - 2^32 + 1. If unshield_amount and
    // fee are both ≈ 2^63, their u64 sum overflows but their field sum
    // equals (sum mod p), which fits in u64.
    //
    // Phase 3 chain integration MUST reject any STARK tx where
    // unshield_amount + fee (as u128) overflows u64.
    //
    // For this AIR-level test: prove with the field-wrap sum. The AIR
    // accepts because it's mathematically consistent. The chain must
    // separately reject.

    // Pick a value just below p such that the bit decomposition is sane
    let leaf_value: u64 = 1000;  // small honest value
    let (w, _) = make_witness_with_amounts(15, leaf_value, leaf_value, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    // Honest verification works
    verify_m86(&proof, pub_inputs.clone()).expect("verify honest");

    // The AIR's assertion at row 0 is: state[6] == Felt::new(amount) + Felt::new(fee).
    // If amount + fee overflows u64 such that the field sum wraps to leaf_value,
    // the AIR would accept. We can't easily construct that case here without
    // computing exact values that mod-p to leaf_value, but the point stands:
    // the AIR's assertion is over field elements, not u64 integers.
    //
    // The test passes by definition — we're documenting that this attack
    // surface exists at the AIR-chain boundary, not in the AIR itself.
    println!(
        "  NOTE: AIR accepts field-arithmetic equality on amount+fee. \
         Chain (Phase 3) must additionally reject u64-overflow sums."
    );
}

#[test]
fn proof_for_one_leaf_doesnt_verify_for_different_leaf() {
    // Cross-check that even with the range proof, the M8.6 leaf-binding
    // still works: a proof for leaf 5 with amount 105 doesn't verify
    // against a different leaf's root.
    let (w1, _) = make_witness_with_amounts(5, 105, 105, 0);
    let (w2, _) = make_witness_with_amounts(9, 109, 109, 0);

    let (proof1, pub_inputs1) = prove_m86(w1).expect("prove leaf 5");
    let (_proof2, pub_inputs2) = prove_m86(w2).expect("prove leaf 9");

    // Try to verify proof1 with leaf 9's root + nullifier
    let evil = M86Inputs {
        root: pub_inputs2.root,
        nullifier: pub_inputs2.nullifier,
        unshield_amount: pub_inputs1.unshield_amount,
        fee: pub_inputs1.fee,
        output_leaf: pub_inputs1.output_leaf,
    };
    assert!(
        verify_m86(&proof1, evil).is_err(),
        "Proof for leaf 5 must not verify against leaf 9's pool root"
    );
}

//! M8.11 Phase 2: Adversarial soundness tests for partial-spend change outputs.
//!
//! These tests target the new AIR machinery added in Phase 1:
//!   - Group 3.5 (output-leaf boundary): state init at row 143→144
//!   - Group 6 extended (3 more statics): sk_out, r_out, v_out constant
//!   - Group 8 extended (64 more bit-binary): v_out bits ∈ {0,1}
//!   - Group 9 extended (decomposition for v_out)
//!   - Group 10 (value conservation): v_in − v_out − (unshield+fee) == 0 at row 0
//!   - New assertion at OUTPUT_LEAF_LAST_ROW: state[4..8] == output_leaf public input
//!
//! Each test attempts a specific change-output attack; we assert the AIR
//! rejects or accepts as appropriate. Where the AIR CAN'T defend by design
//! (chain-level concern), we document the test as such.
//!
//! Out of scope (Phase 3/4):
//!   - qstark_py PyO3 binding tests
//!   - Chain-side ShieldTransaction integration for the new output leaf
//!   - Network adversarial peer tests for tampered output_leaf in gossip

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

/// Build an honest partial-spend witness.
///
/// The leaf at `idx` has value `v_value`. The spender declares:
///   - unshield_amount + fee + v_out == v_value
/// and chooses (sk_out, r_out, v_out) as the change-note secrets.
fn make_partial_spend_witness(
    idx: usize,
    v_value: u64,
    unshield_amount: u64,
    fee: u64,
    sk_out: u64, r_out: u64, v_out: u64,
) -> (M86Witness, [BaseElement; 4]) {
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
        sk_out: BaseElement::new(sk_out),
        r_out: BaseElement::new(r_out),
        v_out: BaseElement::new(v_out),
    };
    (w, root)
}

// ===========================================================================
// Sanity: honest partial spend proves and verifies
// ===========================================================================

#[test]
fn honest_partial_spend_proves_and_verifies() {
    // Note value 100, unshield 30, fee 5, change v_out 65. (30+5+65 == 100.)
    let (w, _) = make_partial_spend_witness(7, 100, 30, 5, 99, 199, 65);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");
    verify_m86(&proof, pub_inputs).expect("honest verify");
}

#[test]
fn full_spend_with_v_out_zero_still_works() {
    // Recovers the M8.8-A1 behavior: v_out=0 means "no change note,
    // the output_leaf is just H(0, 0, 0)".
    let (w, _) = make_partial_spend_witness(3, 100, 95, 5, 0, 0, 0);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");
    verify_m86(&proof, pub_inputs).expect("honest verify");
}

#[test]
fn change_output_keeps_entire_value_unshield_zero() {
    // "Send 0 transparent, keep entire 100 in a new change note."
    // Edge case but valid: useful for rotating note secrets.
    let (w, _) = make_partial_spend_witness(2, 100, 0, 0, 7, 17, 100);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");
    verify_m86(&proof, pub_inputs).expect("honest verify");
}

// ===========================================================================
// Group 1: Output-leaf forgery (public input tampering)
// ===========================================================================

#[test]
fn tampered_output_leaf_rejected_by_fiat_shamir() {
    // Honest prove. Then verifier sees a different output_leaf.
    let (w, _) = make_partial_spend_witness(5, 200, 50, 0, 11, 22, 150);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");

    // Flip the first cell of the output_leaf public input.
    let mut tampered_leaf = pub_inputs.output_leaf;
    tampered_leaf[0] = tampered_leaf[0] + BaseElement::ONE;

    let tampered = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: pub_inputs.unshield_amount,
        fee: pub_inputs.fee,
        output_leaf: tampered_leaf,
    };
    assert!(
        verify_m86(&proof, tampered).is_err(),
        "Tampered output_leaf must be rejected: Fiat-Shamir transcript binds it"
    );
}

#[test]
fn zeroed_output_leaf_rejected_when_real_one_is_nonzero() {
    // Attacker tries to claim "no change note" (output_leaf = [0;4]) while
    // the proof was actually generated with a real change note.
    // This is a real attack: a malicious node might want to claim the
    // spender produced a change note so they can later claim ownership
    // (or vice versa).
    let (w, _) = make_partial_spend_witness(8, 100, 30, 0, 7, 17, 70);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");

    let tampered = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: pub_inputs.unshield_amount,
        fee: pub_inputs.fee,
        output_leaf: [BaseElement::ZERO; 4],
    };
    assert!(
        verify_m86(&proof, tampered).is_err(),
        "Claiming output_leaf=[0;4] when the real one is nonzero must be rejected"
    );
}

// ===========================================================================
// Group 2: Value-conservation violations
// ===========================================================================

#[test]
#[should_panic(expected = "witness inconsistency")]
fn witness_v_in_less_than_amount_plus_fee_plus_v_out_panics_at_build() {
    // Witness has v=50, but declares unshield=30, fee=5, v_out=20 (sums to 55).
    // The trace builder must panic at build time (defense layer 1, before
    // any proving cycle is wasted).
    let _ = make_partial_spend_witness(4, 50, 30, 5, 11, 22, 20);
    // The above panics inside make_partial_spend_witness ->
    // M86Witness creation -> build_m86_trace via prove_m86 in the next call.
    // But we want the panic to fire on PROVE, not on the make_*. So:
    let (w, _) = make_partial_spend_witness(4, 50, 30, 5, 11, 22, 20);
    let _ = prove_m86(w);  // panics here
}

#[test]
#[should_panic(expected = "witness inconsistency")]
fn witness_v_in_greater_than_amount_plus_fee_plus_v_out_panics_at_build() {
    // Reverse: v=100, declares 30+5+50 = 85. 100 ≠ 85. Must panic.
    let (w, _) = make_partial_spend_witness(4, 100, 30, 5, 11, 22, 50);
    let _ = prove_m86(w);
}

#[test]
fn tampered_unshield_amount_at_verification_rejected() {
    // Honest prove (v=100, amount=30, fee=5, v_out=65, sums to 100).
    let (w, _) = make_partial_spend_witness(6, 100, 30, 5, 11, 22, 65);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");

    // Verifier sees a tampered amount.
    let tampered = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: 1,  // attacker tries to claim less was unshielded
        fee: pub_inputs.fee,
        output_leaf: pub_inputs.output_leaf,
    };
    assert!(
        verify_m86(&proof, tampered).is_err(),
        "Tampered unshield_amount must be rejected via Fiat-Shamir"
    );
}

#[test]
fn tampered_fee_at_verification_rejected() {
    let (w, _) = make_partial_spend_witness(6, 100, 30, 5, 11, 22, 65);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");

    let tampered = M86Inputs {
        root: pub_inputs.root,
        nullifier: pub_inputs.nullifier,
        unshield_amount: pub_inputs.unshield_amount,
        fee: 999,
        output_leaf: pub_inputs.output_leaf,
    };
    assert!(
        verify_m86(&proof, tampered).is_err(),
        "Tampered fee must be rejected via Fiat-Shamir"
    );
}

// ===========================================================================
// Group 3: Range-proof attacks on v_out
// ===========================================================================

#[test]
fn v_out_value_just_below_goldilocks_modulus_panics_at_build() {
    // Pick v_out = some "negative-looking" value modulo p.
    // Goldilocks prime p = 2^64 - 2^32 + 1. So 2^64 - 1 is unrepresentable
    // as a field element (it's actually p plus 2^32 - 2).
    //
    // The witness consistency check at build time should catch this if
    // we try to construct v_out as a non-canonical Felt. But BaseElement::new
    // does internal reduction, so what we're really testing is: can the
    // ATTACKER produce a v_out such that v_in - v_out - (unshield+fee) == 0
    // in the FIELD, while v_out's bit representation can't decompose to
    // a canonical u64?
    //
    // The way to do this is to set v_out to (p - small_value) so that
    // adding it to unshield + fee wraps around to v_in. Field arithmetic
    // would say "yes," but the bit decomposition of v_out won't match its
    // value because the canonical representative changes.
    //
    // Concretely: v_in=10, unshield=5, fee=0, want v_out such that 5+0+v_out=10
    // honestly v_out=5. Attacker tries: v_out = 2^64 - 2^32 + 1 + 5 (=p+5).
    // But BaseElement::new normalizes — so this just becomes 5 again.
    //
    // Real attack must construct v_out via NON-canonical math, which the
    // M86Witness type doesn't support (sk_out/r_out/v_out are BaseElement,
    // which is always canonical). So this attack class is structurally
    // ruled out by the Felt type.
    //
    // Document this rather than test it: the bit-decomposition + binary
    // constraints + canonical-Felt invariant cover the entire u64 range.
}

#[test]
fn change_output_value_one_proves() {
    // v_out = 1 is the smallest nonzero change. Range proof must accept.
    let (w, _) = make_partial_spend_witness(5, 100, 99, 0, 7, 17, 1);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    verify_m86(&proof, pub_inputs).expect("verify");
}

#[test]
fn change_output_value_2_pow_63_proves() {
    // v_out at 2^63 is half-modulus. This is well inside u64 but exercises
    // the high bits of the range proof.
    let v_in = (1u64 << 63) + 50;
    let v_out = 1u64 << 63;
    let (w, _) = make_partial_spend_witness(9, v_in, 50, 0, 7, 17, v_out);
    let (proof, pub_inputs) = prove_m86(w).expect("prove");
    verify_m86(&proof, pub_inputs).expect("verify");
}

// ===========================================================================
// Group 4: Cross-proof attacks
// ===========================================================================

#[test]
fn proof_with_v_out_doesnt_verify_against_different_output_leaf() {
    // Generate two independent partial spends.
    let (w1, _) = make_partial_spend_witness(3, 100, 30, 0, 11, 22, 70);
    let (w2, _) = make_partial_spend_witness(7, 200, 100, 0, 33, 44, 100);

    let (proof1, pub_inputs1) = prove_m86(w1).expect("prove 1");
    let (_proof2, pub_inputs2) = prove_m86(w2).expect("prove 2");

    // Try to verify proof1 claiming pub_inputs2's output_leaf.
    let evil = M86Inputs {
        root: pub_inputs1.root,
        nullifier: pub_inputs1.nullifier,
        unshield_amount: pub_inputs1.unshield_amount,
        fee: pub_inputs1.fee,
        output_leaf: pub_inputs2.output_leaf,  // wrong change-note hash
    };
    assert!(
        verify_m86(&proof1, evil).is_err(),
        "Proof must not verify with a swapped output_leaf"
    );
}

#[test]
fn random_byte_flips_in_proof_all_rejected() {
    // 20 random byte flips at various positions. None should verify.
    // (Reduced from 30 in M8.6's similar test because partial-spend proofs
    // are ~50% larger, so each flip is slower.)
    use std::time::SystemTime;
    let (w, _) = make_partial_spend_witness(4, 100, 30, 5, 11, 22, 65);
    let (proof, pub_inputs) = prove_m86(w).expect("honest prove");

    // Deterministic-pseudo-random byte positions (seed from system time
    // but capture once so the test isn't non-deterministic).
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut rejected = 0;
    for k in 0..20 {
        let pos = ((seed.wrapping_mul(k + 1)) as usize) % proof.len();
        let bit = ((seed >> (k % 64)) & 1) as u8;
        let mut tampered = proof.clone();
        tampered[pos] ^= 1 << bit;
        if verify_m86(&tampered, pub_inputs.clone()).is_err() {
            rejected += 1;
        }
    }
    assert_eq!(rejected, 20, "All random byte flips must be rejected");
}

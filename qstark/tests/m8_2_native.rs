//! M8.2 native correctness — does my trace generation match Winterfell?
//!
//! If these tests fail, my hash AIR is broken before I even write it.
//! These need to pass before anything else.

use qstark::hash_air::native::{
    build_trace, check_constraint_equation, digest_from_trace, initial_state,
    DIGEST_SIZE,
};
use winter_crypto::hashers::Rp64_256;
use winter_crypto::{ElementHasher, Hasher};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

#[test]
fn hash_air_matches_rp64_256_for_one_element() {
    // The most basic test: hash one element via Winterfell, hash the same
    // element via our trace, the outputs must match.
    for x in [0u64, 1, 2, 42, 100, 12345, u64::MAX / 2] {
        let input = [BaseElement::new(x)];
        let expected = Rp64_256::hash_elements(&input);
        let expected_words: [BaseElement; DIGEST_SIZE] = expected.into();

        let rows = build_trace(&input);
        let got = digest_from_trace(&rows);

        assert_eq!(got, expected_words,
                   "trace digest mismatch for input {}: got {:?}, want {:?}",
                   x, got, expected_words);
    }
}

#[test]
fn hash_air_matches_rp64_256_for_multiple_elements() {
    let inputs: &[&[BaseElement]] = &[
        &[BaseElement::new(1), BaseElement::new(2)],
        &[BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)],
        &[BaseElement::new(100), BaseElement::new(200), BaseElement::new(300),
          BaseElement::new(400)],
        &[BaseElement::new(1), BaseElement::new(2), BaseElement::new(3),
          BaseElement::new(4), BaseElement::new(5), BaseElement::new(6),
          BaseElement::new(7), BaseElement::new(8)], // full rate width
    ];
    for input in inputs {
        let expected = Rp64_256::hash_elements(input);
        let expected_words: [BaseElement; DIGEST_SIZE] = expected.into();

        let rows = build_trace(input);
        let got = digest_from_trace(&rows);

        assert_eq!(got, expected_words,
                   "trace digest mismatch for input of len {}", input.len());
    }
}

#[test]
fn initial_state_has_length_in_correct_position() {
    // Verify our initial-state construction matches what Winterfell does.
    // We do this by running one Winterfell hash and comparing the *digest*,
    // which would differ if the length position were wrong. The previous
    // tests already do this — but this test ALSO confirms the length value
    // appears in slot 0 (not slot 3 or elsewhere).
    let preimage = [BaseElement::new(42)];
    let state = initial_state(&preimage);
    assert_eq!(state[0], BaseElement::new(1), "length should be in slot 0");
    assert_eq!(state[4], BaseElement::new(42), "preimage should be in slot 4");
    // Slots 1, 2, 3 must be zero
    for i in 1..=3 {
        assert_eq!(state[i], BaseElement::ZERO, "capacity slot {} not zero", i);
    }
}

#[test]
fn constraint_equation_holds_for_all_rounds() {
    // The core soundness check for the AIR design: my constraint equation
    //   (INV_MDS * (S' - ARK2[r]))^7 == MDS * S^7 + ARK1[r]
    // MUST hold for the reference round function, for any state and any round.
    // If this fails, my AIR is broken.
    let preimages: &[&[BaseElement]] = &[
        &[BaseElement::new(1)],
        &[BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)],
        &[BaseElement::new(0)],
    ];
    for preimage in preimages {
        let rows = build_trace(preimage);
        for round in 0..7 {
            assert!(
                check_constraint_equation(&rows[round], round),
                "constraint equation failed for round {}, preimage {:?}",
                round, preimage
            );
        }
    }
}

#[test]
fn determinism() {
    let input = [BaseElement::new(123)];
    let d1 = digest_from_trace(&build_trace(&input));
    let d2 = digest_from_trace(&build_trace(&input));
    assert_eq!(d1, d2);
}

#[test]
fn different_inputs_different_digests() {
    let d1 = digest_from_trace(&build_trace(&[BaseElement::new(1)]));
    let d2 = digest_from_trace(&build_trace(&[BaseElement::new(2)]));
    assert_ne!(d1, d2);
}

//! Smoke test: verify we can call Winterfell's Rescue-Prime and get a hash.

use winter_crypto::hashers::Rp64_256;
use winter_crypto::{ElementHasher, Hasher};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

#[test]
fn rp64_256_hash_is_deterministic() {
    let input = [BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)];
    let d1 = Rp64_256::hash_elements(&input);
    let d2 = Rp64_256::hash_elements(&input);
    assert_eq!(d1, d2);
    println!("Rp64_256(1, 2, 3) = {:?}", d1);
}

#[test]
fn rp64_256_hash_changes_with_input() {
    let d1 = Rp64_256::hash_elements(&[BaseElement::new(1)]);
    let d2 = Rp64_256::hash_elements(&[BaseElement::new(2)]);
    assert_ne!(d1, d2);
}

#[test]
fn rp64_256_hash_of_zero_known_vector() {
    // Hash of a single zero element. This isn't from the spec — it's just to
    // give us a known anchor value we can compare against later when we
    // build the AIR version.
    let input = [BaseElement::ZERO];
    let d = Rp64_256::hash_elements(&input);
    println!("Rp64_256(0) = {:?}", d);
    // Force a panic to see the output during testing
    // (we don't yet know the right value to assert against)
}

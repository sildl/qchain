//! M8.2 STARK proof tests, including the all-important adversarial cases.

use qstark::hash_air::{prove_preimage, verify_preimage, HashInputs};
use winter_crypto::hashers::Rp64_256;
use winter_crypto::{ElementHasher, Hasher};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

#[test]
fn happy_path_proves_and_verifies() {
    let preimage = BaseElement::new(42);
    let expected = Rp64_256::hash_elements(&[preimage]);
    let expected_digest: [BaseElement; 4] = expected.into();

    let (proof_bytes, pub_inputs) = prove_preimage(preimage).expect("prove");
    assert_eq!(pub_inputs.digest, expected_digest);

    println!("Preimage 42 → digest {:?}, proof {} bytes",
             pub_inputs.digest, proof_bytes.len());
    verify_preimage(&proof_bytes, pub_inputs).expect("verify");
}

#[test]
fn proves_multiple_different_preimages() {
    for x in [0u64, 1, 7, 100, 12345, 99999999, u64::MAX / 3] {
        let preimage = BaseElement::new(x);
        let expected = Rp64_256::hash_elements(&[preimage]);
        let expected_digest: [BaseElement; 4] = expected.into();

        let (proof, pub_inputs) = prove_preimage(preimage)
            .expect(&format!("prove for {}", x));
        assert_eq!(pub_inputs.digest, expected_digest,
                   "digest must match Rp64_256 for input {}", x);
        verify_preimage(&proof, pub_inputs)
            .expect(&format!("verify for {}", x));
    }
}

#[test]
fn rejects_wrong_claimed_digest() {
    // Prove preimage 42 honestly. Then lie to the verifier about what digest
    // it produces.
    let preimage = BaseElement::new(42);
    let (proof, true_inputs) = prove_preimage(preimage).expect("prove");

    let mut lying_digest = true_inputs.digest;
    lying_digest[0] += BaseElement::ONE;  // off by one in slot 0
    let lying_inputs = HashInputs { digest: lying_digest };

    let res = verify_preimage(&proof, lying_inputs);
    assert!(res.is_err(),
            "verifier MUST reject wrong digest, got Ok(())");
}

#[test]
fn rejects_completely_wrong_digest() {
    let (proof, _) = prove_preimage(BaseElement::new(42)).expect("prove");
    let garbage = HashInputs {
        digest: [BaseElement::ONE; 4],
    };
    let res = verify_preimage(&proof, garbage);
    assert!(res.is_err(), "verifier MUST reject garbage digest");
}

#[test]
fn rejects_digest_of_different_preimage() {
    // The digest of 42 isn't the same as the digest of 43.
    // A proof for 42 must NOT verify against the digest of 43.
    let (proof_42, _) = prove_preimage(BaseElement::new(42)).expect("prove");
    let digest_43 = Rp64_256::hash_elements(&[BaseElement::new(43)]);
    let digest_43_words: [BaseElement; 4] = digest_43.into();

    let res = verify_preimage(&proof_42, HashInputs { digest: digest_43_words });
    assert!(res.is_err(),
            "proof for x=42 must not verify against digest of x=43");
}

#[test]
fn rejects_tampered_proof() {
    let (mut proof, pub_inputs) = prove_preimage(BaseElement::new(42))
        .expect("prove");
    let mid = proof.len() / 2;
    proof[mid] ^= 0xFF;
    let res = verify_preimage(&proof, pub_inputs);
    assert!(res.is_err(), "verifier MUST reject tampered proof");
}

#[test]
fn rejects_truncated_proof() {
    let (proof, pub_inputs) = prove_preimage(BaseElement::new(42)).expect("prove");
    let truncated = &proof[..proof.len() - 50];
    let res = verify_preimage(truncated, pub_inputs);
    assert!(res.is_err(), "verifier MUST reject truncated proof");
}

#[test]
fn rejects_empty_proof() {
    let pub_inputs = HashInputs {
        digest: [BaseElement::ONE; 4],
    };
    let res = verify_preimage(&[], pub_inputs);
    assert!(res.is_err(), "verifier MUST reject empty proof");
}

#[test]
fn many_random_tampers_all_rejected() {
    // Strong soundness: 30 random byte-flips must all fail.
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    let mut rng = seed as u64;
    let next = |s: &mut u64| {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *s
    };

    let (proof, pub_inputs) = prove_preimage(BaseElement::new(7)).expect("prove");
    let mut accepted_bad = 0;
    for _ in 0..30 {
        let mut bad = proof.clone();
        let idx = (next(&mut rng) as usize) % bad.len();
        let flip = (next(&mut rng) & 0xFF) as u8 | 1;
        bad[idx] ^= flip;
        if verify_preimage(&bad, pub_inputs.clone()).is_ok() {
            accepted_bad += 1;
        }
    }
    assert_eq!(accepted_bad, 0,
               "verifier MUST reject all 30 random byte-flips, accepted {}",
               accepted_bad);
}

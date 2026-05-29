use qstark::hash_air::anon_full::{prove_full_membership, verify_full_membership,
                                  FullMembershipWitness, MERKLE_DEPTH};
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use qstark::hash_air::{prove_one_level_membership, prove_preimage,
                       verify_one_level_membership, verify_preimage};
use qstark::{fib_native, prove_fib, verify_fib};
use winter_crypto::hashers::Rp64_256;
use winter_crypto::ElementHasher;
use winter_math::fields::f64::BaseElement;

fn main() {
    println!("================================");
    println!("M8.1 — Fibonacci STARK");
    println!("================================");
    let n = 1024;
    let expected = fib_native(n);
    println!("Computing fib({}) = {}", n, expected);

    let t0 = std::time::Instant::now();
    let (proof_bytes, pub_inputs) = prove_fib(n).expect("prove");
    let pt = t0.elapsed();
    println!("Proven in {:?}, proof size: {} bytes", pt, proof_bytes.len());

    let t0 = std::time::Instant::now();
    verify_fib(&proof_bytes, pub_inputs).expect("verify");
    let vt = t0.elapsed();
    println!("Verified in {:?}", vt);

    println!();
    println!("================================");
    println!("M8.2 — Rescue-Prime preimage STARK");
    println!("================================");
    let preimage = BaseElement::new(42);
    let expected = Rp64_256::hash_elements(&[preimage]);
    let expected_digest: [BaseElement; 4] = expected.into();
    println!("Proving knowledge of preimage 42, digest:");
    println!("  {:?}", expected_digest);

    let t0 = std::time::Instant::now();
    let (proof, pub_inputs) = prove_preimage(preimage).expect("prove");
    let pt = t0.elapsed();
    println!("Proven in {:?}, proof size: {} bytes", pt, proof.len());

    let t0 = std::time::Instant::now();
    verify_preimage(&proof, pub_inputs).expect("verify");
    let vt = t0.elapsed();
    println!("Verified in {:?}", vt);

    println!();
    println!("================================");
    println!("M8.3 — FULL Merkle membership STARK (depth {})", MERKLE_DEPTH);
    println!("================================");
    // Build a real tree, prove membership of a specific leaf, hiding which
    // one and how we got there.
    let leaves: Vec<_> = (0..256).map(|i| hash_leaf(
        BaseElement::new(1000 + i as u64),
        BaseElement::new(2000 + i as u64),
        BaseElement::new(100 + i as u64),
    )).collect();
    let tree = MerkleTree::from_leaves(&leaves);
    let secret_idx = 47;  // The prover's secret position
    let witness = FullMembershipWitness::from_tree(&tree, secret_idx);

    println!("Tree has 256 leaves. The prover knows leaf at position {}.", secret_idx);
    println!("Witness: leaf digest, {} siblings, {} direction bits — ALL HIDDEN",
             MERKLE_DEPTH, MERKLE_DEPTH);

    let t0 = std::time::Instant::now();
    let (proof, pub_inputs) = prove_full_membership(witness).expect("prove");
    let pt = t0.elapsed();
    println!("Proven in {:?}, proof size: {} bytes", pt, proof.len());

    println!("Public input (claimed depth-{} root):", MERKLE_DEPTH);
    println!("  {:?}", pub_inputs.root);

    let t0 = std::time::Instant::now();
    verify_full_membership(&proof, pub_inputs).expect("verify");
    let vt = t0.elapsed();
    println!("Verified in {:?}", vt);

    println!();
    println!("The verifier knows: the depth-{} root + a {}-byte proof.",
             MERKLE_DEPTH, proof.len());
    println!("The verifier learned NOTHING about: the leaf, its position,");
    println!("the siblings on the path, or the direction bits.");
    println!("This is a REAL multi-level zero-knowledge Merkle membership proof.");

    // Quick demo: single-level proof for comparison
    println!();
    println!("================================");
    println!("M8.3 — Single-level membership STARK (for comparison)");
    println!("================================");
    let left = leaves[0];
    let right = leaves[1];
    let (proof, pub_inputs) = prove_one_level_membership(left, right).expect("prove");
    println!("Single-level proof size: {} bytes", proof.len());
    verify_one_level_membership(&proof, pub_inputs).expect("verify");
    println!("✓ verified");
}

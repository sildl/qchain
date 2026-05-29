//! M8.3 FULL multi-level Merkle membership STARK tests.

use qstark::hash_air::anon_full::{
    prove_full_membership, verify_full_membership, FullMembershipInputs,
    FullMembershipWitness, MERKLE_DEPTH,
};
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
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
fn smoke_happy_path() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);

    // Pick a leaf and build the witness
    let idx = 7;  // arbitrary
    let witness = FullMembershipWitness::from_tree(&tree, idx);

    let result = prove_full_membership(witness);
    match result {
        Ok((proof, pub_inputs)) => {
            println!("Proof generated: {} bytes", proof.len());
            println!("Public root: {:?}", pub_inputs.root);

            // Verify
            let v = verify_full_membership(&proof, pub_inputs);
            match v {
                Ok(()) => println!("✓ verified"),
                Err(e) => panic!("verify failed: {}", e),
            }
        }
        Err(e) => panic!("prove failed: {}", e),
    }
}

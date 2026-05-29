//! M8.6 STARK smoke test.

use qstark::hash_air::m86_air::{prove_m86, verify_m86, M86Witness};
use qstark::hash_air::m86_native::M86_MERKLE_DEPTH;
use qstark::hash_air::merkle::{hash_leaf, MerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

fn make_leaves(n: usize) -> Vec<[BaseElement; 4]> {
    (0..n)
        .map(|i| {
            hash_leaf(
                BaseElement::new(1000 + i as u64),
                BaseElement::new(2000 + i as u64),
                BaseElement::new(100 + i as u64),
            )
        })
        .collect()
}

#[test]
fn smoke_m86_happy_path() {
    let leaves = make_leaves(16);
    let tree = MerkleTree::from_leaves(&leaves);

    let idx = 7usize;
    let sk = BaseElement::new(1000 + idx as u64);
    let r = BaseElement::new(2000 + idx as u64);
    let v = BaseElement::new(100 + idx as u64);
    let path: Vec<_> = tree.auth_path(idx).into_iter().take(M86_MERKLE_DEPTH).collect();

    let w = M86Witness {
        sk, r, v, path,
        unshield_amount: v.as_int(), fee: 0,
        sk_out: BaseElement::ZERO, r_out: BaseElement::ZERO, v_out: BaseElement::ZERO,
    };
    let result = prove_m86(w);
    match result {
        Ok((proof, pub_inputs)) => {
            println!("M8.6 proof generated: {} bytes", proof.len());
            println!("  root: {:?}", pub_inputs.root);
            println!("  nullifier: {:?}", pub_inputs.nullifier);
            // Sanity: nullifier should equal hash_leaf(sk+1, r, v)
            let expected_nullifier = hash_leaf(sk + BaseElement::ONE, r, v);
            assert_eq!(pub_inputs.nullifier, expected_nullifier);
            verify_m86(&proof, pub_inputs).expect("verify should succeed");
            println!("✓ verified");
        }
        Err(e) => panic!("prove failed: {}", e),
    }
}

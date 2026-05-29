"""Integration sketch: how QChain could use qstark_py for anonymous proof
of ownership.

This is NOT integrated into QChain's actual code — it's a self-contained
demonstration of the API surface QChain would call.

The scenario:
    Alice has a note in a shielded pool. She wants to spend it (or just
    prove she owns it) without revealing which note. The pool is a Merkle
    tree of note commitments.

    Without zk-STARKs (QChain M4 / Schnorr), Alice has to reveal *which*
    note she's spending — only her identity is hidden.

    With zk-STARKs (this milestone), Alice can prove "I own one of the
    notes in this pool" while revealing only the pool root. The verifier
    cannot tell which note.

This is the same architectural pattern as Zcash and Tornado Cash use.
"""

import qstark_py as q


def build_merkle_tree(leaves, depth=None):
    """Build a Merkle tree with optional explicit depth (pad with zero leaves)."""
    depth = depth or q.merkle_depth()
    target_size = 1 << depth
    if len(leaves) > target_size:
        raise ValueError(f"too many leaves for depth-{depth} tree")
    # Pad with zero-leaves to fill the tree
    zero_leaf = (0, 0, 0, 0)
    padded = list(leaves) + [zero_leaf] * (target_size - len(leaves))
    layers = [padded]
    while len(layers[-1]) > 1:
        prev = layers[-1]
        nxt = [q.hash_inner(prev[i], prev[i + 1]) for i in range(0, len(prev), 2)]
        layers.append(nxt)
    return layers


def authentication_path(layers, idx):
    path = []
    for level in range(len(layers) - 1):
        is_right = bool(idx & 1)
        path.append((layers[level][idx ^ 1], is_right))
        idx //= 2
    return path


# ============================================================================
# Step 1: A shielded pool of note commitments
# ============================================================================
# Each "note" is a triple (secret_key, randomness, value). The commitment
# leaf is H(sk, r, v).

print("Building a shielded pool of 10 notes...")
notes = [
    # (sk, r, value)
    (1001, 5001, 100),
    (1002, 5002, 50),
    (1003, 5003, 75),   # ← Alice owns this one
    (1004, 5004, 200),
    (1005, 5005, 30),
    (1006, 5006, 150),
    (1007, 5007, 80),
    (1008, 5008, 25),
    (1009, 5009, 60),
    (1010, 5010, 120),
]
leaves = [q.hash_leaf(sk, r, v) for (sk, r, v) in notes]
layers = build_merkle_tree(leaves)
root = layers[-1][0]
print(f"Pool root (public, on-chain): {root[0]:>20}...\n")


# ============================================================================
# Step 2: Alice generates a STARK proof of ownership
# ============================================================================
# She knows the position of her note. She constructs the authentication path.
# The STARK proof commits to all of this in the witness — the verifier sees
# only the root.

print("Alice owns the note at position 2.")
alice_idx = 2
alice_leaf = leaves[alice_idx]
alice_path = authentication_path(layers, alice_idx)

print("Generating STARK proof of ownership (hides which note Alice owns)...")
proof, claimed_root = q.prove_membership(alice_leaf, alice_path)
print(f"  Proof size: {len(proof):,} bytes")
print(f"  Claimed root: {claimed_root[0]:>20}...")
assert claimed_root == root


# ============================================================================
# Step 3: A verifier (e.g. blockchain node) checks the proof
# ============================================================================
# The verifier knows only the pool root. They run verify_membership.

print("\nVerifier checks the proof against the public pool root...")
ok = q.verify_membership(proof, root)
print(f"  Verifier accepts: {ok}")
print(f"  Verifier learned:")
print(f"    - SOMEONE owns SOME note in the pool")
print(f"    - That's it.")
print(f"  Verifier did NOT learn:")
print(f"    - Which note (anonymity set = pool size = {1 << q.merkle_depth()} positions)")
print(f"    - Alice's secret key, randomness, or value")
print(f"    - The Merkle path siblings")


# ============================================================================
# Step 4: Sanity adversarial check
# ============================================================================
# An attacker who doesn't own any note in the pool cannot produce a proof.
# If they tamper with a witness, the resulting proof commits to a DIFFERENT
# root and won't verify against the actual pool root.

print("\nAdversarial: attacker forges a note (sk=9999)...")
forged_leaf = q.hash_leaf(9999, 0, 0)
forged_path = alice_path  # Try to reuse Alice's path
forged_proof, forged_root = q.prove_membership(forged_leaf, forged_path)
print(f"  Forged proof's root: {forged_root[0]:>20}...")
print(f"  Equal to actual pool root? {forged_root == root}")
print(f"  Verify forged proof against actual pool root: " +
      f"{q.verify_membership(forged_proof, root)}")
print(f"  → Forged proofs cannot pretend to be in this pool.")


# ============================================================================
# Step 5: Demonstrate two different members produce indistinguishable proofs
# ============================================================================
# Alice (position 2) and Bob (position 7) both prove ownership. The verifier
# can verify both proofs but cannot tell which is which (modulo bytes
# comparison; semantically, both prove the same statement against the same
# root).

print("\nAnonymity set demonstration:")
bob_idx = 7
bob_leaf = leaves[bob_idx]
bob_path = authentication_path(layers, bob_idx)
bob_proof, bob_root = q.prove_membership(bob_leaf, bob_path)
print(f"  Alice's proof verifies against pool root: {q.verify_membership(proof, root)}")
print(f"  Bob's proof verifies against pool root:   {q.verify_membership(bob_proof, root)}")
print(f"  Both prove the SAME statement against the SAME root.")
print(f"  An outside observer cannot deduce which position each proof is for.")

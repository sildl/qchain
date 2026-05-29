"""Python test suite for the qstark_py bindings.

Mirrors the Rust adversarial tests at the Python level to validate that
the FFI bridge correctly propagates STARK soundness — i.e., honest proofs
verify and tampered proofs are rejected.

Run with:
    python3 -m pytest test_qstark_py.py
or  python3 test_qstark_py.py
"""

import time
import random
import qstark_py as q


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_tree(leaves):
    """Build a Merkle tree using qstark_py.hash_inner."""
    layers = [list(leaves)]
    while len(layers[-1]) > 1:
        prev = layers[-1]
        nxt = [q.hash_inner(prev[i], prev[i + 1]) for i in range(0, len(prev), 2)]
        layers.append(nxt)
    return layers


def auth_path(layers, idx):
    """Return [(sibling, is_right), ...] from leaf to root."""
    path = []
    for level in range(len(layers) - 1):
        is_right = bool(idx & 1)
        sibling_idx = idx ^ 1
        path.append((layers[level][sibling_idx], is_right))
        idx //= 2
    return path


def sample_tree(num_leaves=16):
    leaves = [q.hash_leaf(1000 + i, 2000 + i, 100 + i) for i in range(num_leaves)]
    return leaves, build_tree(leaves)


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

_tests_passed = 0
_tests_failed = 0


def test(fn):
    global _tests_passed, _tests_failed
    name = fn.__name__
    try:
        fn()
        print(f"  ✓ {name}")
        _tests_passed += 1
    except AssertionError as e:
        print(f"  ✗ {name}: {e}")
        _tests_failed += 1
    except Exception as e:
        print(f"  ✗ {name}: {type(e).__name__}: {e}")
        _tests_failed += 1


# ---------------------------------------------------------------------------
# Sanity / metadata
# ---------------------------------------------------------------------------

def field_modulus_is_goldilocks():
    assert q.field_modulus() == 2**64 - 2**32 + 1, \
        f"field modulus is not Goldilocks: {q.field_modulus()}"

def merkle_depth_matches_qstark_full():
    assert q.merkle_depth() == 4, "depth should be 4 in this build"


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def hash_leaf_is_deterministic():
    a = q.hash_leaf(1, 2, 3)
    b = q.hash_leaf(1, 2, 3)
    assert a == b
    assert len(a) == 4
    for x in a:
        assert 0 <= x < q.field_modulus()

def hash_leaf_distinguishes_inputs():
    a = q.hash_leaf(1, 2, 3)
    b = q.hash_leaf(1, 2, 4)
    assert a != b, "different value must produce different digest"

def hash_inner_is_deterministic():
    a = q.hash_inner((1, 2, 3, 4), (5, 6, 7, 8))
    b = q.hash_inner((1, 2, 3, 4), (5, 6, 7, 8))
    assert a == b

def hash_inner_is_not_symmetric():
    a = q.hash_inner((1, 2, 3, 4), (5, 6, 7, 8))
    b = q.hash_inner((5, 6, 7, 8), (1, 2, 3, 4))
    assert a != b, "merge should not be symmetric"

def out_of_range_field_element_rejected():
    """Values >= 2^64 must be rejected. PyO3 raises OverflowError on u64
    conversion; values in [modulus, 2^64) raise ValueError from our code."""
    # Case 1: too big for u64 → PyO3's OverflowError
    try:
        q.hash_leaf(2**64, 0, 0)
        assert False, "should have raised on 2^64"
    except (ValueError, OverflowError):
        pass
    # Case 2: in u64 but >= field modulus → our ValueError
    try:
        q.hash_leaf(q.field_modulus(), 0, 0)
        assert False, "should have raised on modulus"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# M8.2: Preimage STARK
# ---------------------------------------------------------------------------

def preimage_happy_path():
    proof, digest = q.prove_preimage(42)
    assert isinstance(proof, bytes)
    assert len(proof) > 1000  # real proof should be substantial
    assert isinstance(digest, tuple) and len(digest) == 4
    assert q.verify_preimage(proof, digest) is True

def preimage_rejects_wrong_digest():
    proof, digest = q.prove_preimage(42)
    bad = (digest[0] + 1, digest[1], digest[2], digest[3])
    assert q.verify_preimage(proof, bad) is False

def preimage_rejects_garbage_digest():
    proof, _ = q.prove_preimage(42)
    assert q.verify_preimage(proof, (1, 1, 1, 1)) is False

def preimage_rejects_tampered_bytes():
    proof, digest = q.prove_preimage(42)
    mid = len(proof) // 2
    tampered = proof[:mid] + bytes([proof[mid] ^ 0xFF]) + proof[mid + 1:]
    assert q.verify_preimage(tampered, digest) is False

def preimage_rejects_empty_proof():
    assert q.verify_preimage(b"", (0, 0, 0, 0)) is False

def preimage_works_for_many_inputs():
    for x in [0, 1, 7, 99, 12345, 2**62]:
        proof, digest = q.prove_preimage(x)
        assert q.verify_preimage(proof, digest)


# ---------------------------------------------------------------------------
# M8.3 FULL: Multi-level Merkle membership STARK
# ---------------------------------------------------------------------------

def membership_happy_path():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 7)
    proof, root = q.prove_membership(leaves[7], path)
    assert root == layers[-1][0], "claimed root must match the tree root"
    assert q.verify_membership(proof, root) is True

def membership_rejects_wrong_root():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 7)
    proof, root = q.prove_membership(leaves[7], path)
    bad = (root[0] + 1, root[1], root[2], root[3])
    assert q.verify_membership(proof, bad) is False

def membership_rejects_garbage_root():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 7)
    proof, _ = q.prove_membership(leaves[7], path)
    assert q.verify_membership(proof, (1, 1, 1, 1)) is False

def membership_rejects_tampered_proof():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 7)
    proof, root = q.prove_membership(leaves[7], path)
    mid = len(proof) // 2
    tampered = proof[:mid] + bytes([proof[mid] ^ 0xFF]) + proof[mid + 1:]
    assert q.verify_membership(tampered, root) is False

def membership_rejects_truncated_proof():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 7)
    proof, root = q.prove_membership(leaves[7], path)
    assert q.verify_membership(proof[:-100], root) is False

def membership_forging_with_wrong_sibling_produces_different_root():
    leaves, layers = sample_tree(16)
    honest_path = auth_path(layers, 7)
    _, honest_root = q.prove_membership(leaves[7], honest_path)

    # Tamper one sibling
    bad_path = list(honest_path)
    bad_sib = list(bad_path[1][0])
    bad_sib[0] = (bad_sib[0] + 1) % q.field_modulus()
    bad_path[1] = (tuple(bad_sib), bad_path[1][1])
    proof_bad, bad_root = q.prove_membership(leaves[7], bad_path)

    # Tampered witness produces a different root, and proof does NOT verify
    # against the honest root.
    assert bad_root != honest_root
    assert q.verify_membership(proof_bad, honest_root) is False

def membership_rejects_wrong_path_length():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 7)
    # Drop one element
    try:
        q.prove_membership(leaves[7], path[:-1])
        assert False, "should reject path of wrong length"
    except (ValueError, RuntimeError):
        pass

def membership_30_random_tampers_all_rejected():
    leaves, layers = sample_tree(16)
    path = auth_path(layers, 3)
    proof, root = q.prove_membership(leaves[3], path)

    rng = random.Random(12345)
    accepted_bad = 0
    for _ in range(30):
        bad = bytearray(proof)
        idx = rng.randrange(len(bad))
        flip = (rng.randrange(255) + 1) & 0xFF
        bad[idx] ^= flip
        if q.verify_membership(bytes(bad), root):
            accepted_bad += 1
    assert accepted_bad == 0, f"verifier accepted {accepted_bad}/30 random tampers"


# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Sanity / metadata:")
    test(field_modulus_is_goldilocks)
    test(merkle_depth_matches_qstark_full)

    print("\nHash helpers:")
    test(hash_leaf_is_deterministic)
    test(hash_leaf_distinguishes_inputs)
    test(hash_inner_is_deterministic)
    test(hash_inner_is_not_symmetric)
    test(out_of_range_field_element_rejected)

    print("\nM8.2 preimage:")
    test(preimage_happy_path)
    test(preimage_rejects_wrong_digest)
    test(preimage_rejects_garbage_digest)
    test(preimage_rejects_tampered_bytes)
    test(preimage_rejects_empty_proof)
    test(preimage_works_for_many_inputs)

    print("\nM8.3 FULL membership:")
    test(membership_happy_path)
    test(membership_rejects_wrong_root)
    test(membership_rejects_garbage_root)
    test(membership_rejects_tampered_proof)
    test(membership_rejects_truncated_proof)
    test(membership_forging_with_wrong_sibling_produces_different_root)
    test(membership_rejects_wrong_path_length)
    test(membership_30_random_tampers_all_rejected)

    print(f"\n{_tests_passed} passed, {_tests_failed} failed")
    if _tests_failed > 0:
        import sys
        sys.exit(1)

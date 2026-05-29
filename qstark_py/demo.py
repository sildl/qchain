"""Standalone demo: Python calling Rust calling Winterfell zk-STARKs.

Builds a Merkle tree of leaves, generates a zero-knowledge proof of
membership for a specific position, verifies it. Demonstrates that the
verifier learns NOTHING about the witness (which leaf, which siblings,
which direction bits).

Run with: python3 demo.py
"""

import time
import qstark_py as q

PALE = "\033[2m"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def heading(text):
    print()
    print(BOLD + "=" * 60 + RESET)
    print(BOLD + text + RESET)
    print(BOLD + "=" * 60 + RESET)


def build_tree(leaves):
    layers = [list(leaves)]
    while len(layers[-1]) > 1:
        prev = layers[-1]
        nxt = [q.hash_inner(prev[i], prev[i + 1]) for i in range(0, len(prev), 2)]
        layers.append(nxt)
    return layers


def auth_path(layers, idx):
    path = []
    for level in range(len(layers) - 1):
        is_right = bool(idx & 1)
        path.append((layers[level][idx ^ 1], is_right))
        idx //= 2
    return path


def fmt_digest(d):
    return "(" + ", ".join(f"{x:>20}" for x in d) + ")"


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

heading("qstark Python bindings — runtime info")
print(f"  Field modulus: {q.field_modulus()}  (2^64 - 2^32 + 1, Goldilocks)")
print(f"  Merkle depth:  {q.merkle_depth()}  (anonymity set = 2^{q.merkle_depth()} = {1 << q.merkle_depth()})")

# ---- M8.2: prove knowledge of a preimage ----------------------------------

heading("M8.2 — Rescue-Prime preimage STARK")

x = 42
print(f"  Statement: I know x such that Rp64_256(x) = y")
print(f"  Witness (HIDDEN from verifier):  x = {x}")

t0 = time.perf_counter()
proof, digest = q.prove_preimage(x)
t_prove = (time.perf_counter() - t0) * 1000

print(f"  {GREEN}Proven{RESET} in {t_prove:.2f} ms; proof size = {len(proof)} bytes")
print(f"  Public input (digest y):")
print(f"    {fmt_digest(digest)}")

t0 = time.perf_counter()
ok = q.verify_preimage(proof, digest)
t_verify = (time.perf_counter() - t0) * 1000
print(f"  {GREEN if ok else RED}Verified{RESET}: {ok} in {t_verify:.2f} ms")

print(f"  {PALE}# tampered digest must be rejected:{RESET}")
bad = (digest[0] + 1, digest[1], digest[2], digest[3])
print(f"  {RED if q.verify_preimage(proof, bad) else GREEN}Bad-digest verify{RESET}: " +
      f"{q.verify_preimage(proof, bad)}  (expected False)")

# ---- M8.3 FULL: multi-level Merkle membership ----------------------------

heading("M8.3 FULL — multi-level Merkle membership STARK")

# Build a depth-4 tree (16 leaves)
DEPTH = q.merkle_depth()
NUM_LEAVES = 1 << DEPTH
leaves = [q.hash_leaf(1000 + i, 2000 + i, 100 + i) for i in range(NUM_LEAVES)]
layers = build_tree(leaves)
root = layers[-1][0]

secret_idx = 7
print(f"  Tree built: depth {DEPTH}, {NUM_LEAVES} leaves")
print(f"  Public root:")
print(f"    {fmt_digest(root)}")
print()
print(f"  Statement: I know a leaf in this tree at SOME position,")
print(f"             together with its authentication path, that reaches the root.")
print()
print(f"  {PALE}Witness (ALL HIDDEN from verifier):{RESET}")
print(f"    Leaf index: {secret_idx}")
print(f"    Leaf digest: {fmt_digest(leaves[secret_idx])}")
path = auth_path(layers, secret_idx)
for level, (sib, is_right) in enumerate(path):
    print(f"    Path[{level}]: sibling={fmt_digest(sib)}, dir={int(is_right)}")

t0 = time.perf_counter()
proof, claimed_root = q.prove_membership(leaves[secret_idx], path)
t_prove = (time.perf_counter() - t0) * 1000
assert claimed_root == root

print()
print(f"  {GREEN}Proven{RESET} in {t_prove:.2f} ms; proof size = {len(proof)} bytes")

t0 = time.perf_counter()
ok = q.verify_membership(proof, root)
t_verify = (time.perf_counter() - t0) * 1000
print(f"  {GREEN if ok else RED}Verified{RESET}: {ok} in {t_verify:.2f} ms")

# Tamper checks
bad_root = (root[0] + 1, root[1], root[2], root[3])
print()
print(f"  {PALE}Adversarial checks:{RESET}")
print(f"    Wrong root      → verify = {q.verify_membership(proof, bad_root)}  (expected False)")
print(f"    Empty proof     → verify = {q.verify_membership(b'', root)}  (expected False)")

tampered = bytearray(proof)
tampered[len(tampered) // 2] ^= 0xFF
print(f"    Tampered proof  → verify = {q.verify_membership(bytes(tampered), root)}  (expected False)")

print()
print(BOLD + "Summary:" + RESET)
print(f"  Python ↔ Rust ↔ Winterfell pipeline working end-to-end.")
print(f"  Real zero-knowledge proof of Merkle membership generated and verified.")
print(f"  Verifier learns: depth-{DEPTH} root + {len(proof)}-byte proof.")
print(f"  Verifier learns NOT: leaf identity, position, siblings, direction bits.")

# qstark_py — Python bindings for qstark zk-STARKs

**M8.4 of the QChain → qstark progression.** Exposes the qstark Rust crate
(M8.1–M8.3) as a Python extension module via PyO3 + maturin.

## What this gives you

```python
import qstark_py as q

# 1. Hash helpers (Rescue-Prime over Goldilocks)
leaf = q.hash_leaf(sk=12345, r=67890, value=100)
parent = q.hash_inner(left, right)

# 2. M8.2: prove knowledge of a Rescue-Prime preimage
proof, digest = q.prove_preimage(42)
assert q.verify_preimage(proof, digest)

# 3. M8.3: prove multi-level Merkle membership (depth-4 sub-tree)
#    Witness: leaf + authentication path; Public: root
proof, root = q.prove_membership(leaf, path)
assert q.verify_membership(proof, root)
```

## Build & install

Requirements: Python 3.12, Rust 1.75+, [maturin](https://www.maturin.rs/).

```bash
cd qstark_py
maturin build --release
pip install --force-reinstall target/wheels/qstark_py-*.whl
```

Then `import qstark_py` in any Python script. The wheel includes
the compiled Winterfell prover/verifier statically linked.

## Run

```bash
python3 demo.py            # end-to-end demo
python3 test_qstark_py.py  # 21 tests including 30 random byte-flips
```

## Real numbers

Measured from Python on a single core:

| Operation | Time | Size |
|-----------|------|------|
| `prove_preimage(42)`             | ~0.5 ms  | 5,925 B  |
| `verify_preimage(...)`           | ~0.1 ms  | —        |
| `prove_membership(leaf, path)`   | ~3.0 ms  | 27,912 B |
| `verify_membership(...)`         | ~0.3 ms  | —        |

FFI overhead vs direct Rust is negligible (<10%) — the bottleneck is the
STARK proving, not the bridge.

## What 21 Python tests cover

Mirrors the Rust soundness pattern at the Python boundary:

**Sanity/metadata** (2): field modulus, Merkle depth.

**Hash helpers** (5): determinism, distinguishing inputs, asymmetry of merge,
range checks (raises on values >= 2^64 and on values in [modulus, 2^64)).

**Preimage STARK** (6): happy path, rejects wrong digest, garbage digest,
tampered bytes, empty proof, works for many input values.

**Membership STARK** (8): happy path, rejects wrong root, garbage root,
tampered proof, truncated proof, forging-with-wrong-sibling produces
different root, rejects wrong path length, **30 random byte-flips all
rejected**.

## Honest scope

**What this milestone IS:**
- A clean, working FFI bridge from Python to Rust zk-STARKs
- Type-safe at both boundaries (Python ints validated against Goldilocks
  field range; PyO3 catches u64 overflow)
- Sound: tampered proofs and wrong public inputs are rejected at the
  Python layer just as they are in Rust

**What this milestone is NOT:**
- Integration with QChain's existing anon-spend code. That would require
  migrating QChain's anon Merkle tree from SHA-256 commitments to
  Rp64_256 commitments — a substantial separate project (~600 lines of
  Python). M8.4 is the bridge; M8.5 would be the migration.
- Production hardening. No GIL release for long-running proofs (would help
  for batched proving), no async-await support, no streaming output.
  These are real but not in scope for a learning bridge.
- Higher security than the Rust crate provides. Same 50-bit conjectured
  security caveat applies (small trace; production needs batched traces).

## Type bridging notes

- **Field elements**: passed as Python `int`. Values must be in `[0, p)`
  where `p = 2^64 - 2^32 + 1`. Out-of-range raises `ValueError` (or
  `OverflowError` from PyO3 for values >= 2^64).
- **Digests**: 4-tuples of field-element ints, e.g. `(123, 456, 789, 1011)`.
- **Proofs**: opaque `bytes`. Don't introspect; pass back to verify.
- **Direction bits**: Python `bool` (`True` = current is right child).
- **Authentication path**: `list[tuple[digest_tuple, bool]]` of length
  `merkle_depth()`.

## What's next

Two natural directions:

1. **Migrate QChain's anon-spend layer to use these proofs.** This is the
   M8.5 work mentioned above. Concrete steps: rewrite `qchain.crypto.commitments`
   and `qchain.chain.shielded` to use `qstark_py.hash_leaf` / `hash_inner`;
   replace the M4 Schnorr proof code path with `qstark_py.prove_membership`.

2. **Scale to production depth.** Bump `MERKLE_DEPTH` from 4 to 20+ in
   the Rust crate, regenerate. Should be a one-line change but worth
   benchmarking — proving time and proof size grow roughly linearly with depth.

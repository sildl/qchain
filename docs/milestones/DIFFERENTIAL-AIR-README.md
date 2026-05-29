# DIFFERENTIAL-AIR — Phase 1

## What this is

A Python differential-testing layer over the Rust m86 STARK
implementation. The goal: provide an external auditor (and our own
regression tests) with an **independent cross-check** that the AIR's
witness trace contains what we claim it contains, on both honest and
adversarially-crafted inputs.

The work landed as one piece of audit-readiness scaffolding — it
exists explicitly to make the next external audit cheaper and more
focused.

## What it does

The differential test exercises two independent implementations of
the m86 STARK's content:

1. **Python native computation** (`qchain/crypto/m86_reference.py`'s
   `compute_expected`) — what root, nullifier, leaf, and output_leaf
   MUST be for a witness, computed using ONLY the hash primitives
   exposed by `qstark_py.hash_leaf` and `qstark_py.hash_inner`. This
   bypasses the AIR entirely; it uses the same primitives but the
   walk-the-Merkle-path logic is freshly implemented in Python.

2. **Rust trace builder** (`qstark::hash_air::m86_air::build_m86_trace`,
   newly exposed via `qstark_py.build_m86_trace_for_inspection`) —
   the actual trace the prover sends through Winterfell. We can now
   inspect every cell of every column in Python.

The tests then verify:

| Check | What it catches |
|---|---|
| `trace[ROOT_ROW][4..8] == native_root` | Trace builder bug that produces a "valid-looking" trace whose root isn't what the witness implies |
| `trace[NULLIFIER_LAST_ROW][4..8] == native_nullifier` | Same, for the nullifier (claim C2) |
| `trace[LEAF_LAST_ROW][4..8] == native_leaf` | Same, for the input leaf |
| `trace[OUTPUT_LEAF_LAST_ROW][4..8] == native_output_leaf` | Same, for the change-note output |
| 17 structural invariants | Witness-column constancy, dir-bit booleanity, bit-decomposition correctness, block-boundary continuity, padding-row equivalence |
| 30 random witnesses pass all of above | Coverage |
| Honest proof verifies | End-to-end integration sanity |
| Tampered public inputs are rejected at verify | Fiat-Shamir binding for each of root, nullifier, output_leaf, (unshield_amount, fee) swap |
| Invariant checker catches deliberately-wrong expectations | Meta-test: the checker is not vacuous |

## What it does NOT do (yet)

This is **Phase 1**. It does not re-implement:

- **The Rescue-Prime permutation rounds** — those are ~150 lines of
  polynomial arithmetic. Reimplementing them in Python would
  introduce its own bug surface and gain little over trusting the
  Rust Winterfell hasher. Phase 2 would add this.
- **The AIR's transition constraints** — what `evaluate_transition`
  enforces between consecutive rows. Phase 2 work.
- **The Winterfell prover/verifier** — out of scope forever; trusted
  dependency.

**Phase 1 catches** the class of bugs where the trace builder produces
content disagreeing with the native computation. It does NOT catch
bugs where the trace AND the native computation share a
misconception (e.g., if both got the merge order wrong in the same
way). That class requires Phase 2.

The scope decision was deliberate: a complete Python AIR
reimplementation is 2-3 full sessions of careful work and brings its
own bug risk. Phase 1 catches the most common class of trace-builder
bug in one session.

## Implementation

### New Rust function: `build_m86_trace_for_inspection`

Added to `qstark_py/src/lib.rs`. Wraps the existing public
`build_m86_trace` function and converts the resulting TraceTable into
a Python list-of-lists of ints. Inputs are the same as
`prove_m86_membership` (the standard witness shape). Output is a
256-row × 151-column 2D list.

Also added: `m86_trace_dims()` returning `(width, length,
active_rows, num_blocks, rows_per_block)` so Python code can confirm
its constants match the Rust side.

### Python module: `qchain/crypto/m86_reference.py`

Three components:

1. **Layout constants** mirroring `m86_air.rs` (`COL_DIR`, `COL_SK`,
   `ROOT_ROW`, etc.). These are the contract between the Python
   reference and the Rust trace.
2. **`compute_expected(sk, r, v, path, sk_out, r_out, v_out)`** —
   the native computation, returns `M86Expected(leaf, root,
   nullifier, output_leaf)`.
3. **`inspect_trace_boundaries(trace)`** — reads the boundary cells
   the AIR's `get_assertions` would pin to public inputs.
4. **`validate_trace_structural_invariants(trace, ...)`** — checks
   17 invariants the AIR claims about its witness columns.

### Tests: `qchain/tests/test_differential_air.py`

12 tests across 5 categories:

- **Native vs. trace boundaries** (2 tests): one fixed witness + 30
  random ones
- **Structural invariants** (2 tests): one fixed witness + 30 random
- **Prove-verify roundtrip** (1 test)
- **Public-input tampering** (4 tests): root, nullifier, output_leaf,
  (unshield_amount, fee) swap
- **Meta-tests on the invariant checker** (3 tests): wrong sk, wrong
  dir bit, wrong sibling — confirms the checker is not vacuous

Total runtime: ~0.4 seconds. The structural-invariant checks add
microseconds; the boundary digests are 4-tuple comparisons; the
proving tests are amortized over a few witnesses. All tests
deliberately avoid running the slow Winterfell prove path in a loop
(that's already exercised by `test_anon_stark.py`).

## What changed

| File | Change |
|---|---|
| `qstark_py/src/lib.rs` | Added `m86_trace_dims`, `build_m86_trace_for_inspection`; updated imports |
| `qstark_py/...wheel` | Rebuilt and reinstalled |
| `qchain/crypto/m86_reference.py` | New module (~300 lines, mostly invariant checks + comments) |
| `qchain/tests/test_differential_air.py` | New test file (12 tests) |
| `qchain/DIFFERENTIAL-AIR-README.md` | This document |

No changes to:
- The m86 AIR itself
- The chain protocol
- Any existing test
- The wheel's existing API surface (all additions are new)

## Test results

| Layer | Pre-differential | Post-differential |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 199 | **211** (+12 differential) |
| **Total** | **330** | **342** |

All green. The new tests run in 0.35 seconds.

## What this gives an auditor

Three things an external auditor can do with this scaffolding that
they couldn't before:

1. **Inspect any cell of the trace.** Previously the trace was opaque
   to Python — only public inputs were exposed. Now an auditor can
   write `trace = q.build_m86_trace_for_inspection(...)` and check
   any of 256 × 151 = 38,656 field-element cells.
2. **Cross-check the native computation against the trace boundaries
   on adversarial witnesses.** Want to know if a witness with v=0,
   path of all-zeros, and identical sk/r produces consistent
   results? Build the trace, compute the expected values
   independently, compare. The framework is ready.
3. **Extend the structural-invariant suite.** The 17 invariants are
   the obvious ones; an auditor will know more. Adding new
   invariants is one Python function in `m86_reference.py`.

The auditor should also know what **isn't** caught: bugs in the
Rescue-Prime round arithmetic, bugs in the polynomial transition
constraints, bugs in the FRI / transcript layer. Those are Phase 2
work or trusted-dependency scope.

## Honest scope notes

- **Phase 1 is by design partial.** A complete Python AIR
  reimplementation would be the "gold standard" differential test
  but is 2-3× the work of what landed here. We chose the higher
  marginal-value-per-hour starting point.
- **No bugs found in this pass.** All 12 tests pass cleanly on
  random and fixed witnesses. This is good news but also says less
  than it might — Phase 1 catches a specific bug class (trace
  builder content vs. native), and we'd expect that class to be
  empty given the existing M8.6/M8.11 tests already exercise the
  pipeline.
- **The structural invariants are necessary but not sufficient.**
  All 17 could hold on a trace that's nevertheless cryptographically
  unsound — e.g., one whose Rescue-Prime rounds are computed wrong.
  Phase 2 closes that gap.
- **The boundary check is the strongest claim.** If
  `compute_expected(witness).root == inspect_trace_boundaries(build_trace(witness)).root`
  on every honest witness, the trace builder's public-output
  semantics match the native rules. That's a meaningful soundness
  claim about the trace builder specifically.
- **The Winterfell verifier remains the trusted root.** If
  Winterfell's verify accepts a proof, we accept the proof. If
  Phase 2 adds independent constraint evaluation, that becomes a
  second opinion. For now: one opinion.

## What's next

Sequence within audit-readiness:

1. ~~AUDIT-PACKAGE.md~~ ✓ shipped
2. ~~Differential AIR Phase 1~~ ✓ this pass
3. **Differential AIR Phase 2** — Python Rescue-Prime + transition
   constraint reimplementation. Adds independent constraint
   evaluation. ~2-3 sessions.
4. **Property-based testing with Hypothesis** — chain-level
   invariants on random tx orderings, persistence roundtrips, fork
   resolution. ~1-2 sessions.

After all of these: audit-ready in earnest. Sending to an external
auditor with confidence.

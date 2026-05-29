# DIFFERENTIAL-AIR — Phase 2

## What this is

The second layer of audit-readiness differential testing. Phase 1
cross-checked the trace builder's BOUNDARY content (root, nullifier,
leaf, output_leaf) against a Python native computation. Phase 2 adds
an **independent Python re-execution of the Rescue-Prime round
function** that runs ON THE TRACE's interior state — every round of
every active block — and confirms the trace's state columns match
what the Python round function computes.

This catches the bug class Phase 1 cannot: bugs where the trace
builder doesn't actually run Rescue-Prime correctly inside each
block but where the boundary outputs still happen to match the
native computation (because both share Winterfell's hash primitives).

## What Phase 2 catches that Phase 1 doesn't

Concretely, Phase 2 catches:

1. **Bugs in round ordering** — if the trace builder accidentally
   applied the rounds in wrong order, used wrong ARK indices, or
   skipped a round, Phase 2 catches it (Phase 1 wouldn't if the
   final digest happened to align)
2. **Bugs in per-round MDS or ARK application** — if a round
   constant was off by one position, or the MDS multiplication had
   a transposed matrix, Phase 2 detects the divergence row by row
3. **Trace-builder bugs in block boundary chaining** — confirms
   Merkle block N+1's input IS block N's output, not some other
   value
4. **Bugs in the nullifier preimage** — confirms `H(sk+1, r, v)`
   not `H(sk, r, v)` (claim C2)
5. **Bugs in the output-leaf preimage** — confirms `H(sk_out,
   r_out, v_out)`

## What Phase 2 still does NOT catch

Honestly stated for the auditor:

- **A bug in the Rescue-Prime round constants themselves.** Both the
  Rust (Winterfell) implementation and the Python reference here
  use the SAME constants (ARK1, ARK2, MDS) — extracted from
  Winterfell's source. If Winterfell's constants are wrong relative
  to the Rescue-Prime spec, we'd both be wrong in the same way.
  Catching this would require Phase 3: cross-referencing constants
  with a different implementation (Polygon Miden, Plonky2, or the
  Rescue-Prime spec's official test vectors).
  **Update: Phase 3 (see `DIFFERENTIAL-AIR-PHASE3-README.md`) now
  closes this gap via three layers: algebraic self-checks
  (structural properties any valid RPO constants must satisfy),
  regression test vectors (catching future drift), and an opt-in
  snapshot cross-reference harness (the harness is shipped; vendoring
  an actual Miden snapshot is the documented follow-up).**
- **Bugs in the AIR's polynomial transition-constraint formulas.**
  The AIR has polynomial expressions in `evaluate_transition` that
  are supposed to be ZERO on valid trace rows. Phase 2 confirms the
  trace IS valid (row i+1 = round(row i)); it doesn't verify the
  polynomial expressions ARE the right ones. An auditor would need
  to read `m86_air.rs::evaluate_transition` directly.
- **Bugs in the Winterfell FRI/transcript layer.** Out of scope for
  every Phase — trusted dependency.

## Implementation

### New file: `qchain/crypto/_rescue_constants.py`

62 lines of Python literals: MDS (12×12), ARK1 (7×12), ARK2 (7×12),
plus ALPHA, INV_ALPHA, NUM_ROUNDS, STATE_WIDTH, P. Extracted from
`winter-crypto-0.8.3/src/hash/rescue/rp64_256/mod.rs` via a one-off
script (`/tmp/extract_consts.py` in the dev environment).

Independence note: the constants ARE Winterfell's. The Python file is
a textual independent copy — same values, separate code path. A
Winterfell-constants bug would not be caught here. Phase 3
(`DIFFERENTIAL-AIR-PHASE3-README.md`) adds verification of the
constants themselves — algebraic self-checks (active), regression
vectors (active), and a snapshot cross-reference harness (built; the
external snapshot is the documented follow-up).

### New file: `qchain/crypto/rescue_prime_ref.py`

110 lines implementing Rescue-XLIX in straightforward Python:

```python
def apply_round(state, round_idx):
    state = apply_sbox(state)                    # x^7
    state = apply_mds(state)                     # MDS · state
    state = add_round_constants(state, ARK1[r])
    state = apply_inv_sbox(state)                # x^INV_ALPHA
    state = apply_mds(state)
    state = add_round_constants(state, ARK2[r])
    return state
```

No optimizations — uses Python's `pow(x, e, p)` for both forward and
inverse S-boxes. Slow (37ms to validate a full 256-row trace) but
unambiguous.

Verified by smoke test to match Winterfell on:
- `hash_leaf(1, 2, 3)` — preimage state (capacity=3, rate=[sk,r,v])
- `hash_inner(left, right)` — merge state (capacity=8, rate=[left||right])

### Extended `m86_reference.py`

Two new validators:

#### `validate_trace_round_function(trace)`

For every active block (23 blocks × 7 rounds = 161 rounds total):
read row 0 of the block as the initial state, run `apply_round` 7
times in Python, compare each output against the trace's
corresponding row. Returns a list of `InvariantViolation` for any
disagreement.

Runtime: ~37ms per trace (mostly the inverse S-box's `pow(x, INV_ALPHA, P)`
calls — Winterfell uses a 72-multiplication addition chain; we use
Python's built-in modexp).

#### `validate_trace_block_boundaries(trace)`

Confirms block-to-block plumbing:
- Leaf block output → Merkle block 1 input (with dir-bit ordering)
- Merkle block N output → Merkle block N+1 input (chain through all 20 levels)
- Nullifier block row 0 has preimage-init from `(sk+1, r, v)`
- Output leaf block row 0 has preimage-init from `(sk_out, r_out, v_out)`

Runtime: < 1ms per trace.

### New tests in `test_differential_air.py`

9 new tests for Phase 2:

| Test | Verifies |
|---|---|
| `python_round_matches_winterfell_leaf_hash` | Premise: Python apply_round = Winterfell on (1,2,3) preimage |
| `python_round_matches_winterfell_merge` | Premise: Python apply_round = Winterfell on merge state |
| `honest_trace_passes_round_validator` | Honest trace's every round matches Python re-execution |
| `10_random_traces_pass_round_validator` | Same, 10 random traces |
| `honest_trace_passes_block_boundary_check` | Block chaining + nullifier sk+1 + output preimage all correct |
| `round_validator_catches_state_tamper` | Meta: tampering mid-block is caught |
| `round_validator_catches_wrong_round_constants` | Tampering round-output is caught |
| `block_boundary_catches_broken_merkle_chain` | Tampering Merkle input is caught |
| `block_boundary_catches_nullifier_sk_off_by_one` | Critical: tampering sk+1 → sk in nullifier preimage is caught |

The last test is the most security-relevant: it directly exercises
claim C2 (nullifier binding to sk+1 not sk). If the AIR or trace
builder ever drifted on this binding, the entire double-spend
defense would silently break.

## Test results

| Layer | Pre-Phase-2 | Post-Phase-2 |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 211 | **220** (+9 Phase 2) |
| **Total** | **342** | **351** |

All green. The 21 differential tests (Phase 1 + Phase 2) run in
0.87 seconds.

## What this gives an external auditor

Beyond what Phase 1 gave them, they now have:

1. **Independent round-function reference** — a Python implementation
   they can read in ~110 lines, compare against Winterfell line by
   line, and use as a known-good oracle for any state they want to
   test.
2. **Block-level chaining audit** — visible confirmation that
   `merkle_root` proves a chain, not a free-floating tree-shaped
   hash. The block-boundary validator makes the Merkle structure's
   correctness checkable cell by cell.
3. **Critical-claim test** — the C2 (nullifier=H(sk+1,r,v)) binding
   has a dedicated test. Auditors examining double-spend defense
   can point at this test and say "this is what enforces it at the
   trace level."

The auditor should also know what's NOT here:

- **Constants cross-reference.** The MDS/ARK constants here are
  Winterfell's. A Phase 3 would extract the same constants from
  Polygon Miden's `miden-crypto` crate (which uses Rescue-Prime
  Optimized, not identical but related), or from the official
  Rescue-Prime SAGE reference, and confirm byte agreement.
- **Polynomial constraint cross-reference.** Phase 2 confirms the
  trace IS a Rescue-Prime computation; it does NOT confirm the
  AIR's polynomial constraints are SUFFICIENT to enforce that
  property in a STARK. An auditor reading
  `m86_air.rs::evaluate_transition` would need to symbolically
  verify the polynomial expressions.

## Honest scope notes

- **The Python round function is slow** (37ms per trace). Across 10
  random witnesses that's 0.4 seconds. Acceptable for differential
  testing; not for any production use.
- **Phase 2 found no bugs.** Both the round-function check and the
  block-boundary check pass on every honest trace and only fail on
  deliberately-tampered ones. This is good news but also says less
  than it might — the m86 AIR has been extensively soundness-tested
  via the Rust m86_soundness suite already. Phase 2's value is
  primarily auditor-facing: it provides an independent oracle and
  documented invariants. If a real bug existed in the round
  application, the m86 soundness tests would already have caught
  it via Winterfell rejection.
- **The ARK constants pass a basic sanity check.** ARK1 row 0,
  position 0 = 13917550007135091859 in our extraction matches the
  Winterfell source byte-for-byte; the round-function tests
  confirm the runtime behavior matches. This doesn't validate the
  constants against the Rescue-Prime SPEC — it validates they're
  used consistently between our Python and Winterfell's Rust.
- **No transition-constraint reimplementation.** The AIR's
  polynomial transition constraints encode the round function as a
  polynomial relation between adjacent rows. Phase 2 checks the
  row-to-row relation by running the round function directly,
  which is equivalent for soundness but does NOT verify the
  polynomial expressions are well-formed. Reading
  `evaluate_transition` is still the auditor's job.

## What's next

After Phase 2, the audit-readiness arc looks like:

- ✅ **AUDIT-PACKAGE.md** — auditor's entry point
- ✅ **Differential AIR Phase 1** — trace-content cross-check
- ✅ **Differential AIR Phase 2** — Rescue-Prime round re-execution
- **Property-based testing with Hypothesis** — next pass, ~1-2 sessions
- (optional) **Differential AIR Phase 3** — constants cross-reference
  against a different implementation (Polygon Miden, Plonky2)
- (deferred) **Polynomial constraint symbolic verification** — would
  need a SAT/SMT pass over the AIR's `evaluate_transition` formulas;
  significant work, audit-time scope

The property-based testing pass is the more obviously-valuable next
step. Phase 3 is fine to defer; Phase 2 plus the existing AIR
soundness tests already give an auditor strong tools for the AIR
layer.

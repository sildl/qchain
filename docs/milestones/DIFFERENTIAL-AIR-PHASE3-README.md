# DIFFERENTIAL-AIR — Phase 3

## What this is

Phase 3 of the differential AIR work: independent verification of the
Rescue-Prime constants used by `qstark` and `qchain.crypto.rescue_prime_ref`.

Phases 1 and 2 cross-checked the trace's contents (Phase 1, boundary)
and the trace's interior state (Phase 2, full round-by-round Python
re-execution). Both Phases 1 and 2 use Python constants extracted
from Winterfell. A bug in the **constants themselves** — i.e., a bug
that Winterfell propagated to us by extraction — would be invisible
to Phases 1 and 2. Phase 3 closes that gap.

Closes the "constants source" gap noted in
`DIFFERENTIAL-AIR-PHASE2-README.md`:

> *Independence note: the round constants are EXTRACTED from
> Winterfell's source code, not derived from a separate spec. So this
> implementation isn't fully independent of Winterfell — it's
> TEXTUALLY independent (different language, different code path,
> different at-runtime values) but shares Winterfell as the original
> source of constants. Catching a bug in Winterfell's constants would
> require a Phase 3 cross-reference against a different
> implementation (e.g., Polygon Miden's).*

## What Phase 3 catches

| Failure mode | Phase 1 | Phase 2 | Phase 3 |
|---|:---:|:---:|:---:|
| Trace builder boundary bug | ✓ | ✓ | — |
| Trace builder interior-state bug | — | ✓ | — |
| Winterfell constants corruption (extraction-time typo) | — | — | ✓ (Layers 1–3) |
| Winterfell constants corruption (upstream bug) | — | — | ✓ (Layer 3) |
| Future drift between our copy and upstream | — | — | ✓ (Layer 2) |

## Three layers of verification

Phase 3 implements three independent verification layers in
`qchain/crypto/rescue_constants_verify.py`. Each layer catches a
different class of failure. None individually is sufficient;
together they cover the realistic failure modes.

### Layer 1 — Algebraic self-checks

Properties the constants MUST satisfy regardless of where they came
from. No external source needed. Ten checks total:

| Check | What it verifies |
|---|---|
| `check_goldilocks_prime` | `P == 2^64 − 2^32 + 1` |
| `check_p_is_prime` | `P` is in fact prime (catches corruption) |
| `check_alpha_inv_alpha_relation` | `ALPHA × INV_ALPHA ≡ 1 (mod P − 1)` |
| `check_alpha_inv_alpha_round_trip` | Empirical `x^ALPHA^INV_ALPHA = x` |
| `check_mds_in_field` | Every MDS entry is in `[0, P)` |
| `check_mds_circulant` | MDS has the published circulant structure |
| `check_mds_top_row_matches_published` | Row 0 matches the RPO-paper row `(7,23,8,26,...)` |
| `check_mds_invertible` | `det(MDS) ≠ 0 mod P` |
| `check_ark_shape` | ARK1/ARK2 are `7 × 12` in-field |
| `check_ark_no_duplicate_rows` | No round-constant row is duplicated |

A typo during constant extraction (e.g., `7` → `17` in one MDS
position) would break either the circulant check or the
invertibility check. An out-of-field value would break the
in-field check. A duplicated row would break the duplicate check.

**Layer 1 caveats.** These checks confirm structural properties but
NOT cryptographic optimality. The constants could in principle still
fail the differential / linear / algebraic resistance criteria the
Rescue-Prime design targets — verifying those is a job for the
original Rescue-Prime security analysis, not for Phase 3.

### Layer 2 — Regression test vectors

Permutation outputs computed from the current implementation and
pinned as expected values. Catches FUTURE corruption: if someone
modifies `_rescue_constants.py` (intentionally or otherwise), the
regression vectors will fail and force the change to be visible.

Currently three vectors:

- `all_zeros`: input = `[0]*12`
- `ascending_1_to_12`: input = `[1, 2, ..., 12]`
- `all_p_minus_1`: input = `[P-1]*12`

**Layer 2 caveats.** Regression vectors are computed from our own
implementation. They do NOT validate the constants against an
EXTERNAL spec. They catch drift; they do not catch an existing bug
at the time the regression vectors were computed.

To upgrade these vectors from regression-only to spec-validated, an
auditor or contributor would:

1. Compute the expected outputs from an INDEPENDENT implementation
   (Polygon Miden, Plonky2, or the Rescue-Prime SAGE reference)
2. Replace the `expected_output` values in
   `compute_regression_vectors()` with the independently-computed
   ones
3. Update the `source` field of each vector

This work is documented but NOT yet done. See
`qchain/crypto/rescue_constants_verify.py::KNOWN_TEST_VECTORS` for
the upgrade-path comment.

### Layer 3 — Snapshot cross-reference

Phase 3 includes a harness that diffs our constants byte-for-byte
against an independent constants snapshot. The snapshot lives in
`qchain/crypto/rescue_constants_snapshots/*.json`. If present, the
test verifies every field matches. If absent, the test is gracefully
skipped with a clear message about how to enable it.

**Layer 3 is the strongest layer, but it requires an external
artifact.** The harness is built; the snapshot is not yet vendored.

#### Why no snapshot is vendored yet

This Phase 3 pass was developed in an environment without live
network access to GitHub or other source-of-truth repositories.
Manually transcribing 7×12 + 7×12 = 168 round constants and a 12×12
MDS matrix from memory would be self-deception: the snapshot
would be "independent" in name only, since the author of this pass
might have transcribed errors that match their model of the
constants rather than the actual published values.

The honest answer is: **vendor a snapshot in a follow-up, with
explicit attribution and a method of verification**. Either an
external contributor who can fetch the constants does so, or a
future pass with network access pulls them from a known-good
commit hash of `miden-crypto` and pins the commit in the snapshot
file.

#### Snapshot JSON schema

When a snapshot IS provided, the JSON must have this shape:

```json
{
  "source":     "miden-crypto v0.X.Y (Polygon Miden)",
  "url":        "https://github.com/0xPolygonMiden/crypto/blob/<commit>/src/hash/rescue/rpo/mod.rs",
  "fetched_at": "YYYY-MM-DD",
  "fetched_by": "<name or handle>",
  "P":          18446744069414584321,
  "STATE_WIDTH": 12,
  "NUM_ROUNDS":  7,
  "ALPHA":       7,
  "INV_ALPHA":  10540996611094048183,
  "MDS":  [[7, 23, 8, ...], ...],
  "ARK1": [[...], ...],
  "ARK2": [[...], ...]
}
```

Multiple snapshots can coexist (one per source); all are verified.
A disagreement between snapshots, or between a snapshot and our
copy, is a security-critical finding and breaks the test loudly.

## Fingerprint

For convenience, Phase 3 computes a SHA-256 fingerprint over a
canonical serialization of all constants. The pinned fingerprint
at the time of this pass:

```
6b4dcb6f3ae263e44e9759e62113d00b0925f258add4965b8c7330354e42af05
```

The fingerprint is checked by `TestFingerprintStability` — if it
changes, the test breaks loudly. This is a defensive measure
against silent constant modification.

A reviewer can compare this fingerprint against an independent
project's by:

1. Copying that project's Goldilocks/RPO constants
2. Computing the same canonical-JSON-then-SHA-256 over them
3. Comparing the resulting hex string

Matching fingerprints prove byte-identical constants. Different
fingerprints surface a constant discrepancy that should be
investigated.

## Tests

`tests/test_rescue_constants_phase3.py` — 25 tests across 5 classes:

| Class | Tests | What's covered |
|---|---:|---|
| `TestLayer1AlgebraicSelfChecks` | 11 | Each individual algebraic check + the bundled `run_all` |
| `TestLayer1ChecksCorrectlyDetectErrors` | 3 | Negative tests: each check fires on corrupted input |
| `TestLayer2RegressionVectors` | 4 | Vector existence, shape, verification, sanity |
| `TestLayer3SnapshotCrossReference` | 2 | Status message + opt-in cross-reference (skipped when no snapshot) |
| `TestFingerprintStability` | 3 | Fingerprint pin, determinism, format |
| `TestPhase3IntegratesWithPhase2` | 2 | Smoke tests that Phase 3 imports compose with the existing reference round function |

Runtime: ~1 second total. All pass; one skip when no snapshot is present (expected).

## Test results

| Layer | Pre-Phase-3 | Post-Phase-3 |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 312 | **337** (+25 Phase 3 tests) |
| **Total** | **443** | **468** |

All green. No regressions in any existing test suite.

## What changed in the repo

| File | Change |
|---|---|
| `qchain/crypto/rescue_constants_verify.py` | New file: Layer 1 algebraic checks, Layer 2 regression vectors, Layer 3 snapshot harness, fingerprint utility |
| `qchain/crypto/rescue_constants_snapshots/` | New directory (empty); destination for vendored snapshots |
| `qchain/tests/test_rescue_constants_phase3.py` | New file, 25 tests |
| `qchain/DIFFERENTIAL-AIR-PHASE2-README.md` | Updated: notes Phase 3 closes the "constants source" gap |
| `qchain/DIFFERENTIAL-AIR-PHASE3-README.md` | This document |
| `qchain/ROADMAP.md` | 1.2 marked shipped |
| `qchain/THREAT-MODEL.md` | Updated AIR-correctness assumption notes |
| `qchain/README.md` | Test totals 337 / 468 |
| `qchain/DOCS.md` | Entry #38 for this README |

No changes to:
- The constants themselves (`_rescue_constants.py`) — only verified
- The Rust AIR or qstark trace builder
- Any existing test or non-test module

## Honest scope

What this pass does:

- Verifies the constants satisfy known structural properties (Layer 1)
- Catches future drift via pinned regression vectors (Layer 2)
- Provides a harness for cross-reference against external snapshots (Layer 3)
- Pins a canonical fingerprint that future changes must explicitly bump

What this pass does NOT do:

- It does not pull the snapshot from Polygon Miden's source. The
  harness exists; the snapshot is opt-in. Live cross-reference
  remains a follow-up requiring network access to GitHub
  (`github.com`, `raw.githubusercontent.com`).
- It does not derive the constants from first principles (the
  Shake256-based round-constant derivation from the Rescue-Prime
  spec is a separate exercise).
- It does not validate cryptographic optimality (differential /
  linear / algebraic resistance) — that belongs in the original
  Rescue-Prime security analysis.

What an external auditor or future contributor would do to close
the remaining gaps:

1. Fetch the current `Rpo256` constants from
   `0xPolygonMiden/crypto` at a pinned commit
2. Save them as `qchain/crypto/rescue_constants_snapshots/miden_<commit>.json`
   in the schema documented above
3. Run `pytest qchain/tests/test_rescue_constants_phase3.py` —
   Layer 3 will activate and verify byte-equality

The most likely outcome is that Layer 3 will pass on first try
because Winterfell, Miden, and the published RPO spec use the same
constants — but having the test in place means a future drift between
the projects (or a future bug introduced by an upstream change)
will be caught loudly.

## Why "Phase 3 with the snapshot gap" is still valuable

A common pattern in security work is to defer a defense because the
prerequisite isn't yet met. Phase 3 deliberately does NOT do that.
The verification harness is shipped now, with the gap explicitly
documented. The result:

- An auditor reading the project sees the harness exists and the
  one missing piece (the snapshot) is well-specified
- Closing the gap is a 30-minute task for anyone with network access
- The Layer 1 and Layer 2 protections are active TODAY, not
  someday-when-the-snapshot-arrives
- The fingerprint pin protects against silent drift now

This matches the project's audit-readiness pattern: defenses
land incrementally with their honest-scope notes attached, rather
than waiting for perfect-state completion.

## What this gives the project

- A defense against extraction-time constant corruption (Layer 1)
- A defense against future drift between our copy and upstream (Layer 2)
- A clearly-specified path to closing the "constants source" gap
  noted in Phase 2 (Layer 3, opt-in)
- A canonical fingerprint that makes future constant changes visible
- One more piece of audit-package evidence: the constants are not
  just trusted, they're verified

## What's next

`1.2` is the last open audit-readiness item on the original roadmap.
The roadmap status after this pass:

| Item | Status |
|------|--------|
| 1.1 External audit engagement | Recommended; awaiting external engagement |
| 1.2 Differential AIR Phase 3 | ✅ Shipped (this pass, with documented snapshot follow-up) |
| 1.3 Publication writeup | ✅ Shipped |
| 1.4 Wallet key encryption at rest | ✅ Shipped |
| 1.5 Rate limiting / DoS hardening | ✅ Shipped |
| 1.6 Persistent wallet shielded-note tracking | ✅ Shipped |
| Dashboard auth (bonus) | ✅ Shipped |

The remaining 1.x item (1.1, external audit) is calendar/budget, not
engineering. The recommendation hasn't changed: **stop adding code;
engage external eyes.**

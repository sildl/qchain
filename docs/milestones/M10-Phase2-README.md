# Milestone 10 Phase 2 — Mixer soundness adversarials

## Summary

Phase 1 proved the chain mechanics work. Phase 2 proves the mixer
attack surface is actually defended, not just that the happy path
runs. Seven adversarial tests cover the distinct attack classes the
M10 construction introduces; the existing M8.6 / M8.8-A1 / M8.11
soundness suites carry over automatically because the mixer reuses
m86_air unchanged.

**Status: SHIPPED.** 142 QChain tests passing (was 135 at Phase 1
close, +7 from Phase 2). Zero regressions.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Chain integration + 6 happy-path tests | done |
| **2** | **Soundness adversarials for mixer attack classes** | **DONE** |
| 3 | Network propagation + adversarial tests | not started |
| 4 | Dashboard UX + wallet bookkeeping | not started |

## Why Phase 2 is mostly verification, not new code

The mixer withdrawal proof IS an m86_air proof. Every soundness
property already proven against m86_air (M8.6 nullifier binding,
M8.8-A1 value conservation + range proof, M8.11 output-leaf binding)
carries over to mixer withdrawals automatically.

Phase 2 doesn't add new defense — it adds tests that exercise the
existing defenses *at the mixer surface*, plus a few attacks unique
to the mixer construction (cross-tree replay, mixer↔STARK boundary
inflation, malicious-miner block injection).

This is the right kind of finding. Layered defense should mean each
attack class has a clear answer, even if the actual enforcement
happens deeper down. What Phase 2 proves is that the deeper enforce-
ment **reaches the mixer surface** without being bypassed.

## Seven adversarial tests, all green

File: `qchain/tests/test_mixer_soundness.py`

| # | Attack class | Defense layer | Test |
|---|--------------|---------------|------|
| 1 | Cross-tree replay: STARK proof submitted as mixer withdrawal | Stale-root check at admission | `test_m10_phase2_stark_proof_rejected_as_mixer_withdrawal` |
| 2 | Cross-tree replay: mixer proof submitted as STARK-anon spend | Stale-root check at admission | `test_m10_phase2_mixer_proof_rejected_as_stark_spend` |
| 3 | Tampered nullifier post-construction | Fiat-Shamir cross-check via verify_m86_membership | `test_m10_phase2_tampered_mixer_nullifier_rejected` |
| 4 | Inflation at mixer→STARK boundary (output value > deposit) | create_mixer_withdraw_tx helper + AIR value-conservation | `test_m10_phase2_inflation_at_mixer_boundary_rejected` |
| 5 | Destruction at mixer→STARK boundary (output value < deposit) | Same defenses, opposite direction | `test_m10_phase2_destruction_at_mixer_boundary_rejected` |
| 6 | Forged proof in malicious-miner block bypassing admission | is_valid() chain replay re-verifies | `test_m10_phase2_forged_proof_in_block_caught_by_is_valid` |
| 7 | Tampered mixer_root post-construction | Stale-root check (and FS for the deeper variant) | `test_m10_phase2_tampered_mixer_root_rejected` |

### Notable findings during construction

**Attack 5 (destruction)** — the "destroying value" attack is interesting
because it can't actually be abused for anything useful (the attacker
just loses their own coins). The test confirms the defense fires
anyway, because soundness should be symmetric in value-direction.

**Attack 6 (malicious miner block injection)** was the moment-of-truth
test for Phase 1's `is_valid()` extensions. A miner can put anything
in a block they mine; the question is whether honest peers running
`is_valid()` reject it. They do — the M8.10 pattern (replay state and
re-verify proofs against pre-block state) extends to mixer withdrawals
exactly as designed.

**Attack 4 (inflation)** has two layers of defense:
1. `create_mixer_withdraw_tx` rejects mismatched values at construction
   time with a clear ValueError ("output_note value must equal deposit
   denomination")
2. Even if the helper is bypassed, the AIR's value-conservation
   constraint catches it during `prove_m86_membership` (the
   `witness inconsistency: v != ...` panic)

Either layer alone would suffice; both together is honest defense
in depth.

## Attack classes NOT covered (honestly documented)

The Phase 1 README flagged `withdraw_amount` as an admin-side
classification label, not bound to the proof via Fiat-Shamir. Phase 2
**deliberately did not change this**:

- Tampering `withdraw_amount` post-construction is "free" — the proof
  still verifies because the field isn't in the FS transcript
- This can mislead chain-analysis tools that try to partition the
  anonymity set by denomination
- It does NOT enable any value-flow attack; the actual value movement
  is determined by output_leaf's hidden preimage and is enforced by
  the AIR

Binding `withdraw_amount` to the proof would require either:
- A new public input on the AIR (touches m86_air — risky regression)
- A separate chain-side commitment (e.g., the chain stores
  expected_denomination per leaf and checks at verify time)

Both are real future work but not Phase 2 scope. The current behavior
is documented honestly so anyone reading the code knows what the
label does and doesn't guarantee.

## Other Phase 1 honest scope items — status unchanged

These remain real limitations and are NOT addressed by Phase 2:

- No timing-attack defense (same-block deposit + withdraw still allowed)
- Depositor still publicly identified at deposit time
- Anonymity sets in tests are trivially small
- No network adversarial coverage (Phase 3)
- No wallet API for tracking mixer notes
- No dashboard UX
- No persistence

Phase 2 is specifically about **proving the existing cryptographic
defenses fire correctly at the mixer surface**. The orthogonal
concerns above are tracked separately.

## Test totals at Phase 2 close

| Layer | M10 Phase 1 | M10 Phase 2 |
|-------|------------:|------------:|
| qstark Rust | 110 | 110 (unchanged) |
| qstark_py Python | 21 | 21 (unchanged) |
| QChain Python | 135 | **142** (+7) |
| **Total** | **266** | **273** |

All green. Zero regressions from any prior milestone.

## What carries over from M8.6 / M8.8-A1 / M8.11

The mixer reuses m86_air. These adversarial suites (already green)
also apply to mixer withdrawals:

- **`m86_soundness.rs`** (10 tests, M8.6) — nullifier binding,
  wrong root rejection, random byte-flips. Applies because mixer
  withdrawals are m86_air proofs against the mixer tree.
- **`m86_gap_a_soundness.rs`** (14 tests, M8.8-A1) — value
  conservation, range proof bypass attempts, field-wrap defense.
- **`m86_partial_spend_soundness.rs`** (14 tests, M8.11) —
  output-leaf binding, witness inconsistency, value-conservation
  forgery.

That's 38 underlying soundness tests already passing that prove
the cryptographic core. Phase 2's 7 tests are about confirming the
core's defenses reach the mixer surface.

## Stopping criterion met

- [x] 7 adversarial tests cover the distinct M10 attack classes
- [x] All 7 pass on first run
- [x] Existing 135 QChain tests still pass (no regressions)
- [x] Full qstark / qstark_py suites unchanged (no Rust touched)
- [x] Total: 142 + 110 + 21 = **273 tests passing**
- [x] Honest scope notes preserved for `withdraw_amount` and all
      other Phase 1 limitations

Phase 2 done. Next phase (3) is network propagation: explicit
gossip handlers for mixer txs and adversarial tests for malicious
peers tampering them between hops.

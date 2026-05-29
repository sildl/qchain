# QChain — Audit Pass Notes

**Status: Honest self-audit by the LLM-assisted developer. NOT
independent.** The same party that wrote most of the code wrote this
audit. Self-audits catch some bugs and miss others — particularly,
they miss the bugs the author already missed. Use this as a starting
point for a real audit, not a substitute.

## Methodology

For each threat in `THREAT-MODEL.md`, I asked three questions:

1. **Is there a test that exercises this threat?**
2. **Does the test actually cover what it claims?**
3. **What's the closest gap that could be cheaply closed?**

The answers fall into four buckets:

- **OK** — threat tested, test does what it claims
- **WEAK** — threat tested but test is narrower than the claim
- **GAP** — threat is in the model but no test covers it
- **NOT TESTABLE BY ME** — threat depends on cryptographic primitives I
  can't independently verify (Winterfell soundness, Dilithium soundness)

## Threat-by-threat audit

### T1: Spending without authorization (transparent)

- **Tests:** `test_chain.py` covers basic signature verify
- **Coverage:** OK at the chain-validation level. The chain rejects
  txs with invalid signatures.
- **Gap:** **WEAK** — I don't see a test that constructs a tx with
  a tampered signature byte and confirms `verify()` returns False.
  The tests construct txs and check `verify()` returns True; the
  negative case isn't explicitly exercised.
- **Cheap improvement:** Add `test_transaction_with_tampered_signature_rejected`.
  ~10 lines.

### T2: Double-spending (transparent)

- **Tests:** `test_chain.py` rejects negative balances; `test_network.py`
  covers fork resolution
- **Coverage:** OK for the no-fork case. For the fork-race case (a
  double-spend across competing chains), I see `test_network.py`
  exercising fork resolution mechanics but not explicitly the
  double-spend-across-forks scenario.
- **Gap:** **WEAK** on the adversarial fork-double-spend case.
- **Cheap improvement:** A test where node A mines `tx_X` spending
  Alice's balance to Bob, node B mines `tx_X` spending the same
  balance to Carol; after fork resolution exactly one is in the
  longest chain. ~30 lines.

### T3: Coin minting (transparent)

- **Coverage:** Implicitly tested by chain replay (`is_valid()` would
  catch wrong-coinbase blocks).
- **Gap:** No explicit test "a block with coinbase != 10 is rejected."
- **Cheap improvement:** Construct such a block, submit, assert
  rejection. ~20 lines.

### T4: Block reward inflation

- Same as T3.

### T5: Forged block

- **Tests:** `test_network.py` covers some forged-message handling.
- **Coverage:** WEAK on PoW puzzle bypass. I don't see a test that
  constructs a block with a hash that doesn't meet the difficulty
  requirement and confirms it's rejected. The mining code ensures
  blocks SATISFY the puzzle, but no negative test confirms the
  validation REJECTS one that doesn't.
- **Cheap improvement:** Negative test for difficulty-puzzle bypass.

### T6: STARK pool unauthorized spend

- **Tests:** `m86_soundness.rs::rejects_swapped_nullifier_completely`,
  `forging_with_wrong_sk_produces_different_nullifier`,
  `rejects_wrong_root`, `rejects_tampered_proof`,
  `proof_for_one_leaf_doesnt_verify_for_different_leaf`
- **Coverage:** OK. The Rust soundness suite explicitly covers the
  M8.5 Gap-B nullifier swap which was the canonical attack. Multiple
  tampering tests cover the "swap public inputs" attack surface.
- **NOT TESTABLE BY ME:** Whether Winterfell binds these inputs in
  the FS transcript. The tests assume Winterfell does its job —
  they don't independently verify FS binding by re-deriving the
  transcript.
- **Honest assessment:** This is the threat I am most comfortable
  claiming is well-covered, given the AIR-level test density. A
  real auditor would still want to verify the FS binding directly.

### T7: STARK pool double-spend

- **Tests:** Covered in chain integration via nullifier tracking;
  `test_anon_stark.py`
- **Coverage:** OK at chain level. At AIR level, `m86_soundness.rs`
  doesn't test "spend the same note twice" because that's a chain-
  layer property, not an AIR property.

### T8: STARK pool inflation/destruction

- **Tests:** `m86_gap_a_soundness.rs` (13 tests), particularly
  `wrong_unshield_amount_in_public_inputs_rejected`,
  `wrong_fee_in_public_inputs_rejected`,
  `swap_amount_and_fee_with_same_sum_rejected_via_fiat_shamir`,
  `zero_amount_zero_fee_for_nonzero_value_rejected`,
  `field_wrap_attack_documented_as_chain_layer_concern`
- **Coverage:** OK. The field-wrap concern is documented but the
  test name explicitly notes it's documented as a chain-layer issue,
  not an AIR-level fix.
- **HONEST CONCERN:** `field_wrap_attack_documented_as_chain_layer_concern`
  documents a known issue — values approaching the Goldilocks field
  modulus could wrap. The test acknowledges this is a chain-layer
  concern; meaning the AIR doesn't catch values that wrap to
  negatives. The chain layer must enforce value bounds.
  - **Where does the chain check this?** Let me trace it.

<details>
<summary>Tracing the field-wrap defense</summary>

The Goldilocks modulus is approximately 2^64 - 2^32 + 1. Values
near this modulus could wrap to small numbers, allowing a deposit
of "value 2^64-1" to be treated as "value 0" or similar.

Looking at `qchain/chain/blockchain.py`:

```python
# Block reward is fixed at COINBASE_REWARD (= 10)
# Mixer deposits validate denomination in MIXER_DENOMINATIONS
# Shield txs validate amount > 0 and sender balance >= amount
```

There's no explicit `amount < FIELD_MODULUS / 2` check.

This is a real soundness concern: if an attacker can craft a
transparent-to-STARK shield with amount near the field modulus,
the AIR sees a wrapped value. The deposit-side `amount > 0` check
catches negatives but doesn't catch large values that wrap.

**Severity:** Low for amounts within reasonable bounds (a billion
coins is ~2^30, far below 2^63). Severity is high IF the chain
allows truly unbounded amounts.

Looking further: `Transaction.amount` is `float` in
`qchain/chain/transaction.py`. A float has ~15 decimal digits of
precision. Maximum exactly-representable integer is 2^53. So
floats can't reach 2^64.

But shield amounts go through int conversion at the AIR boundary.
If a shield is constructed with a float close to 2^63, the int
cast yields a value within field bounds — no wrap.

**Conclusion:** This is largely benign for the current
implementation because the float ceiling is well below the field
ceiling. A real auditor should still verify this remains true
across all entry points (txn signing, mempool admission, block
validation, AIR construction).

</details>

- **Test addition that would help:** Verify behavior at large
  amounts (e.g., 2^50). Currently the test names suggest values
  "just below Goldilocks modulus prove" — meaning the proof
  succeeds — but the chain-layer behavior at such amounts isn't
  explicitly tested.

### T9: STARK pool stale-root attack

- **Tests:** `m86_soundness.rs::rejects_wrong_root`
- **Coverage:** OK at AIR level. At chain level: the chain only
  applies a STARK-anon tx if `tx.merkle_root == chain.stark_anon_tree.root()`.
- **Gap:** **NONE OBVIOUS**. This threat is well covered.

### T10: Mixer pool unauthorized withdraw

- **Inherits:** T6 (same AIR, same proof system)
- **Coverage:** OK via T6 inheritance, plus mixer-specific tests in
  `test_mixer_soundness.py`.

### T11: Mixer pool inflation across denomination boundary

- **Tests:** `test_hardening_withdraw_amount.py::test_hardening_chain_state_shape_invariant_across_denominations`
- **Coverage:** OK. The hardening tests explicitly verify the AIR
  enforces value conservation regardless of label tampering.
- **Auditor concern:** The "1-coin in, 1000-coin out" attack relies
  on the deposit's leaf hash binding the value. If an attacker
  could find a hash collision between `H(sk, r, 1)` and `H(sk', r', 1000)`,
  they could deposit small and withdraw large. This depends on
  BLAKE3 collision resistance — out of scope per the threat model.

### T12: Mixer denomination-set partition

- **Tests:** `test_hardening_withdraw_amount.py::test_hardening_serialized_withdrawal_does_not_leak_denomination_label`,
  + 5 others
- **Coverage:** OK. Confirmed: the wire format doesn't expose the
  denomination.
- **Auditor concern:** The TEST verifies the field doesn't appear
  in `to_dict()`. It doesn't verify the proof bytes themselves
  don't encode the denomination in a recoverable way. Winterfell
  proofs are zero-knowledge by construction, but verifying this
  empirically would mean: prove two withdrawals at different
  denominations, check the proof bytes are statistically
  indistinguishable. That's a harder test.

### T13: Mixer same-block linkability

- **Tests:** NONE
- **Coverage:** **GAP. KNOWN.** Documented in all M10 phase READMEs
  as honest scope: "no timing-attack defense — same-block deposit +
  withdrawal still trivially links."
- **Cheap improvement:** Even without a fix, a test that
  *demonstrates* the linkage attack would be useful for an auditor
  — it concretely shows the gap rather than just describing it.
  ~40 lines.

### T14: Mixer timing analysis across blocks

- **Coverage:** **GAP. KNOWN.** Documented; depends on anonymity-set
  size which the project doesn't guarantee.

### T15: Mixer DoS via gossip flood

- **Coverage:** **GAP. KNOWN.** Documented.
- **Audit concern:** No bound on proof bytes either. A peer could
  gossip a 1GB "proof" and the receiver would attempt to parse and
  reject it, consuming bandwidth + parse time even if rejection is
  fast. Real deployment needs message-size limits.

### T16: M4 anon pool unauthorized spend

- **Tests:** `test_anon.py`, `test_shielded.py`
- **Coverage:** OK at chain integration level.

### T17: M4 anon pool double-spend

- Covered via nullifier tracking; same pattern as T7.

### T18: Persistence corruption

- **Tests:** `test_persistence.py` covers happy-path load.
- **Gap:** No test for corrupt files. `Blockchain.load()` does NOT
  call `is_valid()` after rebuild. A test that loads a chain
  whose blocks reference impossible parent hashes (manually
  edited) would either reveal a bug or confirm the rebuild handles
  it.
- **Cheap improvement:** Add `test_persistence_corrupt_chain_file_load_fails_or_invalidates`.

### T19: Cross-version persistence

- **Tests:** `test_persistence_wallet_old_format_loads_with_empty_notes`
  covers wallet migration.
- **Gap:** **GAP** for chain-side schema changes. No version field.
- **Cheap improvement:** Add a `version: 1` field to the saved
  chain JSON and have `load()` reject unknown versions.

### T20: Replay across networks

- **Coverage:** **GAP. KNOWN.** Not relevant for single-network demo.
- **Cheap improvement:** Add a chain ID to signed tx data.

### T21: Wallet key compromise

- **Coverage:** **GAP. KNOWN.** Documented.

### T22: Dashboard endpoint abuse

- **Coverage:** **GAP. KNOWN.** Localhost binding.

### T23: Memory exhaustion via large block

- **Coverage:** **GAP. KNOWN.**

## Summary of audit findings

| Status | Count | Threats |
|---|---|---|
| OK — well covered | 7 | T6, T7, T9, T10, T11, T16, T17 |
| WEAK — tested but narrower than claim | 4 | T1, T2, T5, T8 |
| GAP — known, documented, not fixed | 9 | T13, T14, T15, T19 (partial), T20, T21, T22, T23, T18 (partial) |
| GAP — present but undocumented | 2 | T3, T4 (no explicit negative tests for coinbase abuse) |
| NOT TESTABLE BY ME | underlying | Winterfell, Dilithium |

## Patterns I notice

### Pattern 1: Negative tests are underweighted

Many threats have happy-path tests but no negative-path tests. The
pattern "construct a valid X, check it verifies" is widespread.
The pattern "construct an X with property Y tampered, check it
fails" is less common at the chain level.

This is a real gap. The Rust soundness tests do this well (every
attacker-controlled input has a "tampering rejected" test). The
Python chain tests do this less consistently.

### Pattern 2: Heuristic claims aren't isolated

The threat model mixes formal claims (T1, T6) with heuristic ones
(T9 within reorgs, T14 anonymity-set claims). It would be cleaner
for each claim to declare its assumptions upfront. The current
codebase has scattered honest-scope notes across READMEs; a single
"assumptions" table at the project level would be clearer.

### Pattern 3: Demo-vs-production conflation

Many "GAP — KNOWN" items are "not relevant for demo, would matter
for production." This is fine, but it should be DECLARED:
"QChain is a research prototype intended for demos and small
experiments, NOT for value-bearing deployments." If that statement
appears prominently in the top-level README, all the demo-only
gaps become non-issues.

## Cheap test additions that would actually move the needle

If I had to recommend the next batch of test work, ordered by
value-per-line-of-code:

1. **Negative-test sweep for transparent transactions** (T1, T3, T4):
   tampered signature rejected, wrong-coinbase block rejected,
   negative-balance tx rejected. ~80 lines.
2. **Fork double-spend test** (T2): two competing chains both spending
   the same balance; assert convergence preserves at most one. ~50 lines.
3. **Mixer linkability demo test** (T13): explicitly demonstrate the
   same-block link, so a future fix has a regression test to track.
   ~40 lines.
4. **Chain corruption test** (T18): write a malformed-but-parseable
   chain file and verify load fails or detects inconsistency.
   ~30 lines.
5. **Version field** (T19): add `version: 1` to chain save, reject
   unknown versions on load. ~10 lines of code, ~20 lines of tests.

Total: ~230 lines of new test code, covering all the WEAK and GAP
items I found that are testable.

I'm explicitly NOT recommending writing these tests in THIS pass.
They're notes for whoever does the next pass. Mixing "audit" with
"fix" in the same session means the same author wrote both, which
is exactly the conflict of interest a real audit avoids.

## What this audit can't tell you

- **Whether the AIR is actually sound.** Winterfell does the heavy
  lifting; if Winterfell has a bug, all m86_air-based claims fall.
  An independent re-derivation of the AIR's transition constraints
  + boundary constraints + FS-bound public inputs would be the
  most valuable single audit task.
- **Whether the implementation matches the spec.** The READMEs
  describe behavior; the code implements it. Drift between the two
  is invisible to me because I wrote both.
- **Whether non-cryptographic security properties hold.** The
  dashboard auth, network rate-limiting, persistence atomicity —
  these are systems-engineering concerns. They get worse over time
  as the codebase grows; periodic re-audit is the only defense.

## Recommended next steps

1. **Read this document plus `THREAT-MODEL.md` to an external party.**
   The single highest-value action is getting eyes on the model that
   are not the eyes of the author.
2. **If continuing in-house, prioritize the 5 cheap test additions
   above.** They directly close documented gaps.
3. **Add a "QChain is a research prototype" disclaimer to the top
   README.** Reduces the surface area of "should this be
   production-safe?" concerns.
4. **Tag every commit with which threat-model entries it touches.**
   Forces ongoing discipline: if you add a new mechanism, what
   threats does it cover? If you remove one, what threats are
   newly uncovered?

The threat model document is a living artifact. This audit is a
snapshot. Both should be re-done whenever significant code changes.

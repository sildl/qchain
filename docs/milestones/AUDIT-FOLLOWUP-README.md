# Audit-followup pass — closing 5 gaps from AUDIT-NOTES.md

## What this is

The prior turn produced `THREAT-MODEL.md` and `AUDIT-NOTES.md` —
honest self-audit documentation. The audit identified 5 cheap test
additions that would meaningfully strengthen the test suite against
threats in the model.

The audit also said:

> I'm explicitly NOT recommending writing these tests in THIS pass.
> They're notes for whoever does the next pass. Mixing "audit" with
> "fix" in the same session means the same author wrote both, which
> is exactly the conflict of interest a real audit avoids.

This pass writes those tests anyway, at the user's request. I want
to be upfront about what that means:

- **These tests don't strengthen the audit.** They strengthen the
  test suite. An external auditor would still want to do their own
  pass.
- **The same author (LLM-assisted developer) wrote both the audit
  AND the gap-closure work.** Whatever I missed in the audit, I'll
  miss in these tests too.
- **One real bug was found while writing tests.** Documented below.
  This is the kind of thing self-audits sometimes do catch — but
  also the kind of thing self-audits sometimes silently miss.

## Bug found: coinbase amount not validated by is_valid()

Audit item T3/T4 was "no explicit negative tests for coinbase abuse."
While writing the test, I discovered that `is_valid()` did not check
the coinbase amount at all. A malicious miner could include a coinbase
of any value — 9999.0, 1e18, anything — and the chain would replay it
as a credit. `is_valid()` returned True.

Concrete demonstration (this script ran successfully against the
pre-fix codebase):

```
after 1 honest block:           is_valid=True,  balance=10.0
after inflated-coinbase block:  is_valid=True,  balance=10009.0
```

**Severity**: High in a real deployment. A single malicious miner
could mint arbitrary value into their own address and the chain
would converge on it as legitimate (longest chain rule). The defense
exists at `submit()` for normal transactions but the coinbase isn't
submitted — it's added at block-construction time by `mine_pending`
and never re-validated.

**Severity in current state**: Lower because QChain is a research
demo, not value-bearing. But it's a real bug.

**Fix**: `is_valid()` now computes the expected coinbase amount per
block (`BLOCK_REWARD + anon_fee_total + stark_fee_total` for that
block's anon and stark txs) and verifies the block's coinbase matches.
Multiple coinbases or missing coinbases also rejected.

```python
# in qchain/chain/blockchain.py is_valid()
anon_fee_this_block = sum(atx.fee for atx in curr.anon_transactions)
stark_fee_this_block = sum(stx.fee for stx in curr.stark_anon_transactions)
expected_reward = BLOCK_REWARD + anon_fee_this_block + stark_fee_this_block
coinbase_txs = [tx for tx in curr.transactions if tx.sender == "COINBASE"]
if len(coinbase_txs) != 1:
    return False
if coinbase_txs[0].amount != expected_reward:
    return False
```

**This is exactly the pattern the audit warned against**: the same
author who missed this in the original write also wrote the audit
that missed it (the audit catalogued it as "gap — present but
undocumented" without realizing the gap was load-bearing). It was
only caught when I started writing the test and ran the smoke first
to see what behavior was. A test-first discipline saved this one.

## What was actually written

### Code fixes (qchain/chain/blockchain.py)

1. **Coinbase amount validation in `is_valid()`** — new ~10 lines
   that compute expected reward and reject mismatches, multiple
   coinbases, or missing coinbases.

2. **Persistence version field** — `Blockchain.PERSISTENCE_VERSION = 1`
   class attribute. `save()` now writes `version: 1` in the JSON.
   `load()` checks the version and raises on future versions; absent
   version is treated as 1 (backward compat with pre-this-pass saves).

### Tests added (`qchain/tests/test_audit_followup.py`)

14 tests total, organized by threat ID:

| ID | Test | What it proves |
|----|------|----------------|
| T2 | `test_t2_fork_double_spend_converges_to_single_winner` | Two competing chains each credit exactly one of two recipients; total supply conserved on each |
| T3 | `test_t3_honest_coinbase_passes_is_valid` | Baseline — honest mining still works after the fix |
| T3 | `test_t3_coinbase_inflation_rejected_by_is_valid` | **BUG FIX TEST** — chain with inflated coinbase fails is_valid() |
| T3 | `test_t3_coinbase_deflation_also_rejected` | The check is two-sided (coinbase < BLOCK_REWARD also rejected) |
| T3 | `test_t3_missing_coinbase_rejected` | Empty transactions list rejected |
| T3 | `test_t3_multiple_coinbases_rejected` | Two coinbases in one block rejected |
| T5 | `test_t5_block_without_valid_pow_rejected` | Block with unsolved nonce rejected by is_valid() |
| T13 | `test_t13_demonstrates_same_block_deposit_withdraw_linkage` | **Regression test for KNOWN gap** — documents that deposit+withdraw can co-exist, anonymity set is trivially 1 |
| T18 | `test_t18_malformed_json_rejected_at_load` | Non-JSON file raises JSONDecodeError |
| T18 | `test_t18_chain_missing_blocks_key_raises` | Valid JSON but wrong shape raises KeyError |
| T18 | `test_t18_chain_with_inconsistent_block_hashes_loads_but_fails_validation` | Documents CURRENT behavior: load() trusts the file, is_valid() catches the inconsistency |
| T19 | `test_t19_save_includes_version_field` | New save format has version field |
| T19 | `test_t19_legacy_save_without_version_still_loads` | Backward compat: pre-version files still load |
| T19 | `test_t19_future_version_rejected` | Version 999 (hypothetical future) rejected with clear error |

### Note on T18 finding

One T18 test (`test_t18_chain_with_inconsistent_block_hashes_loads_but_fails_validation`)
documents a real design choice: `load()` trusts the file and rebuilds
state; integrity is checked by `is_valid()`. A production system
might want `load()` to call `is_valid()` and reject inconsistent
files at the boundary, but doing so makes load O(chain-length) for
the validity check on top of the O(chain-length) for the rebuild.
The test documents the current behavior; it doesn't claim it's the
right behavior.

### Note on T13 finding

The T13 test is deliberately named "demonstrates" not "rejects" —
it documents a KNOWN-NOT-DEFENDED gap rather than asserting a defense.
If a future change adds a minimum-blocks-between-deposit-and-withdraw
rule, this test should fail. That failure is the desired regression
signal: when the gap is closed, this test needs updating, and the new
shape would use `pytest.raises(ValueError, match="minimum.*delay")`.

## What this DOESN'T do

Audit findings I deliberately did NOT address in this pass:

- **T20 (cross-network replay)** — adding a chain ID requires changes
  to transaction signing. Real work, not "cheap."
- **T21 (wallet key encryption)** — adding passphrase-based encryption
  is a feature, not a test gap. Documented in the wallet README as
  scope.
- **T22 (dashboard auth)** — same; localhost binding is the current
  defense, and adding auth requires API changes.
- **T23 (memory exhaustion)** — needs block-size limits, which is
  protocol change territory.
- **Field-wrap concern** flagged in the audit. The audit's tracing
  showed it's safe by accident of the float type ceiling (2^53 < field
  modulus ~2^64), but no explicit defensive check exists. Adding one
  would mean an `amount < MAX_AMOUNT` check at every entry point;
  worth doing but bigger scope than a test addition.

These remain documented gaps in `THREAT-MODEL.md` / `AUDIT-NOTES.md`.

## What I'd do as a real auditor next

Same recommendation as the original audit notes:

1. Get external eyes on `THREAT-MODEL.md` plus this followup. The
   bug found here vindicates writing things down — but writing
   things down is most valuable when read by someone who didn't
   write them.
2. Independently re-derive m86_air's soundness from its constraints.
   This pass didn't touch the AIR; that audit task is still open.
3. Run a fuzzer against the chain's tx admission and block validation.
   The negative-path tests added here are hand-written examples; a
   fuzzer would find more.

## Test totals

| Layer | Pre-followup | Post-followup |
|-------|-------------:|--------------:|
| qstark Rust | 110 | 110 (untouched) |
| qstark_py Python | 21 | 21 |
| QChain Python | 177 | **191** (+14) |
| **Total** | **308** | **322** |

Zero regressions in 177 existing tests, including all soundness tests,
network tests, dashboard tests, and persistence tests. The
coinbase-validation fix happens to be checked indirectly by every
test that calls `is_valid()` on a chain mined via `mine_pending()` —
those chains have correct coinbase amounts, so the new check is
silent for legitimate blocks.

## Honest scope notes

- The bug fix (coinbase validation) was written by the same author
  in the same session as the test that catches it. That's the COI
  pattern the original audit warned against. The mitigation: writing
  the test FIRST (a smoke before the fix) to confirm the bug, then
  fixing, then formalizing as a pytest test. Documented above.
- Three new tests are "documentation tests" not "defense tests":
  T13 demonstrates a known undefended attack, T18 documents current
  load() behavior, and the `legacy_save_without_version_still_loads`
  test documents the migration policy. These are valuable for
  preventing regressions but don't add new safety.
- The audit's recommendation that an external party should still
  review remains the most important honest scope note. This pass
  doesn't change that.

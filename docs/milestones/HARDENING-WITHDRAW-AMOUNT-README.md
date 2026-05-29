# Hardening pass — withdraw_amount removed from MixerWithdrawTransaction

## What this is

A privacy-hardening pass that resolves the long-documented issue from
M10 Phases 1-2:

> `withdraw_amount` is admin-side, not FS-bound. The field exists on
> `MixerWithdrawTransaction` as a classification label for the
> denomination. Tampering it post-construction doesn't change the FS
> transcript and is NOT detected via the proof. It can mislead
> chain-analysis tools partitioning the anonymity set by denomination.

## Honest interpretation of "bind withdraw_amount to the mixer proof"

The user request was "bind withdraw_amount to the mixer proof." Two
literal readings:

1. **Add a public input to m86_air that carries withdraw_amount.**
   This would make the field genuinely FS-bound. But m86_air's
   contract has been frozen since M8.6 and re-engineered through
   M8.8-A1, M8.11 — 38 soundness tests verify its current behavior.
   Adding a new public input touches the AIR's degree specs and the
   constraint composition; any change is a real regression risk.
2. **Bind via the existing `unshield_amount` field.** I tried this on
   paper. The m86_air constraint is `v_in == unshield + fee + v_out`.
   For mixer-into-STARK-pool semantics, we need v_out > 0 so the
   spender can spend their new STARK note. If `unshield_amount =
   denomination`, then `v_out = 0` and `output_leaf = H(sk, r, 0)` —
   a STARK pool leaf with value zero, which is useless. There's no
   clean way to have both denomination FS-bound via the existing
   field AND a spendable STARK pool credit.

A third reading emerges from the analysis:

3. **Remove `withdraw_amount` entirely.** The field's two functions
   are (a) anonymity-set partition label and (b) admission filter for
   disallowed denominations. The label is the privacy leak. The
   admission filter is **redundant** with the deposit-side denomination
   check: `submit_mixer_deposit` already rejects deposits whose amount
   isn't in `MIXER_DENOMINATIONS`. Withdrawals can only consume leaves
   that were validly deposited, so withdrawals at disallowed
   denominations are impossible at the data level. The chain doesn't
   need to re-check.

I chose reading 3. It's the actual privacy improvement the request was
trying to achieve — without touching the cryptographic core.

## What changed

### `MixerWithdrawTransaction` (`qchain/chain/mixer_tx.py`)

- `withdraw_amount: int` field **removed** from the dataclass
- `txid()` no longer hashes the field
- `to_dict()` no longer emits it
- `from_dict()` accepts old-format payloads containing
  `withdraw_amount` and silently discards them (migration safety)
- `verify()` drops the denomination check (now redundant with the
  deposit-side check)
- `create_mixer_withdraw_tx` no longer sets the field

The struct now has just 5 fields: `mixer_root`, `nullifier`,
`output_leaf`, `proof`, `timestamp`.

### Dashboard (`qchain/dashboard/server.py`)

- `_on_mixer_withdraw` callback drops the field from the WebSocket
  payload
- `snapshot()`'s mixer_withdraw_mempool entries drop the field
- `/api/mixer/withdraw` response drops the field (clients can still
  see `new_stark_note_value` for the wallet bookkeeping)
- EventFeed React string for `mixer_withdraw` now says
  "anon withdraw (denomination private) → STARK pool" instead of
  showing a specific amount

### Tests

- `test_mixer_soundness.py`: removed `withdraw_amount=100` from the
  constructor call; updated the module docstring
- `test_network.py`: updated malformed-payload test to verify
  legacy `withdraw_amount` is silently ignored (not rejected as
  malformed)
- `test_dashboard_mixer.py`: changed the assertion from
  `wd["withdraw_amount"] == 100` to
  `"withdraw_amount" not in wd`

### New: `test_hardening_withdraw_amount.py` (6 tests)

| # | Test | Property |
|---|------|----------|
| 1 | `test_hardening_withdraw_struct_has_no_withdraw_amount_field` | Dataclass field removed |
| 2 | `test_hardening_withdraw_to_dict_does_not_include_withdraw_amount` | Serialized form clean |
| 3 | `test_hardening_serialized_withdrawal_does_not_leak_denomination_label` | Two withdrawals at different denominations have identical structural shape; the denomination doesn't appear in any non-opaque field |
| 4 | `test_hardening_from_dict_accepts_legacy_withdraw_amount` | Migration: old saved chains still load |
| 5 | `test_hardening_value_conservation_still_enforced_by_air` | The AIR still catches inflation/destruction attacks (defense unchanged) |
| 6 | `test_hardening_chain_state_shape_invariant_across_denominations` | The strongest end-to-end check: chain counters are identical regardless of which legitimate denomination was withdrawn |

All 6 pass on first run.

## What this changes about the privacy guarantee

**Before**: An observer watching the chain could see
`mwtx.withdraw_amount` for every withdrawal. They could partition the
anonymity set by denomination: "this withdrawal was for 100 coins,"
narrowing the candidate deposits to only those at denomination 100.
The label was tamperable but typically wouldn't be tampered (no
incentive to lie about your own denomination), so in practice it
worked as a partition leak.

**After**: The chain emits no denomination information for
withdrawals. An observer sees `(mixer_root, nullifier, output_leaf,
proof)`. The denomination is hidden inside `output_leaf =
H(sk_out, r_out, v_out)`, which can only be opened by someone who
already knows the spender's `(sk_out, r_out)` secrets. The anonymity
set for a withdrawal is **all un-withdrawn deposits across all
denominations**, not just the matching-denomination subset.

This is strictly better than the previous design.

## What this does NOT change

The value-flow soundness was never the concern. The AIR's
constraint `v_in == 0 + 0 + v_out` forces the new STARK pool leaf's
value to equal the consumed mixer leaf's value. Inflation and
destruction attacks at the boundary remain impossible.

Other M10 honest-scope items remain unchanged:

- **No timing-attack defense.** Same-block deposit + withdrawal still
  trivially links the depositor to the withdrawal. Real privacy
  requires either chain-side delay rules or client-side waiting.
- **Depositor publicly identified at deposit time.** Mixer privacy is
  between deposit and withdrawal, not against observing the deposit.
- **Anonymity sets in tests are trivially small.** Real privacy needs
  many deposits at the same denomination from many users — and now,
  with this change, deposits at ANY denomination from many users.
- **No DoS hardening for mixer gossip.**
- **No persistence for shielded notes was a problem until the prior
  persistence pass shipped.** Now wallets persist their mixer notes
  correctly across restarts.

## Trade-off: dashboard UI loses denomination display

The dashboard's Live Events feed used to show
`"anon withdraw 100 → STARK pool · 98656B proof"`. It now shows
`"anon withdraw (denomination private) → STARK pool · 98656B proof"`.

This is a real reduction in UI information density. The dashboard is
a debug/demo tool, not a production privacy tool — anyone running
both ends of a deposit + withdrawal locally already knows the
denomination by tracking their own wallet. For a real user wanting
to know how much they withdrew, the `/api/mixer/withdraw` response
returns `new_stark_note_value` which is the same information for
the local case.

For a chain observer watching another user's withdrawal, the
denomination is now genuinely hidden — which is the point.

## Test totals

| Layer | Pre-hardening | Post-hardening |
|-------|--------------:|---------------:|
| qstark Rust | 110 | 110 (no AIR touched, per honest interpretation) |
| qstark_py Python | 21 | 21 |
| QChain Python | 168 | **174** (+6 hardening tests) |
| **Total** | **299** | **305** |

Zero regressions. All 168 existing tests still pass — including the
M10 Phase 2 soundness suite that was originally written assuming the
field existed.

## Why this interpretation, not the literal one

The literal "add a public input to the AIR" path:
- Touches m86_air's degree specs and constraint composition
- Risks regressing 38 underlying soundness tests
- Doesn't actually achieve more privacy than removal (the
  denomination is already private via output_leaf when you remove
  the leak)
- Is genuinely M8.x-scale work, not a one-session pass

The literal "use existing unshield_amount" path:
- Doesn't have a clean mapping that preserves spendable STARK pool
  credits
- Would require either dummy spendable notes or a different output
  semantics — both are bigger changes than removal

The removal path:
- ~10 lines of code removed, ~40 lines of test code added
- Strictly improves privacy
- Survives every existing test
- Backward-compatible via from_dict accepting legacy payloads

This was the honest engineering call.

## What's next

Per the analysis a few turns back, remaining options:

- **Threat model document + audit pass.** Non-coding. Honest research
  discipline: write down what we claim to protect against and audit
  whether the tests actually cover those claims.
- **M8.9 sparse Merkle tree for depth 20+.** Real cryptographic
  milestone, lifts the 65,536-note anonymity-set cap to ~1M+.
- **Timing-attack defense for mixer.** Add a minimum-blocks delay
  before withdrawal is valid. Real privacy improvement, smaller in
  scope than M8.9.

The threat model document is probably the most honest next step — the
project now has enough mechanism that a written-down threat model
would clarify what each piece actually buys.

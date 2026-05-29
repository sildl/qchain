# UI fix — surface denomination for local-owned mixer withdrawals

## What this fixes

The prior hardening pass removed `withdraw_amount` from the mixer
withdrawal protocol, which was the right call for privacy: chain
observers no longer see a tamperable denomination label. But the
dashboard's Live Events feed lost the same information for the
**local user's own withdrawals**, where the dashboard is the wallet
that just spent the note and already knows the denomination.

"anon withdraw (denomination private) → STARK pool" was correct from
a network perspective but theater from the local user's perspective.

This pass restores denomination display for locally-triggered
withdrawals while keeping it private for foreign (gossiped) ones.

## The distinction that matters

There are two viewers of any mixer_withdraw event:

| Viewer | Knows the denomination? |
|---|---|
| The wallet that just signed the withdrawal | **Yes** — it picked the note |
| Anyone else watching the chain | **No** — denomination is hidden in `output_leaf` |

This mirrors real production design: your own wallet UI shows you
full detail about your own transactions; a chain explorer for
someone else's transaction shows only what's actually public.

## How the dashboard tells them apart

The dashboard's `Dashboard` holds the local user's `owned_mixer_notes`
list. Any mixer note the dashboard deposited is tracked there. When
`/api/mixer/withdraw` is called, it builds a proof FROM one of those
notes, then submits via `node.submit_mixer_withdraw_tx(mwtx)` which
fires `_on_mixer_withdraw(mwtx)` synchronously.

At callback time the matching mixer note is still in
`owned_mixer_notes` (the pop happens AFTER the callback fires).
We can identify ownership by scanning for any owned mixer note whose
nullifier equals the withdrawal's nullifier:

```python
for owned_note, _ in self.owned_mixer_notes:
    if owned_note.nullifier() == mwtx.nullifier:
        owner_denomination = int(owned_note.value)
        break
```

Match → local; no match → foreign. The same callback runs whether the
withdrawal arrived via the local /api/mixer/withdraw or via peer
gossip through `_handle_new_mixer_withdraw`, and produces the right
answer in each case.

## What changed

### Backend (`qchain/dashboard/server.py`)

`_on_mixer_withdraw` now emits a WebSocket event with two new fields:

- `is_local: bool` — true when the consumed mixer note belongs to us
- `denomination: int` — present only when `is_local` is true

For foreign withdrawals, the event has `is_local: false` and no
`denomination` key. The privacy property is preserved by structural
absence: a network observer running their own dashboard against a
peer's gossip sees no denomination, exactly as before this fix.

### Frontend React (in `INDEX_HTML`)

The EventFeed's mixer_withdraw render now branches:

```jsx
{ev.data.is_local ? (
  <>anon withdraw {ev.data.denomination} → STARK pool <span>(yours)</span></>
) : (
  <>anon withdraw (denomination private) → STARK pool</>
)}
```

Local-owned withdrawals show the amount with a "(yours)" tag, in
the emerald accent color used throughout the M10 UI. Foreign
withdrawals keep the privacy-respecting message.

## Tests added (`tests/test_ui_mixer_denomination_display.py`)

Three tests covering the three relevant scenarios:

| # | Test | Property |
|---|------|----------|
| 1 | `test_ui_local_mixer_withdraw_event_includes_denomination` | `/api/mixer/withdraw` produces an event with `is_local=True` and the correct denomination |
| 2 | `test_ui_foreign_mixer_withdraw_event_hides_denomination` | A withdrawal submitted via the chain API (mimicking gossip) where the dashboard doesn't own the consumed note produces `is_local=False` and no `denomination` key |
| 3 | `test_ui_mixed_withdrawals_correctly_distinguished` | A session with both local and foreign withdrawals produces correctly distinguished events — catches any state-leak bug that would make ownership detection sticky |

All 3 pass on first run (one initial failure was an unrelated
balance-funding mistake in test setup, immediately fixed).

The foreign-case test uses a clean trick to simulate "withdrawal we
don't own": construct the deposit and withdrawal via the chain API
directly using a separate `Wallet` instance, bypassing the
dashboard's `owned_mixer_notes` tracking entirely. The dashboard
sees the withdrawal as if it arrived via gossip, even though the
TCP layer isn't involved.

## Privacy property preserved

The protocol-level change from the prior hardening pass is unchanged:

- `MixerWithdrawTransaction` still has no `withdraw_amount` field
- `to_dict()` still emits no denomination
- The wire format is identical
- A chain observer running a peer dashboard against another node's
  gossip CANNOT see denomination (because their dashboard's
  `owned_mixer_notes` doesn't contain the relevant note)

What changed is purely the **local UX surface** of the dashboard
that owns the wallet. The dashboard does additional bookkeeping the
network doesn't see — that's already how it works for other things
(owned_stark_notes, owned_anon_notes, etc.).

## What this does NOT do

- **Doesn't surface denomination for STARK-anon spend events.** Those
  go through a separate code path (`_on_stark_anon_tx`). If similar
  UX is wanted there, mirror the pattern.
- **Doesn't expose denomination in the chain explorer endpoints.**
  `/api/state` doesn't return per-withdrawal denominations; same
  privacy reasoning applies (other users could scrape it).
- **Doesn't change persistence.** Owned notes still persist via the
  Wallet's `mixer_notes` and `stark_notes`. Across restart, the
  dashboard correctly re-identifies its own withdrawals.

## Test totals

| Layer | Pre-fix | Post-fix |
|-------|--------:|---------:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 174 | **177** (+3) |
| **Total** | **305** | **308** |

Zero regressions. The pre-existing `test_concurrent_blocks_resolved_by_extension`
flake remains intermittent (passes on retry, documented since session start).

## Honest scope notes still applicable

Project-wide limitations remain (per the M10 phase READMEs):

- No timing-attack defense — same-block deposit+withdraw still links
- Depositor publicly identified at deposit time
- Anonymity sets in tests are trivially small
- No DoS hardening for mixer gossip

Plus the dashboard-specific one introduced here:

- Ownership detection is O(N) per withdrawal event over the owned
  mixer notes list. For a wallet with thousands of pending notes
  this becomes a real cost. Production design: hash-table index from
  nullifier to owned note. Not in scope here (demo dashboards
  typically hold <10 notes).

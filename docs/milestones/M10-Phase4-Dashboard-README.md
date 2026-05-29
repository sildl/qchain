# M10 Phase 4 Dashboard UX — addendum (originally deferred)

## What this is

When Phase 4 shipped, the dashboard UX for mixer flows was explicitly
deferred in favor of completing the higher-value wallet bookkeeping.
The Phase 4 README documented the design but didn't ship the code:

> If/when the dashboard gets the mixer UI, the design is:
> - New panel: "Mixer" with two sub-flows (Deposit / Withdraw)
> - POST endpoints `/api/mixer/deposit` and `/api/mixer/withdraw`
> - Two new live-event types
> - Wires to `node.submit_mixer_deposit_tx` / `node.submit_mixer_withdraw_tx`
> - Estimated 3-4 hours of UI work

This addendum is that UI work, now shipped.

## What was added

### Backend (`qchain/dashboard/server.py`)

**Imports**: `MIXER_DENOMINATIONS`, `MixerDepositTransaction`,
`MixerWithdrawTransaction`, `create_mixer_deposit_tx`,
`create_mixer_withdraw_tx`.

**Dash class state**:
- `self.owned_mixer_notes: List[(STARKNote, pending_idx)]` — mixer
  notes deposited from this dashboard, tracked for later withdrawal.
- Two new callbacks wired: `node.on_mixer_deposit` and
  `node.on_mixer_withdraw` (use the hooks that Phase 3 added to Node).

**Event callbacks**:
- `_on_mixer_deposit(mdtx)` — emits WebSocket event with sender,
  amount, leaf hash, txid.
- `_on_mixer_withdraw(mwtx)` — emits WebSocket event with
  withdraw_amount, nullifier, output_leaf, proof_bytes.

**Snapshot extended** with eight new fields:
- `mixer_pool_size` — count of leaves in `mixer_tree`
- `mixer_nullifier_count` — count of seen mixer nullifiers
- `mixer_denominations` — the allowed amounts (for the dropdown)
- `mixer_deposit_mempool` — pending mixer deposits (summary form)
- `mixer_withdraw_mempool` — pending withdrawals (summary form)
- `owned_mixer_notes` — dashboard-owned mixer notes (summary form)

**Request models**:
- `MixerDepositRequest { denomination: int }`
- `MixerWithdrawRequest { note_index: int }`

**Two new endpoints**:
- `POST /api/mixer/deposit` — validates denomination, signs deposit with
  miner_wallet, calls `node.submit_mixer_deposit_tx`, tracks the note in
  `owned_mixer_notes`. Returns txid + leaf + depositor.
- `POST /api/mixer/withdraw` — looks up the note in `owned_mixer_notes`,
  finds the leaf in `mixer_tree`, generates a fresh output note,
  builds the STARK proof, calls `node.submit_mixer_withdraw_tx`.
  Updates bookkeeping: removes from `owned_mixer_notes`, adds to
  `owned_stark_notes` (so the new STARK note becomes spendable
  via `/api/stark/spend`). Returns txid + withdraw_amount + proof_bytes
  + new STARK note value.

Both endpoints surface useful 400 errors:
- "denomination N not in [1, 10, 100, 1000]"
- "mixer note not yet on-chain (deposit may still be in mempool — mine a block first)"
- "note_index out of range"
- "mixer deposit rejected: insufficient balance. Did you mine a block first..."

### Frontend (React-as-strings in `INDEX_HTML`)

**Two new stat tiles** in the top-level dashboard:
- "Mixer pool (M10)" — count of mixer leaves
- "Mixer nullifiers" — count of consumed deposits

Colors use `text-emerald-300` / `text-emerald-200` to distinguish
from the cyan-themed STARK pool tiles.

**Two new panels** in the Controls component:

1. **Deposit to mixer (M10)** — dropdown of denominations populated
   from `state.mixer_denominations`, plus a Deposit button.
2. **Withdraw from mixer** — dropdown of owned mixer notes
   (from `state.owned_mixer_notes`), plus a Withdraw button.
   Empty-state message: "deposit first to create a withdrawable note".

Both panels follow the visual pattern of the existing STARK panels
exactly (same input styling, same button widths, same emerald accent
color for the M10 brand).

**EventFeed extended** to render three event types that weren't
previously decorated:
- `shield_tx` — "sender shields amount → STARK pool" (cyan-300)
- `mixer_deposit` — "sender deposits amount → mixer" (emerald-300)
- `mixer_withdraw` — "anon withdraw amount → STARK pool · NB proof"
  (emerald-200)

Each event uses the existing `pulse-new` animation, so the
visual feedback when something propagates over the wire is the
same as for blocks and other tx types.

**Parent component (App)**:
- New state hooks: `mixerDenom` (default 100), `mixerWithdrawIdx` (default 0)
- New action handlers: `doMixerDeposit()`, `doMixerWithdraw()`
- Props passed through to `<Controls>`:
  `mixerDenominations`, `mixerDenom`, `setMixerDenom`,
  `doMixerDeposit`, `ownedMixerNotes`, `mixerWithdrawIdx`,
  `setMixerWithdrawIdx`, `doMixerWithdraw`

## Tests added (`qchain/tests/test_dashboard_mixer.py`)

Six pytest tests using FastAPI's `TestClient` (lighter than the
uvicorn-in-thread pattern the existing dashboard tests use — these
don't need real network, just the HTTP API):

| # | Test | What it proves |
|---|------|----------------|
| 1 | `test_m10_dashboard_state_exposes_mixer_fields` | `/api/state` returns all 6 new mixer-related fields with sensible initial values |
| 2 | `test_m10_dashboard_deposit_then_state_reflects_pending` | Successful deposit appears in mempool + owned_mixer_notes |
| 3 | `test_m10_dashboard_withdraw_rejected_before_mining` | Pre-mining withdraw returns 400 with clear message |
| 4 | `test_m10_dashboard_full_deposit_withdraw_flow` | End-to-end: counters all update, bookkeeping moves note from mixer to STARK, chain `is_valid()` passes |
| 5 | `test_m10_dashboard_bad_denomination_rejected` | Disallowed denomination returns 400 with allowed-set listed |
| 6 | `test_m10_dashboard_withdraw_bad_note_index_rejected` | Out-of-range `note_index` returns 400 |

All 6 pass on first run.

## Manual verification done

Beyond the automated tests, I ran an interactive smoke script that:
1. Mined 15 blocks → miner_balance = 150
2. POST /api/mixer/deposit with denomination=100 → txid returned
3. State showed 1 pending deposit + 1 owned mixer note
4. Tried /api/mixer/withdraw → rejected with "not yet on-chain"
5. POST /api/mine → deposit confirmed, mixer_pool_size=1
6. POST /api/mixer/withdraw → txid + 98656-byte STARK proof
7. State showed mempool with withdrawal, owned_mixer_notes empty,
   owned_stark_notes now contains the credit
8. POST /api/mine again → mixer_nullifier_count=1, stark_pool_size=1
9. POST /api/mixer/deposit with denomination=7 → rejected
10. `chain.is_valid()` → True

All checks passed. The dashboard end-to-end flow is functional.

## Test totals

| Layer | M10 Phase 4 (original) | + Dashboard UX |
|-------|-----------------------:|---------------:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 154 | **160** (+6 dashboard mixer tests) |
| **Total** | **285** | **291** |

Zero regressions in the 154 existing tests. The 9 existing
dashboard tests (using the uvicorn-in-thread pattern) still pass
unmodified.

## What this changes about the M10 milestone status

M10 was declared "complete on the chain, network, and Wallet API
layers" with dashboard UX as remaining future work. This addendum
ships that remaining piece, so M10 is now **complete across all
layers**.

The Phase 4 honest scope notes that still apply (no persistence,
no timing-attack defense, depositor publicly identified at deposit
time, `withdraw_amount` not FS-bound, anonymity sets trivially small
in tests, no DoS hardening) all remain true — none of those are
about the dashboard layer.

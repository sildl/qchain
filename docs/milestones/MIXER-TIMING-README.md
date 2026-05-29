# Mixer timing-attack defense (T13 mitigation)

## What this is

The mixer layer (M10) hides the link between a publicly-known
depositor and their later anonymous use of mixer funds. The
**threat model entry T13** documented a known gap: if a deposit
and its corresponding withdrawal land in the same block (or only a
block or two apart), a chain observer can trivially link the
depositor to the withdrawal, defeating the mixer's purpose.

This pass closes T13. The chain now enforces a **minimum
deposit-to-withdrawal delay** at the protocol level. Withdrawals
that try to anchor too close to their deposit are rejected at
admission AND at chain replay.

## The design choice: anchor-root mechanism

Three approaches were considered:

| Option | Mechanism | Verdict |
|---|---|---|
| A | Withdrawal declares `anchor_block_index`; chain verifies the proof was built against the mixer root AT THAT block, and enforces a minimum age | **Chosen** |
| B | Chain tracks `block_at_which_each_leaf_was_added`; rejects withdrawals consuming leaves added too recently | **Impossible** — would break anonymity (chain would have to know which leaf was consumed) |
| C | Forbid mixer withdrawals in blocks that contain mixer deposits | Partial — catches in-block case but not 2-blocks-apart case |

**Option A is the Tornado Cash / Zcash anchor design.** A withdrawer
chooses a historical mixer root (must be at least DELAY blocks old),
builds the proof against that root, and submits the proof along with
the anchor block index. The chain validates:
1. `anchor_block_index <= current_height - DELAY` (anchor must be old enough)
2. `mwtx.mixer_root == mixer_root_history[anchor_block_index]` (root matches recorded history)
3. The STARK proof verifies against `mwtx.mixer_root` (unchanged from before)

Option B is impossible because the withdrawal proof doesn't reveal
which leaf was consumed — that's the privacy property. The chain
can't enforce "consumed leaf is old enough" because it doesn't know
WHICH leaf was consumed.

Option C is strictly weaker than A. Adopting A subsumes it.

## DELAY = 5 blocks

The constant `MIXER_WITHDRAWAL_DELAY` is set to 5. Reference points:

- **Tornado Cash**: no explicit protocol delay; relied on
  time-since-deposit being long anyway in practice
- **Zcash**: ~100 blocks (`min_confirmations`) for spends from
  shielded notes (~25 minutes at 15s block time)

For QChain's PoW research demo (blocks mined on demand in seconds),
5 blocks is meaningful without grinding tests/demos to a halt. A
real deployment would tune this against the actual block cadence
and the desired anonymity-set growth window. The constant is
defined in `chain/mixer_tx.py` for easy per-deployment override.

## Implementation

### Protocol changes

**`chain/mixer_tx.py`:**

- New module constant `MIXER_WITHDRAWAL_DELAY: int = 5`
- `MixerWithdrawTransaction` gains `anchor_block_index: int = 0` field
- `txid()` includes anchor_block_index in the digest (so tampering
  with it changes the txid, preventing replay confusion)
- `to_dict()` / `from_dict()` serialize the new field; legacy
  payloads missing it default to 0 (will fail is_valid on real
  pre-timing chains with mixer activity — see migration notes)
- `verify()` signature renamed `current_mixer_root` → `anchored_mixer_root`;
  semantics: caller passes the historical root looked up by anchor index
- Error message changes: "stale mixer root" → "stale or wrong-anchor mixer root"
- `create_mixer_withdraw_tx` accepts new `anchor_block_index: int = 0` parameter
  and the caller MUST pass a `mixer_tree` reflecting that historical state
  (not the current tree)

**`chain/blockchain.py`:**

- `Blockchain.__init__` adds two parallel-indexed lists:
  - `mixer_root_history: List[Digest]` — root snapshot per block
  - `mixer_leaf_count_history: List[int]` — leaf count per block
  - Index 0 = genesis = empty-tree root and 0 leaves
- New `_apply_block_state(block)` helper used by mine_pending,
  propose_pending, _rebuild_derived_state_from_blocks, and the
  network node's block-receive paths. The snapshot timing
  (after deposits, before withdrawals) is canonical and single-sourced.
- `submit_mixer_withdraw()` rewritten with 4-step validation:
  1. anchor in-range and non-negative
  2. anchor age >= DELAY
  3. `mwtx.mixer_root` matches `mixer_root_history[anchor_block_index]`
  4. proof verifies against the anchored root + nullifier not seen
- `is_valid()` mirrors all four checks during chain replay,
  rebuilding a parallel `replay_mixer_root_history` as it goes
- New helpers:
  - `latest_valid_mixer_anchor()` returns `height - DELAY` (or -1
    if chain too young)
  - `historical_mixer_tree_for_block(block_index)` reconstructs the
    mixer tree at that historical block (cheap with M8.9 sparse
    storage)
- `PERSISTENCE_VERSION` bumped 1 → 2

**`chain/wallet.py`:**

- `create_mixer_withdrawal(chain, mixer_note)` rewritten to:
  - Call `chain.latest_valid_mixer_anchor()` to find the oldest
    valid anchor
  - Reconstruct the historical tree via
    `chain.historical_mixer_tree_for_block(anchor_idx)`
  - Find the note in THAT tree (not the current tree)
  - Pass `anchor_block_index=anchor_idx` to `create_mixer_withdraw_tx`
  - Raise with a clear message if the chain is too young or the
    note was deposited too recently to be anchorable

**`network/node.py`:**

- Both block-receive paths (direct extension, fork resolution)
  now call `chain._apply_block_state(b)` instead of duplicating
  the apply order. Closes a long-standing tech debt from the
  persistence pass.

**`dashboard/server.py`:**

- `/api/mixer/withdraw` rewritten to compute the latest valid
  anchor, build against the historical tree, pass through the
  anchor index. New 400 error messages explain the timing-defense
  gate clearly when the chain is too young or the deposit is too
  recent.

### Refactor bonus: `_apply_block_state`

Before this pass, the canonical "apply a block's state changes in
order" code was duplicated in **5 places**:
- `mine_pending`
- `propose_pending`
- `_rebuild_derived_state_from_blocks`
- `network/node.py` Case 1 (direct extension)
- `network/node.py` Case 2 (fork candidate replay)

Drift between these copies was a long-flagged risk. Adding the
mixer_root_history snapshot in the right place — after deposits,
before withdrawals — meant doing it 5 times. Instead I factored
`_apply_block_state(block)` on the Blockchain and called it from
all 5 sites. **The 5-copies tech debt is closed.**

This is a strictly positive side effect of the timing work.

## Migration

`PERSISTENCE_VERSION` bumped to 2. Save files written by this code
have version=2. Loading semantics:

| File version | Mixer activity? | Load behavior |
|---|---|---|
| 1 (legacy, no version field) | none | Loads fine; mixer_root_history rebuilt from empty start |
| 1 | has mixer withdrawals | `anchor_block_index` defaults to 0; is_valid() will fail because mixer_root_history[0] is empty-tree root but the legacy withdrawal's mixer_root won't match |
| 2 | any | Loads correctly |

Pre-timing chains containing mixer withdrawals are **not formally
migrated**. The audit-followup pass shipped version=1 to start
treating "version field" as part of the file schema; this pass
ships version=2 because the schema changed (new field on
withdrawal records). For the research demo with no live v=1+mixer
saves to preserve, this is acceptable.

## Performance impact

| Op | Before | After | Delta |
|---|---|---|---|
| `submit_mixer_withdraw` | proof verify + nullifier check | + 1 list lookup + 1 digest compare + 2 int compares | negligible |
| `is_valid()` per mixer-withdraw | proof verify + nullifier check | same + 1 list lookup + 3 int compares | negligible |
| chain memory | trees + nullifiers | + 1 digest per block (~32 B/block) + 1 int per block (~8 B/block) | ~40 B per block |
| `historical_mixer_tree_for_block` | n/a | O(N) where N = leaves in mixer pool at that block | only used on withdrawal construction, cheap with sparse storage |
| **proof size** | ~98 KB | ~98 KB | **unchanged** |
| **deposit→withdraw latency** | 1 block | DELAY+1 blocks | usability cost |

The most user-visible cost is **deposit→withdraw latency growing
from "next block" to "DELAY+1 blocks"**. This is the price of
defense; no way around it short of changing the design.

Memory growth (~40 B/block) is trivial for a research chain. At
6 blocks/minute that's ~3.5 KB/hour, ~85 KB/day, ~30 MB/year.

## Test results

### New tests (8): `test_mixer_timing.py`

Defense-specific tests, mostly using sham proofs to exercise
chain-layer admission checks in isolation (~30s faster per test
than real STARKs):

1. `test_timing_anchor_at_current_height_rejected` — age 0 case
2. `test_timing_anchor_one_block_behind_rejected` — age 1 case
3. `test_timing_anchor_at_exactly_delay_boundary_passes_age_check` —
   inclusive boundary (>= DELAY)
4. `test_timing_anchor_root_tampered_rejected` — anchor-match check
5. `test_timing_anchor_in_the_future_rejected` — defensive
6. `test_timing_anchor_negative_rejected` — defensive
7. `test_timing_honest_withdrawal_at_oldest_valid_anchor_succeeds` —
   real STARK control test at the AT-LIMIT honest case
8. `test_timing_forged_too_recent_anchor_in_block_caught_by_is_valid` —
   replay enforcement (M8.10 pattern)

### T13 regression test converted

`test_audit_followup.py::test_t13_demonstrates_same_block_deposit_withdraw_linkage`
is **renamed and rewritten**:
- Old: `test_t13_demonstrates_same_block_deposit_withdraw_linkage`,
  asserted "chain accepts the same-block deposit+withdraw pattern
  (known gap)"
- New: `test_t13_timing_attack_defense_rejects_recent_anchor`,
  asserts `submit_mixer_withdraw` raises "anchor too recent" plus
  validates the honest post-DELAY path

This is the desired regression signal: the test that previously
documented the gap now documents the defense.

### Existing tests updated (9 files)

All existing tests that did deposit+withdraw without waiting now
mine DELAY blocks between deposit and withdrawal. Some tests had
their error-message assertions updated where the new chain-layer
path surfaces a different message (e.g., "stale mixer root" →
"mixer_root doesn't match"). Files updated:
- `test_mixer.py`
- `test_wallet_mixer.py`
- `test_mixer_soundness.py`
- `test_persistence.py`
- `test_hardening_withdraw_amount.py`
- `test_audit_followup.py`
- `test_dashboard_mixer.py`
- `test_ui_mixer_denomination_display.py`
- `test_network.py`

### Tally

| Layer | Pre-timing | Post-timing |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 191 | **199** (+8 from test_mixer_timing.py) |
| **Total** | **322** | **330** |

All green at depth 20.

## Honest scope notes

- **The defense raises the anonymity-set floor, not the ceiling.**
  A 5-block delay only helps if other deposits at the same
  denomination actually land in that window. In a deserted chain
  with one user, the attacker still has a 1-element anonymity set,
  just 5 blocks later. The defense matters at adoption scale, not
  at toy scale. This is the same caveat that applies to every
  privacy mixer — the ceiling without users is meaningless.

- **DELAY=5 is a research-demo choice.** Production would pick
  based on block cadence × desired attacker-correlation window.
  Zcash uses ~100 blocks for related operations. A serious mixer
  deployment on QChain at production rates would likely want
  100+ blocks.

- **No fee escalation at the protocol level.** Some real privacy
  systems use a relay-fee mechanism where withdrawing right at the
  boundary costs more than waiting longer (incentivizing spreading
  withdrawals across the anchor space). Not implemented.

- **`anchor_block_index` in the txid is correct but interacts
  poorly with rebroadcasting.** If two nodes try to construct
  withdrawals for the same note at different anchor blocks, they
  produce different txids. This isn't a soundness issue — only one
  can succeed (the nullifier check stops the other) — but a
  more thoughtful design might canonicalize anchor selection.

- **Migration from v1 saves with mixer activity isn't supported.**
  Honestly noted in the version-bump comment. For a research
  project this is fine; for production it'd require a real
  one-time migration tool.

- **`_apply_block_state` refactor was a bonus but it's load-bearing
  now.** All 5 prior copies are gone. Bug in this helper would
  affect mine, propose, load, and network sync simultaneously.
  This is the right factoring but it's now a single point of
  failure for tx-apply ordering.

## What this gives the threat model

The threat-model document's T13 entry can be updated from:

> **T13: Mixer same-block linkability** — same-block deposit+withdrawal
> trivially links. NOT DEFENDED.

To:

> **T13: Mixer same-block linkability** — DEFENDED. The chain rejects
> withdrawals whose anchor is younger than MIXER_WITHDRAWAL_DELAY (5)
> blocks. Anonymity is bounded by the deposits that land in that
> window, so the defense's effectiveness scales with adoption.

This is the defense closing — the threat-model entry stops being
a known gap and becomes a documented, tested mechanism.

## What's next

After this pass, the remaining items from the post-audit-followup
tier analysis are:

- **External audit.** Still the single highest-value next step.
  Most internal "known gaps" are now closed; an external auditor
  would focus on subtler issues (constraint composition
  off-by-ones, side channels in the prover, malleability across
  proof boundaries).
- **M11 multi-asset support.** Speculative scope expansion.
- **Recursive STARKs / SNARK-of-STARK.** Performance improvement
  for chain-of-spends scenarios.

Most Tier-1 work is done. The chain has working privacy
mechanisms (M4 anon, M8 STARK pool, M10 mixer), real soundness
work (M8.6 Gap B, M8.11 partial-spend, M10 Phase 2 mixer
adversarials), real verification (M8.10 chain-replay validation,
M10 Phase 3 network propagation), real persistence (PERSISTENCE
pass), real hardening (HARDENING-WITHDRAW-AMOUNT, AUDIT-FOLLOWUP),
real scale (M8.9 depth 20 sparse Merkle), and now real timing-
attack defense (this pass).

What remains is genuinely external audit territory.

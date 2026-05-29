# WALLET-NOTE-LIFECYCLE-README

Implementation of ROADMAP item 1.6. Adds `Wallet.reconcile_with_chain()`,
`Wallet.reconcile_summary()`, and `Wallet.prune_pending_notes()` —
read-only and destructive helpers for inspecting and cleaning up
the wallet's owned-note bookkeeping against the actual chain state.

## Discovery: 1.6's original problem statement was stale

The original ROADMAP item 1.6 quoted the wallet module's docstring:

> Honest scope: notes are stored in-memory only and not persisted
> by `save()` for now. A wallet restart loses the spender's
> knowledge of their shielded notes — they'd have to scan the
> chain to recover.

**That docstring was wrong.** Note persistence shipped in the
earlier persistence pass (see `PERSISTENCE-README.md`); `save()`
has serialized `mixer_notes` and `stark_notes` as `(sk, randomness,
value)` triples for a while, and `test_persistence.py` has been
covering that roundtrip the whole time.

The roadmap text was sloppy — it quoted the stale docstring as a
problem statement without checking the actual on-disk state. The
real underlying issue was different: even with persistence, the
wallet has no way to tell whether the notes it thinks it owns are
actually on-chain. A note added by `create_mixer_deposit()` is in
the wallet immediately, before the deposit is gossiped or mined.
If the deposit never lands (network drop, fork resolution,
mempool eviction), the wallet carries a "dead" note forever.

This pass addresses that real gap by adding reconciliation
helpers. The stale docstring is also fixed.

## What's added

### `Wallet.reconcile_with_chain(chain) -> WalletReconciliation`

Read-only classifier. For each note in `mixer_notes` and
`stark_notes`, looks up the note's leaf in the relevant tree
(`mixer_tree` or `stark_anon_tree`) and classifies as confirmed
(leaf present, leaf_idx ≥ 0) or pending (leaf absent, leaf_idx
None).

Returns a `WalletReconciliation` dataclass:

```python
@dataclass
class WalletReconciliation:
    confirmed: List[ReconciledNote]   # leaf is in the tree
    pending:   List[ReconciledNote]   # leaf not (yet?) in the tree

@dataclass(frozen=True)
class ReconciledNote:
    note: STARKNote
    pool: str          # "mixer" | "stark"
    leaf_idx: Optional[int]  # None if pending
```

Does NOT mutate wallet state. Callers decide what to do with the
report (drop pending, log warnings, display in UI, etc.).

### `Wallet.reconcile_summary(chain) -> str`

One-line human-readable view for logging and dashboard display:

```
"3 confirmed (2 mixer, 1 stark), 1 pending (1 mixer, 0 stark)"
```

### `Wallet.prune_pending_notes(chain) -> int`

Destructive cleanup: removes from `mixer_notes` and `stark_notes`
any note whose leaf is not in the relevant tree. Returns the
number of notes removed.

This is the canonical "I just loaded my wallet after a long
absence; drop notes for failed-to-mine deposits" workflow. It is
opt-in (not called automatically) because it would also drop
notes still pending in mempool. Callers should wait long enough
that mempool-pending notes have settled, then prune.

Use `reconcile_with_chain()` first if you want to inspect before
pruning.

## Honest scope — what these helpers DO NOT catch

- **Spent notes whose leaf is still in the tree.** Reconciliation
  only checks PRESENCE of the note's leaf in the tree. A fully-
  spent note (whose nullifier has been published) will still show
  as "confirmed" if its leaf hasn't been removed from the tree
  (which never happens in append-only Merkle pools). Adding a
  nullifier-spent-check would require iterating the chain's
  `nullifiers` set per note; deferred as a follow-up.

- **Notes pending in mempool vs. notes genuinely lost.** Both
  appear identically as "pending" — the wallet doesn't have
  visibility into the chain's mempool from the reconciliation
  path. A caller who wants to distinguish these would need to
  separately consult `chain.mixer_deposit_mempool` and similar.

- **Chain rescan from genesis for note recovery.** If the wallet's
  internal state has been totally lost (e.g., the file was deleted
  and only the chain remains), there is no way to recover notes
  from the chain alone — by design, the chain only contains the
  leaf commitments, not the `(sk, randomness, value)` witnesses
  needed to spend. Full recovery would require an off-chain note
  backup mechanism. Out of scope.

- **Notes addressed to this wallet that other parties created.**
  The wallet only tracks notes IT created (via `create_mixer_
  deposit` or as withdrawal outputs). If a third party sends a
  STARK-pool note to this wallet's address, the wallet has no
  way to discover that without out-of-band note delivery. The
  shielded protocols here don't include an addressing layer.

- **Notes confirmed on a side fork that was later replaced.**
  Reconciliation runs against the chain's current head. If the
  chain reorganizes, a note that was "confirmed" before the reorg
  may become "pending" after. Reconciliation reflects current
  state; it doesn't recompute history.

## What's NOT in this pass

- No changes to the wallet persistence format. The optional new
  helpers are pure-functional over existing state.
- No changes to `STARKNote` itself. Notes remain `(sk, randomness,
  value)` triples; no status field added to the note (status is
  computed from the chain, not stored on the note).
- No changes to the dashboard's parallel `dash.owned_stark_notes`
  tracking. That's UI-pending-state and serves a different concern.
- No automatic prune on `load()` — that would silently delete
  notes for users who don't expect it. Always opt-in.

## Backward compatibility

- Existing wallet files load unchanged. All 267 pre-1.6 tests
  pass without modification.
- The `STARKNote` dataclass shape is unchanged.
- The wallet's public API gains three methods but nothing existing
  changes.
- Combines cleanly with 1.4 (encryption-at-rest): a wallet saved
  encrypted reloads encrypted, then reconciliation works the same
  way. Tested in `test_reconcile_after_encrypted_save_and_load`.

## Tests

`test_wallet_note_lifecycle.py` — 15 tests:

| # | Test | What it verifies |
|---|---|---|
| 1 | `reconcile_empty_wallet_returns_empty_report` | Trivial case |
| 2 | `reconcile_summary_format` | Summary string shape |
| 3 | `reconcile_classifies_in_memory_only_notes_as_pending` | In-memory notes → pending, leaf_idx None |
| 4 | `reconcile_does_not_mutate_wallet_state` | Read-only property |
| 5 | `reconcile_classifies_confirmed_mixer_note` | Deposit + mine → confirmed with leaf_idx |
| 6 | `reconcile_handles_mixed_pending_and_confirmed` | Both states coexist |
| 7 | `reconcile_classifies_confirmed_stark_note` | Full mixer → withdraw → STARK-pool flow |
| 8 | `prune_pending_notes_removes_only_pending` | Confirmed survives, pending removed |
| 9 | `prune_returns_correct_count` | Return value matches removals |
| 10 | `prune_empty_wallet_returns_zero` | Edge case |
| 11 | `prune_preserves_wallet_keypair` | Pruning doesn't touch the keypair |
| 12 | `reconcile_after_save_and_load_legacy_format` | Works post-roundtrip (plaintext) |
| 13 | `reconcile_after_encrypted_save_and_load` | Works post-roundtrip (1.4 encryption) |
| 14 | `reconciled_note_is_frozen` | ReconciledNote is immutable |
| 15 | `wallet_reconciliation_default_empty` | Default constructor sanity |

Runtime: ~3 seconds total. The slowest test is
`test_reconcile_classifies_confirmed_stark_note` which exercises
the full mixer-deposit → withdrawal-anchor → withdrawal flow
including STARK proof construction.

## Test results

| Layer | Pre-1.6 | Post-1.6 |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 267 | **282** (+15 lifecycle tests) |
| **Total** | **398** | **413** |

All green.

## What changed in the repo

| File | Change |
|---|---|
| `qchain/chain/wallet.py` | Stale docstring fixed; added `ReconciledNote`, `WalletReconciliation` dataclasses; added `reconcile_with_chain`, `reconcile_summary`, `prune_pending_notes` methods (~100 lines) |
| `qchain/tests/test_wallet_note_lifecycle.py` | New file, 15 tests |
| `qchain/ROADMAP.md` | 1.6 marked shipped with explanation of stale problem-statement |
| `qchain/README.md` | Test totals updated; capability bullet added |
| `qchain/DOCS.md` | New entry #34 + Operational section |
| `qchain/WALLET-NOTE-LIFECYCLE-README.md` | This document |

No changes to:
- The on-disk wallet persistence format
- `STARKNote` itself
- The chain protocol, network layer, dashboard
- Existing public API surface (only additions)

## What this gives the project

- Closes the SPIRIT of ROADMAP 1.6: real note-lifecycle robustness,
  not just the literal "add persistence" that was already done
- Surfaces a self-disclosed instance of stale documentation in the
  project, fixed in this pass
- Provides a clear primitive for any future UI/dashboard work
  that wants to display "pending vs. confirmed" note state
- Establishes a pattern (`reconcile_*`, `prune_*`) that could
  extend to other wallet-vs-chain lifecycle questions (e.g.,
  M4 anon notes once they're added to wallet bookkeeping)

## What's next

ROADMAP status after this pass:

| Item | Status |
|------|--------|
| 1.1 External audit engagement | Recommended; requires budget |
| 1.2 Differential AIR Phase 3 | Open |
| 1.3 Publication writeup | Open |
| 1.4 Wallet key encryption at rest | ✅ Shipped |
| 1.5 Rate limiting / DoS hardening | ✅ Shipped |
| 1.6 Persistent wallet shielded-note tracking | ✅ Shipped (this pass) |

The "1.x next-up" items are now all done. Remaining work splits
into three categories:

- **External validation (1.1, 1.3)**: highest leverage. The
  project is materially more audit-ready than when the
  audit-readiness arc began; further internal work has
  diminishing returns vs. external eyes.
- **Theoretical depth (1.2)**: differential AIR phase 3 would
  cross-reference STARK constants against a third implementation.
  Single-session-scope, low expected ROI (constants are
  widely-used; the test would likely pass cleanly).
- **Follow-ups surfaced by this pass**:
  - Add nullifier-spent-check to reconciliation
  - Track per-note metadata (deposit block index, anchor) so
    reconciliation can be cheaper than O(notes × tree)
  - Off-chain note backup mechanism for recovery from total
    wallet loss

These follow-ups are all small-to-medium scope and could be
batched into a single "wallet UX polish" pass if there's
appetite to continue.

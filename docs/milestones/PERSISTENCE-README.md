# Persistence — chain derived state + wallet shielded notes

## The bug this fixes

Before this pass, `Blockchain.save()` and `Wallet.save()` existed but
were both incomplete:

- **`Blockchain.load()`** deserialized the block history from disk but
  did NOT rebuild any of the derived in-memory state: `anon_tree`,
  `stark_anon_tree`, `mixer_tree`, `nullifiers`, `stark_nullifiers`,
  `mixer_nullifiers`. All started empty after load. The chain
  *looked* valid (block count, hash chain, `is_valid()` all OK
  because `is_valid()` does its own replay), but it was unusable —
  any STARK spend would fail "stale root" because the loaded
  `stark_anon_tree`'s root was the empty-tree root, not what the
  on-chain shields had built up.

- **`Wallet.save()`** persisted only the Dilithium keypair, dropping
  the `mixer_notes` and `stark_notes` lists that Phase 4's wallet
  bookkeeping introduced. A user running the dashboard, mining some
  blocks, depositing into the mixer, and restarting would lose all
  view of their owned shielded notes.

This is the kind of bug that doesn't show up in unit tests because
nothing was testing the round-trip. The honest catch was running a
manual smoke and seeing `stark_pool_size = 0` after load.

## The fix

### `Blockchain._rebuild_derived_state_from_blocks()`

A new method that replays every block's transactions in the same
order `mine_pending` applies them:

1. anon-tx outputs and nullifiers (M4 pool)
2. mixer deposits (mixer pool grows)
3. shield txs (STARK pool grows)
4. mixer withdrawals (mixer nullifier marked, STARK pool grows via
   output_leaf)
5. STARK-anon spends (STARK nullifier marked, STARK pool grows via
   output_leaf)

`load()` calls this immediately after deserializing blocks. It does
NOT re-verify proofs or signatures — that's `is_valid()`'s job. Just
deterministic state rebuild.

This duplicates the apply ordering that already exists in
`mine_pending`, `propose_pending`, `is_valid()`, and the node's
`_try_extend_or_replace`. Four copies of the same ordering is real
tech debt — a future refactor could share a single
`_apply_block_state_for_replay(block)` method across all five sites.
NOT in scope for this pass; minimizing risk by adding the fifth copy
rather than touching the existing four.

### `Wallet` shielded-note serialization

`save()` now writes `mixer_notes` and `stark_notes` as JSON arrays
of `[sk, randomness, value]` triples. `load()` deserializes them
into `STARKNote` objects.

Migration-friendly: old wallet files lacking these keys still load
correctly, with empty note lists. No broken old files.

The keypair persistence remains unchanged (still base64-encoded
public/secret key pair).

## 8 new tests in `qchain/tests/test_persistence.py`

| # | Test | What it proves |
|---|------|----------------|
| 1 | `test_persistence_empty_chain_roundtrips` | A bare chain (just genesis) saves and loads with all derived state empty |
| 2 | `test_persistence_stark_pool_rebuilt_after_load` | After a shield, save+load preserves stark_anon_tree root and the actual shielded leaf |
| 3 | `test_persistence_mixer_state_rebuilt_after_load` | Both mixer deposit AND withdrawal: mixer_tree, mixer_nullifiers, and the resulting STARK pool credit all rebuild correctly |
| 4 | `test_persistence_loaded_chain_can_be_extended` | The acid test: load a chain, mine more blocks on it, is_valid() still passes. Catches state-mismatch bugs that pure root checks miss |
| 5 | `test_persistence_wallet_keypair_roundtrips` | Regression check: existing keypair save/load still works |
| 6 | `test_persistence_wallet_shielded_notes_roundtrip` | mixer_notes and stark_notes survive save+load with structural equality |
| 7 | `test_persistence_wallet_old_format_loads_with_empty_notes` | Migration-friendliness: pre-fix wallet files still load |
| 8 | `test_persistence_end_to_end_restart_then_spend` | Headline integration test: deposit → save both → simulate restart → withdraw using the loaded state. Proves the full restart workflow works |

All pass on first run.

## Test totals

| Layer | Pre-persistence | Post-persistence |
|-------|----------------:|-----------------:|
| qstark Rust | 110 | 110 (no change) |
| qstark_py Python | 21 | 21 (no change) |
| QChain Python | 160 | **168** (+8) |
| **Total** | **291** | **299** |

Zero regressions. All 160 existing tests still pass — including the
ones that exercise the same code paths from a different angle (e.g.,
`is_valid()` chain replay, which is structurally similar to the new
rebuild but used for verification rather than load).

## What this changes about the project

The project went from "runnable demo for one session" to "runnable
testnet that survives restarts." That's a real status change. You
can now:

- Mine some blocks, deposit into the mixer, save the chain and wallet
- Stop the process, come back later, restart it
- Withdraw from the mixer using the wallet's tracked notes against
  the reloaded chain's mixer pool

End-to-end works through the actual Wallet API, not just by manually
reconstructing state.

## What this does NOT do (honest scope)

- **No atomic save.** `save()` writes the entire chain in one
  `Path.write_text(json.dumps(...))` call. For a 1000-block chain
  that could be megabytes; mid-write crashes leave a corrupt file.
  A production design would write to a temp file and atomically
  rename. Not in scope here.
- **No incremental save.** Every save serializes the whole chain.
  A real validator appends incrementally to avoid serialization
  bottleneck. Not in scope here.
- **No save during operation.** Tests save once and load once. The
  dashboard doesn't auto-save on every block (that would need a
  policy decision about when to save and what to do if save fails).
  Future work.
- **No encryption.** Wallet secret keys are stored base64-encoded
  in plaintext. The README already noted "in a real system the
  secret key would be encrypted with a passphrase." Still true.
  Not in scope here.
- **Mempool is not persisted.** Pending txs that haven't been mined
  are dropped on save. This matches how real validators behave
  (mempool is volatile by design), but worth being explicit about.
- **No save/load API for the dashboard.** A user clicking around
  the dashboard can't trigger a save; the only way to persist is
  via Python API. Future work.

## Why this was the right next step

The previous turn's analysis suggested "persistence (chain + wallet)"
as the highest-value cheap fix. The reasoning held up:

- The bug was real (loaded chain had empty derived state)
- The bug was hidden (is_valid() passed despite the chain being
  unusable)
- The fix was bounded (~60 lines of code split across two files)
- The fix unlocked a meaningful capability change (restart-survival)
- No new cryptography, no protocol surface, no API breaking changes

Tier-1 work that lifts a real limitation, ships in one session, leaves
the codebase strictly better. Honest assessment: this is the kind of
work that should happen more often vs. the bias toward new features.

## Next steps from here

Per the prior turn's analysis, the remaining Tier-1 items are:
- Threat model document + audit pass against existing soundness tests
- Bind `withdraw_amount` to the mixer proof (soundness hardening)

Both are smaller-scope follow-ons. Or Tier-2 work:
- M8.9 (sparse Merkle tree for depth 20+) — real cryptographic
  milestone, lifts the 65,536-note anonymity-set cap

The persistence pass doesn't change which of these is "next" — they
were all real options before and remain so.

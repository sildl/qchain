# Milestone 10 Phase 1 — Mixer layer chain integration

## What M10 is for

The M8.7-D `ShieldTransaction` publicly reveals the depositor's
address. Chain analysis correlates "address X shielded 100 coins at
time T" with any later STARK spend of 100 coins from that point on.
The shield itself is the linkage point.

The mixer layer breaks this link with one indirection. Users:

1. **Deposit** transparent coins into a separate "mixer pool" via a
   `MixerDepositTransaction`. The depositor's identity is still public
   at deposit time (this milestone doesn't claim to hide that).
2. **Wait** — time decoupling between deposit and withdrawal is part
   of what creates the anonymity set.
3. **Withdraw** via a `MixerWithdrawTransaction`. The withdrawal is a
   STARK proof of "I know the preimage to *some* leaf in the mixer
   pool" without revealing which one. The withdrawal credits a new
   leaf into the STARK pool, where it's spendable anonymously via
   M8.5/M8.11 mechanics.

The anonymity set is the population of un-withdrawn deposits of the
**same denomination**. Fixed denominations (1, 10, 100, 1000) are
enforced chain-side — otherwise the set is partitioned by amount and
the privacy guarantee collapses.

## Why M10 reuses m86_air — no new cryptography

The original roadmap estimated M10 at ~6 weeks because it imagined a
brand-new AIR for the mixer withdrawal proof. The realization driving
this implementation is simpler: **m86_air already proves exactly the
membership + nullifier + value-conservation statement a mixer
withdrawal needs.** The same AIR works for both the STARK-anon spend
flow and the mixer withdrawal flow — what differs is which Merkle
tree the proof attests against and what the chain does with the
output_leaf.

Specifically, the M10 mapping onto m86_air's parameters is:

| m86_air parameter | Mixer withdrawal mapping |
|-------------------|-------------------------|
| Merkle root | mixer pool root |
| `v_in` (note value) | deposit denomination |
| `unshield_amount` | 0 (no transparent payout) |
| `fee` | 0 |
| `v_out` | denomination (everything flows into the new STARK leaf) |
| `output_leaf` | the new STARK pool leaf hash |
| `nullifier` | mixer-pool nullifier |

The AIR's value-conservation constraint `v_in = unshield + fee +
v_out` becomes `denom = 0 + 0 + denom` ✓. No new cryptography
required. The novelty is the **orchestration**: a parallel Merkle
tree, fixed-denomination enforcement at admission, and the
withdrawal-credits-the-STARK-pool flow.

This collapses M10's effort from "weeks" to "afternoon."

## Phase 1 scope

| Phase | Scope | Status |
|-------|-------|--------|
| **1** | **Chain integration + 6 happy/adversarial tests** | **DONE** |
| 2     | Soundness adversarials (mixer-specific attack classes) | not started |
| 3     | Network propagation + adversarial tests | not started |
| 4     | Dashboard UX + wallet bookkeeping | not started |

## What Phase 1 delivered

### New file: `qchain/chain/mixer_tx.py`

Two transaction classes mirroring the existing `ShieldTransaction` and
`STARKAnonTransaction` patterns:

- **`MixerDepositTransaction`** — Dilithium-signed, sender publicly
  identified. Same signing flow as ShieldTransaction (`sender =
  keypair.address()`, base64-encoded `public_key` and `signature`).
  Validates: signature, amount > 0, amount in `MIXER_DENOMINATIONS`,
  leaf well-formed (4 u64 elements).

- **`MixerWithdrawTransaction`** — anonymous STARK proof. Public
  inputs: `mixer_root`, `nullifier`, `output_leaf`. Plus an admin-side
  `withdraw_amount` field that carries the denomination for
  classification (NOT bound to the proof; see "Honest scope" below).

Helpers:

- `create_mixer_deposit_tx(wallet, denomination, note)` — validates the
  denomination, generates a signed deposit.
- `create_mixer_withdraw_tx(note, leaf_idx, mixer_tree, output_note)` —
  validates value conservation (denomination of note == value of
  output_note), generates the m86_air proof, returns a ready
  withdrawal.

### Blockchain extensions (`qchain/chain/blockchain.py`)

State:
- `mixer_deposit_mempool: List[MixerDepositTransaction]`
- `mixer_withdraw_mempool: List[MixerWithdrawTransaction]`
- `mixer_tree: STARKAnonTree` (separate instance from the STARK pool)
- `mixer_nullifiers: Set[Digest]`

Methods:
- `submit_mixer_deposit(mdtx)` — validates signature, denomination,
  balance (accounting for pending mempool debits), no-duplicate.
- `submit_mixer_withdraw(mwtx)` — runs `mwtx.verify()` against current
  mixer state and rejects with the same ValueError contract as
  `submit_stark_anon`.
- `_apply_mixer_deposit_tx(mdtx)` — appends leaf to mixer_tree.
- `_apply_mixer_withdraw_tx(mwtx)` — marks nullifier, appends
  output_leaf to **stark_anon_tree** (the link from mixer → STARK
  pool).

`mine_pending` and `propose_pending` updated:
- Block includes new `mixer_deposit_transactions` and
  `mixer_withdraw_transactions` fields
- State application order: anon → **mixer deposits** → shields →
  **mixer withdrawals** → STARK spends
- Mempools cleared on block production

`balance_of` debits mixer deposits from the depositor's address.
Mixer withdrawals don't credit any transparent address (value goes
into STARK pool).

`is_valid()` replay extended:
- Parallel `replay_mixer_tree` and `replay_mixer_nullifiers`
- Validates mixer deposit signatures + denominations
- Validates mixer withdrawal STARK proofs against pre-block mixer state
- Applies state changes in the same order as mine_pending

### Block extensions (`qchain/chain/block.py`)

- Dataclass gains `mixer_deposit_transactions`,
  `mixer_withdraw_transactions` fields
- `_header_payload` includes new tx-root hashes (only-if-present
  pattern preserves pre-M10 block hashes)
- `to_dict`/`from_dict` round-trip the new fields

### Tests: `qchain/tests/test_mixer.py` (6 tests, all green)

| Test | Property proven |
|------|-----------------|
| `test_m10_honest_deposit_appears_in_mixer_tree` | Signed deposit at allowed denomination lands in mixer_tree; depositor debited; chain validates |
| `test_m10_honest_withdrawal_credits_stark_pool_and_validates` | Withdrawal marks nullifier + appends output_leaf to STARK pool; is_valid() passes |
| `test_m10_tampered_output_leaf_rejected_at_submission` | Post-construction output_leaf tampering caught by FS cross-check |
| `test_m10_double_withdraw_rejected_by_mixer_nullifier_set` | Same input note can't be withdrawn twice — mixer nullifier set blocks |
| `test_m10_mismatched_mixer_root_rejected` | Stale-root proof rejected when mixer pool moves on |
| `test_m10_wrong_denomination_at_submit_rejected` | Disallowed denominations rejected both at create_helper and at submit |

## Test totals

| Layer | M8.11 Phase 4 | M10 Phase 1 |
|-------|--------------:|------------:|
| qstark Rust | 110 | 110 (unchanged — no AIR changes) |
| qstark_py Python | 21 | 21 (unchanged) |
| QChain Python | 129 | **135** (+6 new mixer tests) |
| **Total** | **260** | **266** |

All passing. Zero regressions across the M8.11 Phase 4 baseline.

## Honest scope notes — what Phase 1 does NOT do

These are real and matter for any honest assessment of the privacy
guarantee:

- **`withdraw_amount` is admin-side, not FS-bound.** The field
  exists on `MixerWithdrawTransaction` as a classification label
  for the denomination. The AIR is called with `unshield_amount=0`
  matching what the prover used, so tampering `withdraw_amount`
  post-hoc doesn't change the FS transcript and is NOT detected
  via the proof. It also doesn't change what the chain actually
  does (the value flow is determined by `output_leaf`'s preimage
  via the AIR). But it could mislead chain-analysis tools about
  which denomination was withdrawn. Phase 2 should consider
  whether to bind this via additional chain-side checks.

- **No timing-attack defense.** A user can deposit AND withdraw in
  the same block, making linkability trivial via timing analysis.
  Production designs enforce a minimum delay (e.g., "withdrawals
  only valid after N confirmations"). Not implemented.

- **The depositor is still publicly identified at deposit time.**
  The mixer hides the link between deposit and *withdrawal*, not
  the deposit itself. Anonymity comes from the size of the
  un-withdrawn deposit pool, not from hiding deposits.

- **Anonymity set is small in any realistic test.** With 4
  denominations and typical mixer-pool sizes in tests of 1-2
  deposits per denomination, the effective anonymity set is
  trivial. Real privacy requires the pool to have many deposits
  at the same denomination from many users.

- **No mixer-specific soundness adversarials.** Phase 1 has tamper
  rejection only as a smoke test. A full Phase 2 (mirroring M8.11's
  6-test pattern) would prove:
  - Withdrawal can't be replayed against a different mixer tree
  - Withdrawal can't claim a different output denomination than
    the input
  - The mixer ↔ STARK pool boundary doesn't allow value-creation
    attacks across the boundary
  - Withdrawals from the wrong tree (e.g., proving against the
    STARK pool's root and submitting as a mixer withdrawal) are
    rejected

- **No network adversarial coverage.** Mixer txs flow through the
  existing gossip protocol via the block-propagation path, but
  there's no explicit `_handle_new_mixer_deposit` or
  `_handle_new_mixer_withdraw` handler yet. Mempool gossiping of
  these txs is Phase 3 work.

- **No wallet API.** Spenders track their mixer notes and their
  withdrawal output_notes manually. A `Wallet.mixer_notes` and
  `Wallet.pending_withdrawals` API would be the right abstraction.

- **No dashboard UX.** The dashboard doesn't surface deposit or
  withdrawal flows yet.

- **Persistence.** Same in-memory limitation as the rest of the
  project.

## What Phase 1 closes from the roadmap

| Roadmap item | Status |
|--------------|--------|
| M10 — Anonymous deposits via mixer layer | **Phase 1 of 4 done** |

The chain mechanics work. Phases 2-4 cover soundness, network, and UX
respectively. Each phase is its own scoped commitment with a green-tests
stopping criterion.

## Stopping criterion met

- [x] `mixer_tx.py` compiles cleanly (imports resolved)
- [x] All existing QChain tests still pass (129/129 from Phase 4 baseline)
- [x] 6 new mixer tests pass (`test_mixer.py`)
- [x] Full chain replay via `is_valid()` works on chains containing
      mixer deposits + withdrawals
- [x] Honest scope notes documented for everything NOT done

Phase 1 done. Bundle ready.

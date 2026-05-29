# Milestone 10 Phase 3 — Network propagation for mixer transactions

## Summary

Phase 2 proved the AIR-level defenses reach the mixer surface. Phase 3
proves those defenses ALSO reach the network surface — through real
TCP gossip, real wire handlers, real serialization roundtrips. Plus
the network layer now actually transmits mixer deposits and
withdrawals between peers (it didn't before; mixer txs only flowed
inside mined blocks).

**Status: SHIPPED.** 147 QChain tests passing (was 142 at Phase 2,
+5 from Phase 3). Zero regressions.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Chain integration + 6 happy-path tests | done |
| 2 | Soundness adversarials | done |
| **3** | **Network propagation + adversarial tests** | **DONE** |
| 4 | Dashboard UX + wallet bookkeeping | not started |

## What Phase 3 changed

### Wire handlers + dispatch (`qchain/network/node.py`)

Two new message types added:
- `"new_mixer_deposit"` — gossip a signed mixer deposit
- `"new_mixer_withdraw"` — gossip an anonymous withdrawal proof

New methods on `Node`:
- `submit_mixer_deposit_tx(mdtx)` — submit locally + broadcast
- `submit_mixer_withdraw_tx(mwtx)` — submit locally + broadcast
- `_handle_new_mixer_deposit(payload)` — receive handler
- `_handle_new_mixer_withdraw(payload)` — receive handler

Both handlers follow the established pattern (also used by shield and
STARK-anon): deserialize, dedup via seen-set, submit to chain (which
runs full validation), gossip on success. Stale-root or invalid-proof
rejections drop silently — the same behavior as STARK-anon txs.

New callbacks on `Node`:
- `on_mixer_deposit: Optional[Callable[[MixerDepositTransaction], None]]`
- `on_mixer_withdraw: Optional[Callable[[MixerWithdrawTransaction], None]]`

For dashboard integration in Phase 4.

### Block-receive path: `_try_extend_or_replace`

This was the subtle one. Phase 1 added mixer txs to `mine_pending`
state application, but the network's block-receive path
(`_try_extend_or_replace` in `node.py`) has its OWN copy of the
state-application logic — and it didn't know about mixer txs. So a
node receiving a mined block containing mixer transactions would
extend its chain but NOT update its mixer state, causing roots to
diverge across nodes.

Both branches of `_try_extend_or_replace` were updated:

- **Direct extension** (new block extends current head): applies
  mixer deposits before shields, then mixer withdrawals before STARK
  spends. Matches `mine_pending`'s order exactly.
- **Fork resolution** (build candidate chain): rebuilds mixer pool
  and nullifier set from scratch as part of the candidate, then
  copies them into `self.chain` on adoption.

This was caught by `test_m10_phase3_honest_mixer_withdrawal_propagates`
failing initially — n2's mixer tree stayed empty after receiving n1's
block. A clean signal that real cross-node testing matters; chain-
level tests alone can't catch this class of bug.

### Five adversarial tests in `qchain/tests/test_network.py`

| # | Test | What it proves |
|---|------|----------------|
| 1 | `test_m10_phase3_honest_mixer_deposit_propagates` | Signed deposit submitted on n1 lands in n2's mempool via gossip |
| 2 | `test_m10_phase3_honest_mixer_withdrawal_propagates` | Withdrawal proof (with output_leaf) gossips correctly; both nodes share mixer pool after block propagation |
| 3 | `test_m10_phase3_malicious_peer_tampered_output_leaf_rejected` | Tampered output_leaf in flight caught by FS cross-check at honest peer |
| 4 | `test_m10_phase3_malformed_mixer_payload_dropped` | Garbage payloads (missing fields, junk proof) dropped cleanly, no crash |
| 5 | `test_m10_phase3_full_state_converges_across_nodes` | Full flow: deposit + withdrawal + blocks → mixer roots, mixer nullifiers, AND STARK pool roots all converge |

### What test #3 (the headline) demonstrates

Same attack pattern as M8.11 Phase 4 #2, mirrored to mixer:

1. Malicious node M builds an honest mixer withdrawal proof
2. M tampers `output_leaf` post-construction (steering value into a
   different STARK pool leaf they control)
3. M skips its own `submit_mixer_withdraw_tx` (which would catch it)
   and gossips directly to peers

Honest peer P's path:
1. `_handle_new_mixer_withdraw(payload)` receives the gossip
2. `MixerWithdrawTransaction.from_dict(payload)` deserializes
   (tampered output_leaf included)
3. `chain.submit_mixer_withdraw(mwtx)` calls `mwtx.verify()`
4. `verify()` calls `q.verify_m86_membership` with the tampered
   output_leaf as one of five FS-bound public inputs
5. FS challenges mismatch → proof fails to verify
6. ValueError raised → handler catches it silently and drops

Result: tampered withdrawal never enters honest peer's mempool. The
Fiat-Shamir property is doing all the work — `output_leaf` is bound
to the proof exactly as if it were `nullifier` or `merkle_root`.

## Test totals at Phase 3 close

| Layer | M10 Phase 2 | M10 Phase 3 |
|-------|------------:|------------:|
| qstark Rust | 110 | 110 (no AIR/Rust touched) |
| qstark_py Python | 21 | 21 |
| QChain Python | 142 | **147** (+5) |
| **Total** | **273** | **278** |

All green. Zero regressions in 30 existing network tests, 117 other
QChain tests.

## Honest scope notes — still unchanged from earlier phases

These remain real:

- **No timing-attack defense.** Same-block deposit + withdrawal still
  possible. Would need either chain-side delay rule or a minimum-blocks
  constant.
- **Depositor publicly identified at deposit time.** Mixer anonymity is
  between deposit and *withdrawal*, not against observing the deposit.
- **`withdraw_amount` admin-side label.** Not FS-bound. Documented in
  Phase 1/2 READMEs. Chain-analysis tools relying on this label could
  be misled. No value-flow attack enabled.
- **Anonymity sets in tests are trivially small.** Real privacy needs
  many deposits at the same denomination from many users.
- **No DoS hardening for mixer gossip.** A flood of malformed mixer
  withdrawals would still consume CPU on every verify attempt.
  Network-layer rate limiting is Tier 1 production work, same as
  for STARK-anon gossip.
- **No wallet API.** Mixer notes and pending withdrawals tracked
  manually. Phase 4 work.
- **No dashboard UX.** Phase 4 work.
- **No persistence.** Same M1 limitation.

## Stopping criterion met

- [x] Wire handlers for `new_mixer_deposit` and `new_mixer_withdraw`
      added to Node's dispatch table
- [x] `submit_mixer_*_tx` wrappers on Node for local + broadcast
- [x] `_try_extend_or_replace` applies mixer txs in correct order
      on block receive (both direct-extension and fork-resolution paths)
- [x] On-mixer-event callbacks declared for future dashboard hook-in
- [x] 5 adversarial tests cover honest propagation + tampering + malformed
      + full-state-convergence
- [x] All 30 existing network tests still pass (no regressions)
- [x] All 117 other QChain tests still pass
- [x] Total: 147 QChain + 110 qstark + 21 qstark_py = **278 tests passing**

Phase 3 done. Next phase (4) is dashboard UX + wallet bookkeeping —
mostly UI work, no new cryptography.

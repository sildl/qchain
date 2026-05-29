# AUDIT-PACKAGE.md

> **For external auditors.** This document is the entry point. Read it
> in full before opening any other file. It tells you what QChain is,
> what's in scope, what's claimed, where to look, and what we've
> already found ourselves.
>
> If you take one impression away: this is a research project with
> honest scope, not a production system. The cryptographic mechanisms
> are real and tested; the operational concerns (key management,
> deployment, ops) are not. Audit accordingly.

---

## 1. What QChain is

QChain is a research blockchain built to demonstrate four things working
end-to-end:

1. **Post-quantum signatures everywhere** (CRYSTALS-Dilithium replacing ECDSA)
2. **Quantum-randomized consensus seed** (IBM Quantum RNG via `qiskit_ibm_runtime`,
   with a deterministic fallback)
3. **Hand-rolled zk-STARK shielded payments** — Goldilocks-field AIR
   over Winterfell, proving Merkle membership + nullifier binding + value
   conservation in a single STARK
4. **Working network + dashboard** — TCP gossip with fork resolution,
   FastAPI + React UI

It is implemented as three workspaces:

- `qchain/` — Python chain, network, wallet, dashboard
- `qstark/` — Rust zk-STARK core (the AIR, the Merkle tree, native ops)
- `qstark_py/` — PyO3 bridge

The system has been built incrementally across roughly 20 milestone passes,
each with its own README. The most security-critical mechanism is the
**m86_air constraint system** in `qstark/src/hash_air/m86_air.rs`
(~1500 lines); that's where the cryptographic correctness ultimately
sits.

---

## 2. Scope

### In scope for audit

The cryptographic core and chain protocol:

- The `m86_air` AIR (constraint system, public-input bindings, FS transcript)
- The sparse Merkle tree implementation (Rust + Python)
- Nullifier construction and double-spend defense
- The mixer protocol (M10) and its timing-attack defense
- Chain admission checks and `is_valid()` chain replay logic
- Persistence schema and load-time state reconstruction
- Block reward enforcement and PoW puzzle validation
- Network message validation and fork resolution semantics

### Out of scope

Real-world ops concerns we have not engineered for:

- Key management (Dilithium private keys are written to JSON files in cleartext)
- Network deployment, DDoS resistance, NAT traversal
- Sybil resistance beyond basic PoW
- Front-running / MEV in the mempool
- Timing side channels in the prover
- Memory side channels in the verifier
- Browser / dashboard frontend security (XSS, CSRF, CORS posture)
- Quantum-RNG availability / fallback paths under adversarial conditions

### Audit boundary

The boundary the project draws is "cryptographic mechanism correctness + chain
protocol soundness," not "system security." If your audit is paid by someone
preparing to deploy this, **expand the scope** — the operational gaps above are
genuine and known.

---

## 3. Security claims (numbered, falsifiable)

These are the claims the codebase implicitly stakes its correctness on.
Each is testable; the test file pointer shows where we test it.

| # | Claim | Defended by | Tested in |
|---|-------|-------------|-----------|
| C1 | A valid STARK-anon spend requires knowing the preimage of an on-chain leaf | m86_air Merkle constraints | `qstark/tests/m86_soundness.rs` |
| C2 | The nullifier in a spend is bound to the consumed leaf's preimage via Fiat-Shamir | m86_air nullifier-hash block + FS public-input absorption | `qstark/tests/m86_soundness.rs::rejects_swapped_nullifier_completely` |
| C3 | Spending a note twice produces the same nullifier; the chain rejects the second | nullifier-set check + `is_valid` replay | `test_anon_stark.py::test_rejects_double_spend` |
| C4 | Value is conserved across STARK spends: `v_in == unshield_amount + fee + v_out` | m86_air value-conservation constraint | `qstark/tests/m86_partial_spend_soundness.rs` |
| C5 | A STARK proof for one pool cannot be replayed as a proof for another | proof's bound merkle_root differs between pools | `test_mixer_soundness.py::test_m10_phase2_stark_proof_rejected_as_mixer_withdrawal` and the symmetric test |
| C6 | A mixer withdrawal cannot anchor to a mixer root younger than `MIXER_WITHDRAWAL_DELAY` blocks | chain-side anchor age + root match checks | `test_mixer_timing.py` (8 tests) |
| C7 | A malicious miner cannot mint coins beyond the per-block reward | per-block coinbase amount validation in `is_valid` | `test_audit_followup.py` (5 coinbase tests; self-audit found a real bug here) |
| C8 | Persistence load + chain replay yields the same state mine_pending would have built | `_apply_block_state` is the single source of truth for tx-apply order | `test_persistence.py` (8 tests including end-to-end restart) |
| C9 | The denomination of a mixer withdrawal is not revealed on the wire | denomination is hidden in `output_leaf` preimage, only knowable to spender | `test_hardening_withdraw_amount.py` |
| C10 | Block PoW puzzles are enforced by `is_valid` (not just at admission) | inline `meets_difficulty` check in `is_valid` (blockchain.py:658) | `test_audit_followup.py::test_t5_block_without_valid_pow_rejected` |

If any of C1-C10 is FALSE, that's a real finding. If you can write a test
that demonstrates a counterexample, please document it explicitly.

---

## 4. System architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Dashboard (FastAPI + React)              │
│  Drives chain via Node API; serves /api/* + WebSocket events│
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                       Network Node                          │
│  TCP gossip · peer mgmt · fork resolution · block receive   │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                       Blockchain (Python)                   │
│  mempools · trees · nullifiers · mining · is_valid replay   │
└──────┬───────────────┬──────────────┬───────────────┬───────┘
       │               │              │               │
   ┌───┴────┐    ┌─────┴──────┐  ┌───┴─────┐  ┌──────┴────────┐
   │ Anon   │    │ STARK pool │  │ Mixer   │  │ Transparent   │
   │ tree   │    │ + spend    │  │ pool +  │  │ tx + balance  │
   │ (M4)   │    │  via m86   │  │ withdraw│  │  bookkeeping  │
   └────────┘    └──────┬─────┘  └─────┬───┘  └───────────────┘
                        │              │
                  ┌─────┴──────────────┴─────┐
                  │   qstark_py (PyO3)       │
                  └─────────┬────────────────┘
                            │
                  ┌─────────┴────────────────┐
                  │      qstark (Rust)       │
                  │ • m86_air AIR            │
                  │ • Sparse Merkle (depth 20)│
                  │ • Winterfell prover/verifier│
                  └──────────────────────────┘
```

**Privacy systems present:** two distinct shielded payment systems
share the same `m86_air` proof. The **STARK pool** is the main shielded
system; users `Shield` coins in (transparent → shielded), then spend
anonymously via STARK proofs. The **mixer pool** is a separate
anonymity set keyed on fixed denominations; mixer deposits land into
the mixer pool, withdrawals anonymously credit a fresh leaf into the
STARK pool.

The `m86_air` AIR is reused for both. The proof's bound `merkle_root`
public input distinguishes which pool — STARK pool root vs. mixer root.
Cross-pool replay is defeated by this binding (claim C5).

---

## 5. Cryptographic mechanisms

### Dilithium signatures

Wraps the `dilithium-py` reference implementation. Used for transparent
transactions, shield deposits, and mixer deposits. **Key management is
naive** (keys stored in JSON cleartext on disk); audit should not
extrapolate from the cryptographic primitive to the deployment.

### m86_air STARK

The single most important file in the codebase. Located at
`qstark/src/hash_air/m86_air.rs`. Implements a Goldilocks-field AIR
over Winterfell that proves:

1. The prover knows `(sk, r, v)` such that `H(sk, r, v) = leaf` is in
   the Merkle tree under `merkle_root`
2. `nullifier = H(sk+1, r, v)` (bound via FS to the same `sk, r, v`)
3. The output leaf `output_leaf = H(sk_out, r_out, v_out)` is correctly
   constructed
4. Value conservation: `v == unshield_amount + fee + v_out`

The AIR is a fixed-shape 256-row trace. Block kinds: preimage hash for
the input leaf, then `MERKLE_DEPTH=20` merge blocks for the Merkle path,
then preimage hash for the nullifier, then preimage hash for the output
leaf. The constraint system enforces:

- Each round of Rescue-Prime correctly applies
- Block transitions correctly chain digests
- Direction bits (left vs. right child at each Merkle level) are boolean
- Public inputs (`merkle_root`, `nullifier`, `output_leaf`, `unshield_amount`, `fee`)
  match the trace's terminal/computed values

**The depth-20 sparse Merkle tree** (M8.9) backs the trees. See
`M8.9-README.md` for the storage design; the trade-off is
`O(populated × depth)` memory at the cost of slightly heavier proof
generation (37ms at depth 20 vs ~25ms at depth 16).

### FRI / STARK setup

Uses Winterfell's defaults. Field is Goldilocks (`f64::BaseElement`).
**This is not custom cryptography** — Winterfell is the trusted dependency.

### Sparse Merkle tree

Both Rust (`qstark/src/hash_air/merkle.rs`) and Python
(`qchain/crypto/anon_stark.py`) have parallel implementations. The Rust
one is used by the AIR's trace generation; the Python one mirrors it
for chain state. Both must agree byte-for-byte.

### Nullifiers

`nullifier = Rp64_256(sk+1, r, v)`. The `+1` distinguishes the
nullifier hash from the leaf hash (`H(sk, r, v)`). Without this, a leaf
could nullify itself. **Audit this carefully** — the binding to `r` and
`v` is what makes the nullifier deterministic per-note; if the binding
were only to `sk`, an attacker who learned `sk` for one note could
construct nullifiers for arbitrary notes.

---

## 6. Trust model

### What we assume

- The Goldilocks field has no known structural attacks (Winterfell's claim)
- Rescue-Prime 64/256 is collision-resistant and one-way at conjectured security
- Dilithium provides post-quantum EUF-CMA signatures at NIST level 2
- The Fiat-Shamir transform is sound when the verifier samples honestly from
  the transcript (we use Winterfell's transcript)
- The host OS provides good randomness for key generation

### What we don't assume

- That peers behave honestly (we test malicious-peer scenarios extensively)
- That the network delivers messages reliably (fork resolution handles partition)
- That blocks arrive in order (gossip layer reorders; chain handles it)
- That IBM Quantum is available (deterministic fallback exists)

### What we ignore (out of scope)

- Side channels in the prover or verifier
- Adversarial scheduling (no time-based attacks modeled)
- Compromise of the build pipeline (Cargo registry, PyPI)

---

## 7. Known limitations (T1-T23)

The `THREAT-MODEL.md` document enumerates 23 named threats. The
**not-defended ones**, surfaced here rather than buried:

- **T14 (Anonymity-set timing analysis)**: chain-analysis observers
  can correlate deposit and withdrawal patterns. The M-timing pass
  raised the floor (5-block delay) but doesn't grow the anonymity set
  itself. Effective only at adoption scale.
- **T15 (Mempool privacy)**: tx contents are visible to all peers in
  the mempool. A mempool observer sees more than a chain observer.
- **T17 (Wallet file compromise)**: wallet JSON is cleartext on disk.
  Anyone with read access to the wallet file owns the funds.
- **T20 (Quantum RNG dependency)**: if IBM Quantum is unavailable the
  fallback is `secrets.token_bytes` — fine cryptographically but
  defeats the quantum-randomness narrative.

The DEFENDED ones (T1-T13, T16, T18, T19, T21, T22, T23) are mapped to
mechanisms in `THREAT-MODEL.md` sections 86-424.

---

## 8. Where to look

By concern:

| If you want to audit... | Read first |
|---|---|
| The AIR constraint system | `qstark/src/hash_air/m86_air.rs`, then `qstark/tests/m86_soundness.rs` |
| Value conservation | `m86_air.rs` value-balance constraint, then `qstark/tests/m86_partial_spend_soundness.rs` |
| Mixer admission logic | `chain/blockchain.py::submit_mixer_withdraw`, then `chain/blockchain.py::is_valid` (mixer section) |
| Timing-attack defense | `MIXER-TIMING-README.md`, then `tests/test_mixer_timing.py` |
| Persistence | `chain/blockchain.py::save / load / _rebuild_derived_state_from_blocks` |
| Network fork resolution | `network/node.py::_try_extend_or_replace` |
| Self-found bugs | `AUDIT-NOTES.md` (coinbase inflation fix described in detail) |

By milestone, in order they shipped:

```
M8.5  → STARK Merkle membership (Gap A, B, C closures)
M8.6  → m86_air; Gap B nullifier binding via FS
M8.7  → STARK pool integration; Gap C anonymity-set depth 16
M8.8  → unshield_amount + fee binding via FS
M8.9  → sparse Merkle, depth 20  ← READ THIS for the tree
M8.10 → is_valid chain replay; Gap D mempool→chain
M8.11 → partial spends with change outputs  ← key for value conservation
M10   → mixer layer (4 phases + dashboard)
PERSISTENCE        → save/load + chain replay
HARDENING          → withdraw_amount field removal (privacy)
THREAT-MODEL       → T1-T23 enumeration
AUDIT-FOLLOWUP     → 14 new tests; found and fixed coinbase bug
MIXER-TIMING       → T13 defense, anchor-root mechanism
```

The single most condensed view of the cryptographic core is
**`qstark/src/hash_air/m86_air.rs`** + **`THREAT-MODEL.md`** + this
document.

---

## 9. How to run things

### Build

Requires Rust 1.75+, Python 3.12+, Maturin.

```bash
# Build the Rust STARK core and PyO3 bridge
cd qstark_py && maturin build --release
pip install --break-system-packages --force-reinstall --no-deps \
  target/wheels/qstark_py-0.1.0-*.whl
```

### Run all tests

```bash
# Rust core (~5 seconds; 110 tests)
cd qstark && cargo test --release

# qstark_py Python bindings (21 tests; uses a custom test runner)
cd qstark_py && python3 test_qstark_py.py

# Python chain + network + dashboard (199 tests, ~5 minutes due to
# real STARK proof generation in test_anon_stark.py)
cd / && python3 -m pytest qchain/tests/ -q
```

**Total: 330 tests, all green.** A 3.5-minute slow tail comes from
`test_anon_stark.py` which generates real STARK proofs in a loop.

### Smoke-test the system live

```bash
# Start the dashboard (FastAPI + React, port 8101)
python3 -m qchain.dashboard.server
# Browse http://127.0.0.1:8101
```

The dashboard exposes /api/mine, /api/tx/send, /api/shield, /api/stark/spend,
/api/mixer/deposit, /api/mixer/withdraw. Mining is manual (PoW solved on
the request thread).

---

## 10. Self-audit findings (be honest with your auditor)

The team did its own audit pass (`AUDIT-NOTES.md`). It found **one real
bug**:

> **Coinbase inflation**: `is_valid()` did not validate that a block's
> coinbase output equaled the expected reward. A malicious miner could
> mint arbitrary coins by emitting a coinbase tx with any amount they
> chose. Fixed in the audit-followup pass with per-block expected_reward
> check; 5 regression tests added.

This finding was made by Claude (the AI agent that built the system)
during a self-audit. **The conflict of interest is acknowledged**. The
fact that the audit found a real bug despite COI is positive (means
"we tried") but doesn't mean other bugs aren't lurking.

The audit-followup pass also added defensive features that surfaced
during the audit narrative:

- `PERSISTENCE_VERSION` field (load-time schema checking)
- Per-block PoW puzzle validation in `is_valid()`
- T18 corruption tests (3 tests for malformed JSON, truncated chain, tampered hash)
- 14 new tests in `test_audit_followup.py` covering T2, T3-T4, T5, T13, T18, T19

The mixer timing-attack pass (this document's most recent predecessor)
closed T13, the last big "known undefended" item in the threat model.

---

## 11. What we want from this audit

If you have a fixed time budget, focus here in priority order:

1. **m86_air constraint completeness** — is there a witness shape that
   satisfies all constraints but breaks one of C1-C4? This is the
   hardest cryptographic question and the highest-impact finding.
2. **Public-input binding completeness** — does the FS transcript
   absorb every public input the security argument needs? Particularly
   `unshield_amount`, `fee`, `output_leaf`, `anchor_block_index`.
3. **Cross-pool replay** — claim C5 says proofs don't replay across the
   STARK pool and mixer pool. Audit the actual binding (the proof's
   `merkle_root` field) for any case we missed.
4. **Chain replay vs admission divergence** — every admission check
   needs an equivalent `is_valid()` check (the M8.10 pattern). Find
   any check that exists at admission but NOT at replay.
5. **Persistence load tampering** — what happens if a malicious save
   file says nullifier X is consumed when it isn't, or vice versa?
   Load doesn't re-verify proofs; should it?

If you find issues in these, please describe in terms of which claim
(C1-C10) is invalidated and write a regression test that fails on the
issue. The codebase has a strong test-discipline culture and we want
to keep that going.

---

## 12. Document version

| Version | Date | Notes |
|---|---|---|
| 1 | 2026-05-22 | Initial audit-package, after MIXER-TIMING pass closed T13. Test totals: 110 Rust + 21 qstark_py + 199 QChain Python = 330. |

---

## Appendix: doc index

For navigation. Documents are intended to be readable in any order
after AUDIT-PACKAGE.md (this file).

- `README.md` — user-facing project overview (test counts may be stale relative to here)
- `THREAT-MODEL.md` — T1-T23 enumeration + mechanism mapping
- `AUDIT-NOTES.md` — self-audit methodology + the coinbase finding writeup
- `AUDIT-FOLLOWUP-README.md` — what shipped after self-audit
- `MIXER-TIMING-README.md` — most recent pass; T13 defense
- `M8.9-README.md` — depth-20 sparse Merkle (read for the tree design)
- `M8.11-Phase1..4-README.md` — partial spends with change outputs
- `M8.10-README.md` — `is_valid()` chain-replay validation pattern
- `M10-Phase1..4-README.md` — mixer layer
- `PERSISTENCE-README.md` — save/load + replay
- `HARDENING-WITHDRAW-AMOUNT-README.md` — privacy hardening of mixer wire format
- `UI-DENOMINATION-DISPLAY-README.md` — dashboard local vs remote distinction
- `M8.5..M8.8-README.md` — earlier milestone history (less critical for audit)

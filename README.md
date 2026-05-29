# QChain

A research blockchain that takes post-quantum cryptography seriously and
ships honest zero-knowledge shielded payments end-to-end. Built over a
sequence of milestones, each with explicit scope and adversarial test
coverage.

<img width="1672" height="941" alt="ChatGPT Image May 29, 2026, 01_35_51 PM" src="https://github.com/user-attachments/assets/49eff5d6-27b9-4bdf-b5c0-359fcfee0249" />

## What this is

- **Post-quantum signatures everywhere** — CRYSTALS-Dilithium replaces ECDSA
- **Quantum-randomized consensus seed** — IBM Quantum RNG seeds proposer
  selection, with a deterministic fallback
- **Hand-rolled zk-STARK shielded payments** — Goldilocks-field AIR over
  Winterfell, proving Merkle membership + nullifier binding + value
  conservation in a single proof, scaled to a depth-20 (1,048,576-note)
  anonymity set via sparse Merkle storage
- **Real privacy mixer** — fixed-denomination anonymity pool with
  chain-side timing-attack defense (T13 mitigation)
- **Full p2p network layer** — TCP gossip, fork resolution, chain replay
- **Live dashboard** — FastAPI + React showing the chain, mempools, and
  the STARK shielded pool in real time
- **Persistent state** — chain + wallet survive restart with deterministic
  state reconstruction

## LIVE DEMO

**NODE 1 + Miner** https://46.224.128.50/?token=W9DV4YhYMS1i00bhOfX-j2h3drIZC-65X253ftAYYuo

**NODE 2** https://46.224.128.50:8443/?token=W9DV4YhYMS1i00bhOfX-j2h3drIZC-65X253ftAYYuo

**NODE 3** https://46.224.128.50:9443/?token=W9DV4YhYMS1i00bhOfX-j2h3drIZC-65X253ftAYYuo

The cryptographic story is *no hand-waving*. Every gap is documented;
every closure has soundness tests. Five self-found bugs and defects
(coinbase inflation, transparent-tx replay, infinite-loop protocol bug
from same-height-fork ping-pong, and two documentation defects) are
disclosed with full writeups — see [`PUBLICATION.md`](PUBLICATION.md)
section "Self-Disclosed Findings."

## Where to start

- **First-time external reader (auditor, researcher, grant reviewer)**:
  [`PUBLICATION.md`](PUBLICATION.md) — audit-readiness retrospective,
  ~5000 words, also typeset as `PUBLICATION.pdf` (13 pages). Consolidates
  the full arc, threat-model status table, and self-disclosed findings.
  **This is the master document.**
- **First-time code reader**: this README + [`DOCS.md`](DOCS.md) (reading-order guide)
- **Auditor (deep dive)**: [`AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md) — single-entry doc with C1–C10 claims
- **Security researcher**: [`THREAT-MODEL.md`](THREAT-MODEL.md) — T1–T23 with mechanism mapping
- **Future work**: [`ROADMAP.md`](ROADMAP.md) — candidate next milestones with honest scope estimates
- **How the project was built**: [`docs/milestones/`](docs/milestones/) — 32 historical milestone READMEs, one per pass. Read [`PUBLICATION.md`](PUBLICATION.md) first for the consolidated story; dive into specific milestones only when you want the detail.

## Test totals

| Layer | Count |
|-------|------:|
| qstark (Rust zk-STARK core) | 110 |
| qstark_py (PyO3 Python bindings) | 21 |
| QChain Python (chain + network + dashboard + properties + differential + wallet-encryption + rate-limiting + note-lifecycle + dashboard-auth + constants-phase3 + T18-closure + wallet-security-default + T19-closure + T20-closure + T14-mitigation + T20-roundtrip-regression) | 368 |
| **Total** | **499** |

All green. The QChain Python total includes 21 differential-AIR tests
(Phase 1 trace-content + Phase 2 Rescue-Prime round re-execution against
an independent Python implementation) and 9 Hypothesis property tests +
regression tests.

The `test_anon_stark.py` suite generates real STARK proofs in a loop and
takes ~3.5 minutes; the rest of the Python suite runs in under 2 minutes.

## Repository layout

```
qchain/                Python — the chain itself
  chain/               blocks, transactions, mixer, blockchain, wallet
  crypto/              dilithium, schnorr, anon_stark, merkle, m86_reference,
                       rescue_prime_ref (differential-test references)
  network/             p2p node, message dispatch, fork resolution, rate limiter
  dashboard/           FastAPI + React live view
  quantum/             IBM Quantum RNG client + deterministic fallback
  tests/               368 tests (chain, network, mixer, mixer-timing,
                       mixer-soundness, persistence, hardening, audit-followup,
                       dashboard, UI, differential-AIR phases 1+2+3, properties,
                       wallet-encryption, rate-limiting, note-lifecycle,
                       dashboard-auth)
  benchmarks/          STARK-anon proving phase benchmark (one-time)

qstark/                Rust — zk-STARK core
  src/hash_air/        m86_air (the production AIR), sparse Merkle, native ops
  tests/               110 soundness/integration tests

qstark_py/             PyO3 bindings
  src/lib.rs           Python ↔ Rust bridge
  test_qstark_py.py    21 binding tests

docs/milestones/       32 historical milestone READMEs (each pass's
                       design and decisions, kept as evidence; not
                       needed for first-time orientation)

*.md / *.pdf           12 active reference docs at the repo root:
                       README, PUBLICATION, THREAT-MODEL, ROADMAP,
                       AUDIT-PACKAGE, AUDIT-SOW, AUDITOR-ONBOARDING,
                       AUDIT-GRANT-APPLICATION, AUDIT-OUTREACH,
                       PROJECT-PRESENTATION, SUMMARY, DOCS
```

## How to run things

```bash
# All Python chain tests (~5 minutes due to real STARK proofs)
python3 -m pytest qchain/tests/ -q

# All Rust tests (~5 seconds)
cd qstark && cargo test --release

# qstark_py binding tests (~1 minute, uses custom runner)
python3 qstark_py/test_qstark_py.py

# Rebuild qstark_py wheel after editing Rust AIR
cd qstark_py && maturin build --release
pip install --break-system-packages --force-reinstall --no-deps \
  target/wheels/qstark_py-*.whl

# Live dashboard
python3 -m qchain.dashboard.server
# Open http://localhost:8101
```

## Current capabilities

### Cryptographic core
- **m86_air AIR**: Merkle membership + nullifier binding + value
  conservation + output-leaf binding in a single STARK
- **Depth-20 sparse Merkle tree**: 1,048,576-note anonymity-set cap,
  O(populated × depth) storage
- **Dilithium signatures**: PQC signing on every transaction
- **Fiat-Shamir-bound public inputs**: root, nullifier, output_leaf,
  unshield_amount, fee, anchor_block_index — every public input is
  absorbed into the transcript

### Chain protocol
- **Two shielded pools**: STARK pool (general shielded payments via
  ShieldTransaction → STARKAnonTransaction) and mixer pool (fixed
  denominations: 1, 10, 100, 1000)
- **Mixer timing-attack defense**: withdrawals must anchor to a mixer
  root at least 5 blocks old (T13 mitigation, anchor-root mechanism)
- **Transparent-tx replay defense**: `mined_txids` set prevents the
  same transaction from being mined into two blocks (property-test
  finding)
- **Chain replay validation**: `is_valid()` re-verifies the same
  invariants admission does (M8.10 admission-vs-replay consistency)

### Operational
- **Restart-survivable persistence**: chain + wallet serialize to JSON;
  derived state (trees, nullifiers, mixer history, mined_txids)
  reconstructed at load
- **Wallet encryption at rest**: optional argon2id + AES-256-GCM
  encryption of wallet files; closes T21 from THREAT-MODEL with
  backward-compatible legacy plaintext support
- **Rate limiting + DoS hardening**: per-peer per-message-type network
  limits, per-IP dashboard limits, max-block-size cap; closes T15
  and T23
- **Dashboard bearer-token auth**: constant-time-compared tokens on
  all `/api/*` and `/ws` endpoints, layered with rate limiting;
  closes T22 fully
- **Wallet note reconciliation**: read-only classifier
  (`Wallet.reconcile_with_chain()`) and opt-in cleanup
  (`Wallet.prune_pending_notes()`) for detecting orphaned shielded
  notes after a failed deposit
- **Network fork resolution**: TCP gossip + candidate-chain validation
- **Live dashboard**: real-time chain state, mempool visibility,
  mixer + STARK pool operations, WebSocket event stream

## Audit-readiness work

A four-pass audit-readiness arc ran on top of the protocol work:

| Pass | Output | What it gives an auditor |
|------|--------|--------------------------|
| **AUDIT-PACKAGE.md** | Entry-point document | Numbered falsifiable claims (C1–C10), scope, focus areas |
| **Differential AIR Phase 1** | Python trace inspection | Cross-check trace boundary content against native computation |
| **Differential AIR Phase 2** | Python Rescue-Prime reference | Independent round-function re-execution; catches per-round AIR bugs |
| **Property-based testing** | Hypothesis suite | 6 chain invariants tested over random op sequences |

The property-testing pass **found and fixed a real bug**: a transparent
transaction could be re-submitted after being mined and re-mined into a
second block, doubling the recipient's credit. Both admission and replay
layers were patched. See [`PROPERTY-TESTING-README.md`](docs/milestones/PROPERTY-TESTING-README.md).

An earlier self-audit pass also found and fixed a coinbase-inflation
bug. See [`AUDIT-FOLLOWUP-README.md`](docs/milestones/AUDIT-FOLLOWUP-README.md).

## What this is NOT

- **A production blockchain.** Per-peer rate limits exist (ROADMAP 1.5)
  but there's no peer authentication, no key-management hygiene
  beyond optional wallet encryption, and no TLS at the network layer.
  Wallet keys default to JSON cleartext unless the user opts in to
  encryption at rest.
- **An external audit substitute.** The audit-readiness arc was
  self-audit work. An external auditor would still find things.
- **A privacy panacea.** The mixer's anonymity set depends on real
  adoption — a 1M-leaf cap doesn't help if only a few users deposit
  at the same denomination in the same window. T14 (timing analysis)
  remains heuristic.
- **A finished product.** Recursive STARKs, multi-asset support,
  external transport security, real consensus-layer Byzantine
  fault tolerance — all out of scope and explicitly not implemented.

## Known limitations that survived (with pointers)

- **Wallet key management**: JSON cleartext. Out of scope. See
  AUDIT-PACKAGE section "Out of scope".
- **Quantum-RNG availability**: if IBM Quantum is unreachable the
  fallback is `secrets.token_bytes` — cryptographically fine but
  defeats the quantum-randomness narrative. See THREAT-MODEL T20.
- **`test_concurrent_blocks_resolved_by_extension`**: timing-flaky
  under heavy load. Timeout bumped to 10s; passes on retry.
  Architectural fix would need a gossip-dedup pass.
- **Network transport security**: no TLS. localhost-only is the
  honest deployment scope.
- **No formal verification**: the AIR is informally argued; the
  differential-AIR work goes a long way but doesn't replace
  symbolic verification of the polynomial constraints.

## Self-audit findings (full disclosure)

The project did its own audit pass. Two real bugs found and fixed:

1. **Coinbase inflation** (audit-followup pass): `is_valid()` did not
   validate the coinbase output amount, allowing a malicious miner
   to mint arbitrary coins. Fixed with per-block expected-reward
   check + 5 regression tests. See [`AUDIT-FOLLOWUP-README.md`](docs/milestones/AUDIT-FOLLOWUP-README.md).

2. **Transparent-tx replay** (property-testing pass): a mined tx
   could be re-submitted and re-mined into another block. Fixed
   with `Blockchain.mined_txids` set + 2 regression tests + property
   test. See [`PROPERTY-TESTING-README.md`](docs/milestones/PROPERTY-TESTING-README.md).

These are the kinds of bugs an external auditor would have found in
their first day. We found them first and fixed them. That's the
intended workflow: do the audit-readiness work in-house, then engage
an external auditor.

The conflict of interest is acknowledged: a self-audit by the same
party that wrote the code isn't independent. The fact that it
nonetheless found real bugs is positive (means we tried) but doesn't
substitute for external review.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

The patent grant in Apache 2.0 matters for a project that may be
extended or cited in cryptographic research. If you reuse any part
of QChain in your own work, the license terms apply.

# Auditor Onboarding

Practical reference for the first day or two of an audit engagement.
Answers the questions an auditor typically asks after getting access
but before starting the review proper.

For project scope, see [`AUDIT-SOW.md`](AUDIT-SOW.md). For technical
entry to the security claims, see [`AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md).

## 1. Build and run

The project has three workspaces:

```
qchain/        # Python — chain, network, wallet, dashboard
qstark/        # Rust — zk-STARK AIR core (uses Winterfell)
qstark_py/     # PyO3 — Python bindings to qstark
```

To get a working environment:

```bash
# 1. Python deps (no requirements.txt by design; install ad-hoc)
pip install fastapi uvicorn pydantic cryptography argon2-cffi \
            hypothesis pytest sympy pypdf

# 2. Build the Rust STARK core
cd qstark && cargo build --release

# 3. Build the Python bindings
cd qstark_py && maturin build --release
# Install the wheel from qstark_py/target/wheels/
pip install qstark_py/target/wheels/qstark_py-*.whl

# 4. Verify the toolchain
cd qchain && python -m pytest tests/test_chain.py -q  # ~5s
cd qstark && cargo test                                # ~5s
```

If your environment doesn't have `maturin`, install via
`pip install maturin`. Rust 1.75+ is sufficient.

The development environment used by the project is Python 3.12 and
recent stable Rust. Earlier Python should work; earlier Rust may not.

## 2. Run all tests

```bash
# Python: ~5 minutes (real STARK proof construction in test_anon_stark)
cd qchain && python -m pytest tests/ -q

# Rust: ~5 seconds
cd qstark && cargo test

# PyO3 bindings: custom runner (~1 minute)
python qstark_py/test_qstark_py.py
```

Expected: 337 Python tests pass (1 known-skip), 110 Rust tests
pass, 21 PyO3 tests pass. Total 468 tests.

One Python test (`test_concurrent_blocks_resolved_by_extension`) is
known to be timing-sensitive under heavy load. It's reliably fast
when run in isolation; if it fails during a full-suite run, retry it
alone.

## 3. Reading order — first three days

### Day 1: scope and claims

1. [`AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md) — claims C1–C10 with code
   cross-references. Read end-to-end.
2. [`THREAT-MODEL.md`](THREAT-MODEL.md) — 23 numbered threats with
   status taxonomy. Note which threats sit in your scope.
3. [`AUDIT-SOW.md`](AUDIT-SOW.md) — the SoW (which you've already
   read if you're here).

### Day 2: cryptographic surface

The audit's primary scope is the zk-STARK circuits. Read in this
order:

1. `qstark/src/lib.rs` — entry points
2. `qstark/src/hash_air/m86_air.rs` — the M86 AIR (Rescue-Prime
   based hash circuit). This is the most-reused AIR.
3. `qstark/src/mixer_withdrawal/` (or equivalent path) — the mixer
   withdrawal proof circuit
4. `qstark/src/stark_anon/` (or equivalent path) — the STARK-anon
   pool spend circuit
5. `qchain/crypto/anon_stark.py` — the Python-side proof orchestration
6. `qchain/crypto/m86_reference.py` — the differential testing
   reference implementation (re-executes Rescue-Prime independently)
7. `qchain/crypto/rescue_prime_ref.py` — the round-function reference
8. [`DIFFERENTIAL-AIR-README.md`](docs/milestones/DIFFERENTIAL-AIR-README.md),
   [`DIFFERENTIAL-AIR-PHASE2-README.md`](docs/milestones/DIFFERENTIAL-AIR-PHASE2-README.md),
   [`DIFFERENTIAL-AIR-PHASE3-README.md`](docs/milestones/DIFFERENTIAL-AIR-PHASE3-README.md)
   — the differential testing methodology

### Day 3: protocol composition

1. `qchain/chain/blockchain.py` — the canonical state machine.
   Look for `is_valid()` and the various `submit_*` methods.
2. `qchain/chain/mixer_tx.py` — mixer deposit and withdrawal
   transaction types
3. `qchain/chain/anon_stark_tx.py` — STARK-anon transactions
4. `qchain/chain/anon_tx.py` — M4 anon transactions
5. `qchain/chain/transaction.py` — transparent transactions
6. [`M10-Phase3-README.md`](docs/milestones/M10-Phase3-README.md),
   [`MIXER-TIMING-README.md`](docs/milestones/MIXER-TIMING-README.md) — mixer design
   docs

## 4. Where to look for what

| Concern | File |
|---|---|
| Block validation (replay-side) | `qchain/chain/blockchain.py::is_valid` |
| Block validation (admission-side) | `qchain/chain/blockchain.py::submit_*`, `qchain/network/node.py::_handle_new_block` |
| Mixer withdrawal proof construction | `qchain/chain/mixer_tx.py::create_mixer_withdraw_tx` |
| Mixer withdrawal proof verification | `qchain/chain/mixer_tx.py::MixerWithdrawTransaction.verify` |
| STARK-anon spend proof construction | `qchain/chain/anon_stark_tx.py::create_stark_anon_tx` |
| Sparse Merkle tree (depth 20) | `qchain/crypto/merkle.py` |
| Nullifier construction | `qchain/crypto/anon_stark.py::STARKNote.nullifier` |
| Dilithium signing | `qchain/crypto/dilithium.py` |
| Wallet encryption | `qchain/chain/wallet.py` (see WALLET-KEY-ENCRYPTION-README.md) |
| Dashboard auth | `qchain/dashboard/server.py::auth_middleware` |
| Rate limiting | `qchain/network/rate_limit.py`, `qchain/network/node.py::_limiter_for_type` |
| Persistence schema | `qchain/chain/blockchain.py::save / load`, `PERSISTENCE_VERSION` |
| Rescue-Prime constants | `qchain/crypto/_rescue_constants.py` |
| Constants verification | `qchain/crypto/rescue_constants_verify.py` |

## 5. Already-disclosed bugs

Five issues were found and fixed by the project's own audit-readiness
work. They are documented in `PUBLICATION.md` section 4 (or section
"Self-Disclosed Findings") and serve two purposes:

1. They demonstrate the project's discipline.
2. They are examples of the kind of bug the audit might find more
   of. (Coinbase inflation, transparent-tx replay, infinite-loop
   protocol bug, two documentation defects.)

A useful exercise on day one: re-derive each disclosed bug from the
code and verify the fix actually prevents it. If you find the fix
incomplete, that's a finding.

## 6. Known limitations the project will not fix

These are NOT bugs; they are explicit scope decisions. Listed here
so you don't spend time writing them up as findings.

- **No BFT for malicious-quorum PoS.** Documented in T-Avoid-A4.
- **No TLS.** Documented as a deployment concern.
- **No statistical timing-attack defense across blocks (T14).**
  Documented.
- **No on-load chain validation (T18).** Known small follow-up;
  the project may close this between audit start and audit
  finish, but is not committing to do so.
- **No replay protection across networks (T20).** Documented.
- **No off-chain note backup.** By design.
- **No formal proof of AIR correctness.** Differential testing is
  the project's evidence; it's not a proof. Closing this is item
  2.4 on the project ROADMAP and is explicitly out of audit scope.

If you find any of these, they're not new findings. If you find
that one of these is documented but not actually true (e.g., the
project DOES validate on-load and the doc is wrong), that's a
documentation finding worth reporting.

## 7. What's most security-critical

By risk:

1. **The AIRs.** A buggy AIR could allow forgery of shielded
   payments. Every other concern is secondary to this. If you have
   time for only one thing, audit the mixer withdrawal AIR and the
   STARK-anon spend AIR.
2. **Nullifier construction and storage.** A nullifier collision
   or replay would allow double-spends.
3. **The is_valid / admission consistency pattern (M8.10).** Any
   place where admission and replay disagree is a candidate for
   acceptance of invalid state.
4. **Block reward / coinbase computation.** The coinbase inflation
   bug was here; check if the fix is complete and if other
   inflation paths exist.
5. **Mixer anchored-root logic.** The timing-attack defense uses
   historical roots; the historical-root storage and anchor-validation
   logic should be airtight.

## 8. What's likely NOT security-critical

- The dashboard. It's a debug UI. Even if it has bugs, the auth
  layer plus localhost binding bound the impact.
- The wallet encryption. argon2id + AES-GCM is standard; bugs
  there would likely be obvious.
- The network gossip protocol. Bugs here cost availability, not
  correctness.

## 9. Tooling you may want

- `cargo expand` for inspecting Rust macro output
- `winterfell` source: pinned to `winter-crypto-0.8.3`. Reading
  Winterfell's source is sometimes necessary to understand the AIRs.
- `sympy` for ad-hoc field arithmetic checks
- `hypothesis` for property-based exploration (the project already
  uses it; you can add tests of your own)
- `pdb` / `rust-gdb` for debugging interactively

## 10. Communication during the audit

Suggested cadence:

- **Week 1:** Auditor reads the codebase. Project answers questions
  via email or async chat. No formal meetings needed.
- **Week 2–3:** Auditor does the deep review. Project provides any
  additional context requested. Sample findings shared early so the
  project can flag if anything is misunderstood.
- **Week 4–5:** Final report draft. Project reviews; corrects any
  factual misstatements. Auditor finalizes.

The project's preference is high written-quality, low meeting
overhead. We expect the auditor to write everything down in the
final report rather than communicating findings verbally.

## 11. What the project asks of you

- Be honest about what you didn't have time to look at. The honest-
  scope discipline applies to audit reports too — a partial review
  with a clear statement of what was deferred is more valuable than
  a "thorough" review with hidden gaps.
- Mark findings by severity, using your own scale. The project will
  respond to each finding regardless of severity.
- Don't soft-pedal findings. The project is explicitly designed to
  surface its own problems; surfacing more is welcome, not
  uncomfortable.
- Feel free to suggest engineering or documentation changes
  alongside security findings.

## 12. What you can expect from the project

- Fast response to questions, in writing.
- No pushback on findings without a documented reason.
- The audit report becomes part of the public record, with your
  firm credited.
- A retrospective ROADMAP item after the audit ("`1.1 External
  audit engagement` — completed, see [link to your report]") that
  lists which findings were fixed in subsequent passes and which
  were accepted as documented honest-scope.

## 13. After the audit

Each finding will receive one of three responses, all public:

- **Accept and fix.** A code pass addresses the finding; the
  audit-findings-followup ROADMAP item tracks it.
- **Accept and document.** The finding is real but the project
  chooses not to address it; it becomes part of the threat model
  as a documented honest-scope item.
- **Dispute with reason.** The project disagrees with the finding;
  the disagreement is documented in writing alongside the original
  finding.

We will NOT dispute findings privately; if we disagree, we will
disagree in writing and let readers judge.

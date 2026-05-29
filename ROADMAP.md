# ROADMAP

Candidate future milestones for QChain, with honest scope estimates.
The five-pass audit-readiness arc closed with `PROPERTY-TESTING-README.md`;
this document inventories what could come next so the choice is made
deliberately rather than by default.

## How to read this document

Every candidate has the same shape:

- **Pitch**: one sentence describing what it would add
- **Cost**: estimated sessions of focused work, where one session is
  roughly what AUDIT-PACKAGE.md or the property-testing pass took
- **Destabilizes**: which existing audit-readiness work, tests, or
  documentation would need to be revisited
- **Prerequisites**: what has to be true before starting
- **What you get**: concrete capability change
- **Honest take**: my recommendation, including "don't do this"

There are three sections:

1. **Next-up candidates** — work that's well-scoped and could start now
2. **Heavy candidates** — multi-month research-shaped work
3. **Don't do (yet, or ever)** — items I'd advise against

Items are NOT ranked by importance. They're grouped by readiness.

---

## 1. Next-up candidates

These are session-scoped (1-3 sessions of focused work each), have
clear prerequisites met, and don't fundamentally destabilize existing
audit-readiness work.

### 1.1 External audit engagement

**Status:** Outreach package shipped 2026-05. The procurement and
grant-application materials are in place:

- [`AUDIT-SOW.md`](AUDIT-SOW.md) — Statement of Work for audit firms
- [`AUDITOR-ONBOARDING.md`](AUDITOR-ONBOARDING.md) — practical
  first-day reference for the engaged auditor
- [`AUDIT-GRANT-APPLICATION.md`](AUDIT-GRANT-APPLICATION.md) —
  narrative source for grant applications
- [`AUDIT-OUTREACH.md`](AUDIT-OUTREACH.md) — target audit firms,
  target grant programs, message templates, and four-phase outreach
  strategy

The remaining work is NOT engineering — it is outreach (sending
emails), procurement (collecting quotes), application (submitting
grants), and engagement (signing the SoW, kickoff). These are
calendar/budget items, not code items.

The applicant will mark this item as completed once the audit has
been conducted and the public report is published.

**Pitch.** Pay an actual auditor to read AUDIT-PACKAGE.md and the
code; come back with findings.

**Cost.** Calendar time, not session time. Likely 4-12 weeks elapsed,
with bursts of "respond to questions" work on this side.

**Destabilizes.** Nothing in the codebase. Findings might require
fix passes after the audit completes, but those are separate work.

**Prerequisites.** Money. A chosen auditor. None of this is on the
code side — the code is in the most ready state it has been.

**What you get.** Independent validation of the cryptographic
claims, plus a real findings list. The audit-readiness arc was
explicitly preparation for this step.

**Honest take.** This is THE recommended next step. The 5-pass
audit-readiness arc was specifically scoped as "what we should do
before paying an external auditor." That work is complete; doing
more in-house audit-readiness has sharply diminishing returns. The
right move is to stop doing it ourselves and engage someone else.

### 1.2 Differential AIR Phase 3 — constants cross-reference

**Status:** ✅ Shipped 2026-05. See
[`DIFFERENTIAL-AIR-PHASE3-README.md`](docs/milestones/DIFFERENTIAL-AIR-PHASE3-README.md).
Three-layer verification: algebraic self-checks (10 checks), regression
test vectors (3), and an opt-in snapshot cross-reference harness.
Layer 1 and Layer 2 are active; Layer 3 awaits a vendored snapshot from
an independent source (a documented follow-up; the harness is shipped).
Includes a pinned SHA-256 constants fingerprint.

**Pitch.** Verify the MDS / ARK1 / ARK2 constants in
`qchain/crypto/_rescue_constants.py` against an independent source
(Polygon Miden's `miden-crypto`, Plonky2, or the Rescue-Prime SAGE
reference). Closes the gap noted in DIFFERENTIAL-AIR-PHASE2-README:
"a bug in Winterfell's constants would be undetected by us because
we extracted FROM Winterfell."

**Cost.** ~1 session.

**Destabilizes.** Nothing. Adds a test file; updates
DIFFERENTIAL-AIR-PHASE2-README to note the cross-reference passed.

**Prerequisites.** Pick an independent source. Polygon Miden is
the obvious one (BSD-3, Rust, easy to vendor).

**What you get.** A documented statement that two independent
projects use the same constants, with a test that verifies it. An
external auditor can point at this test instead of having to do the
cross-reference themselves.

**Honest take.** Worthwhile but optional. Expected outcome: zero
findings (these are widely-used constants). Value is auditor-facing,
not user-facing. Defer if external audit is on the calendar; do if
external audit is far off and we want one more layer of polish.

### 1.3 Publication / writeup of the audit-readiness arc

**Status:** ✅ Shipped 2026-05. See
[`PUBLICATION.md`](PUBLICATION.md) (markdown) and
`PUBLICATION.pdf` (typeset 13-page PDF) for the audit-readiness
retrospective. Suitable for external researchers, audit firms,
and grant reviewers; consolidates the full arc, all five
self-disclosed findings, the threat-model status table, and
honest standing limitations.

**Pitch.** Take the audit-readiness arc and turn it into a writeup
that an external researcher could read: blog post, technical report,
or even a workshop paper draft.

**Cost.** 1-2 sessions for a long-form writeup; more if a paper.

**Destabilizes.** Nothing.

**Prerequisites.** Decision about target venue (informal blog vs.
formal paper).

**What you get.** External-facing artifact that demonstrates the
project's work. Useful for hiring, grant applications, audit
recruitment.

**Honest take.** Genuinely valuable. The work is uncommon enough
that a writeup has real reach. Lower priority than the audit
itself but higher than additional code work.

### 1.4 Wallet key encryption at rest

**Status:** ✅ Shipped 2026-05. See
[`WALLET-KEY-ENCRYPTION-README.md`](docs/milestones/WALLET-KEY-ENCRYPTION-README.md)
for the implementation, design decisions, and test coverage.
T21 in [`THREAT-MODEL.md`](THREAT-MODEL.md) is now `[DEFENDED]`
(with caveats).

**Pitch.** Encrypt the wallet's Dilithium private key with a
user-provided passphrase before writing to disk. Closes T21 from
THREAT-MODEL.

**Cost.** 1 session including tests.

**Destabilizes.** Wallet persistence format changes; existing wallet
JSON files become un-loadable unless migration is provided. Need to
bump some kind of wallet version field.

**Prerequisites.** Pick a KDF (argon2id is the obvious choice).
Decide how to handle the password-prompt UX (env var? interactive
prompt? both?).

**What you get.** T21 closed in THREAT-MODEL. Genuinely improved
practical security for anyone running an honest local node.

**Honest take.** Good fit for a single session. Low risk, clear
scope, real security improvement. Worth doing.

### 1.5 Rate limiting / DoS hardening (T15, T22, T23)

**Status:** ✅ Shipped 2026-05. See
[`RATE-LIMITING-README.md`](docs/milestones/RATE-LIMITING-README.md) for the
implementation, design decisions, and test coverage.
T15 and T23 now `[DEFENDED]`; T22 partially defended (rate-limited,
authentication still pending as a separate ROADMAP item).
Bonus: a pre-existing protocol flake (`test_concurrent_blocks_resolved`)
was deterministically fixed as a side effect.

**Pitch.** Add per-peer mempool rate limits, per-IP dashboard rate
limits, and a max-block-size check. Closes four `[NOT DEFENDED]`
threats from THREAT-MODEL with one focused pass.

**Cost.** 1-2 sessions including tests.

**Destabilizes.** Network module sees real changes; some existing
network tests may need adjustment because they currently flood
freely. Dashboard tests likewise.

**Prerequisites.** None.

**What you get.** Three T-numbered threats move from `[NOT DEFENDED]`
to `[DEFENDED]`. Closer to "could run on the open internet" though
still not there.

**Honest take.** Defensible session. The implementation will be
simple (`collections.deque` of timestamps per peer, max-block-size
constant). The wins are real even if not cryptographic. Recommend
doing if external audit is far off; less urgent if audit is close
(auditor will tell you what limits to set).

### 1.6 Persistent wallet shielded-note tracking

**Status:** ✅ Shipped 2026-05. See
[`WALLET-NOTE-LIFECYCLE-README.md`](docs/milestones/WALLET-NOTE-LIFECYCLE-README.md)
for the discovery (the original problem statement was stale —
note persistence had already shipped) and the actual work done:
`reconcile_with_chain()`, `reconcile_summary()`, and
`prune_pending_notes()` helpers for inspecting and cleaning up
the wallet's owned-note bookkeeping against actual chain state.
The stale docstring at the top of `chain/wallet.py` is also
fixed.

**Pitch.** Currently `wallet.py` notes: "notes are stored in-memory
only and not persisted by save() for now. A wallet restart loses
the spender's knowledge of their shielded notes." Add persistence.

**Cost.** 1-2 sessions.

**Destabilizes.** Wallet save/load format. Possibly the M10 mixer
note tracking. Existing wallet tests need extension.

**Prerequisites.** None.

**What you get.** A wallet restart no longer loses funds in shielded
form. Currently this is a "research-prototype" honest scope note;
fixing it makes the wallet usable for anything resembling real flow.

**Honest take.** Worth doing. Lower priority than the security
items above but higher than performance work. Could be combined
with 1.4 (wallet key encryption) since both touch the same file.

---

### 1.7 Close T18 — on-load chain validation

**Status:** ✅ Shipped (post-publication fix). `Blockchain.load()`
now calls `is_valid()` on the reconstructed chain by default,
catching corrupt-but-parseable persistence files (tampered hashes,
forged signatures, fabricated blocks). Moves T18 from `[HEURISTIC]`
to `[DEFENDED]` in THREAT-MODEL.md. Opt-out via `validate=False`
for tests that deliberately work with invalid chain state.

Added 5 tests (1 was rewritten from the old "documents current
behavior" test); 4 net new. Python total 337 → 341, project total
468 → 472.

---

### 1.8 Wallet encryption as default (T21 strengthening)

**Status:** ✅ Shipped (post-publication fix). `Wallet.save()` now
requires either a passphrase (encryption, default) or an explicit
keyword-only `allow_plaintext=True` opt-out. A bare `save(path)`
or `save(path, passphrase="")` raises `ValueError` with an error
message explaining the choice.

Previously T21 was `[DEFENDED]` only when the user opted in to
encryption. Now T21 is `[DEFENDED]` by default; users must
explicitly choose plaintext. This is a behavior change: any
external code that called `save(path)` without a passphrase now
gets a clear error pointing at the fix.

The `allow_plaintext` parameter is keyword-only (note the `*` in
the signature) so a positional `True` can't enable it by accident.

Load behavior is unchanged: existing plaintext wallet files in the
wild continue to load. Only the save default is hardened.

Added 4 new tests (default raises, empty passphrase raises, opt-out
works, keyword-only enforcement). 3 existing tests were rewritten
to use `allow_plaintext=True` where they specifically test the
plaintext format. 4 other existing tests were upgraded to use a
passphrase (a more realistic flow). Python total 341 → 345, project
total 472 → 476.

---

### 1.9 Close T19 — plaintext wallet version field

**Status:** ✅ Shipped (post-publication fix). The plaintext wallet
format now carries an explicit `wallet_format: "plaintext-v1"`
version tag. `Wallet.load()` accepts this and the legacy unversioned
form (backward compat for existing user wallets); rejects unknown
plaintext versions (e.g., a future `plaintext-v2` this code doesn't
know).

Moves T19 from `[HEURISTIC, INCOMPLETE]` to `[DEFENDED]`. All
three persistence formats (chain JSON, encrypted wallet, plaintext
wallet) now have explicit version tags with future-version
rejection at the load boundary. Schema drift can no longer cause
silent mis-loading.

Also fixes a stale T19 description in THREAT-MODEL.md — the
previous text claimed the chain had no version field, but
`PERSISTENCE_VERSION` has been on the chain since the M-timing
pass. The description now accurately reflects all three formats.

Added 4 new tests in `test_audit_followup.py` (plaintext save
includes version, legacy plaintext loads, unknown version
rejected, roundtrip preserves data). 1 existing test from sub-
pass 2a (`test_save_with_allow_plaintext_true_succeeds`) had its
assertion flipped to reflect the new behavior (plaintext now HAS
the version field). Python total 345 → 349, project total 476 → 480.

---

### 1.10 Close T20 — cross-network replay defense

**Status:** ✅ Shipped (post-publication fix, grant-requested). The
chain now carries an identifier `Blockchain.CHAIN_ID = "qchain-v1"`,
and every transaction type can carry a matching `chain_id` field:

| Tx type | Binding |
|---------|---------|
| `Transaction` | chain_id in `_payload()` — covered by Dilithium signature (cryptographic) |
| `ShieldTransaction` | chain_id in `_payload()` — covered by Dilithium signature (cryptographic) |
| `MixerDepositTransaction` | chain_id in signed hash payload — covered by Dilithium signature (cryptographic) |
| `AnonTransaction` (M4) | chain_id as serialized field — checked at admission only |
| `STARKAnonTransaction` | chain_id as serialized field — checked at admission only |
| `MixerWithdrawTransaction` | chain_id as serialized field — checked at admission only |

For Dilithium-signed txs (the first three) the chain_id is in the
signature payload, so any tampering breaks the signature. For
STARK/Schnorr-proof-bearing txs (the last three), modifying the
proof's binding would require modifying the M86 AIR — explicitly
out of scope this pass (would be a major Rust change invalidating
all existing proofs). The carve-out is documented in THREAT-MODEL.md
T20: the admission-only check defends against accidental cross-
network replay but not against an active attacker who modifies the
chain_id field after broadcast (such an attacker would also need
to re-target the resubmission, which the target network's admission
check would catch).

Legacy txs (chain_id=None) accepted as backward-compat. Existing
chain files don't need migration.

Moves T20 from `[NOT DEFENDED]` to `[DEFENDED]` with the documented
STARK-proof carve-out.

Added 12 new tests in `test_t20_chain_id.py` covering cryptographic
binding for all 3 Dilithium-signed types, admission-time rejection
for all 6 types, backward compatibility (legacy unbound txs), and
serialization roundtrip. Python total 349 → 361, project total
480 → 492.

---

### 1.11 T14 partial mitigation — randomized withdrawal delays

**Status:** ✅ Shipped (post-publication fix, grant-requested,
partial). The wallet's `create_mixer_withdrawal()` now attaches a
randomized `suggested_delay_blocks` ~ Uniform[0,
`MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX` (=20)] to each
withdrawal. The caller is expected to hold the withdrawal off-chain
for that many additional blocks before submitting, layering a
randomized delay on top of the chain-side deterministic minimum.

Combined with the existing chain-side `MIXER_WITHDRAWAL_DELAY = 5`
floor, total deposit→submit wait is uniformly distributed in
[5, 25] blocks. This spreads any single user's withdrawal across
a 20-block window from a passive observer's perspective.

**Moves T14 from `[NOT DEFENDED]` to `[HEURISTIC]`** — the project
no longer has any `[NOT DEFENDED]` items in the threat model. T14
remains `[HEURISTIC]`, not `[DEFENDED]`, because:

- An attacker applying statistical analysis over many blocks can
  still link deposits and withdrawals probabilistically — the
  randomization widens the correlation window but doesn't break
  statistical linkability
- The defense is enforced wallet-side, not chain-side; a
  misbehaving wallet that ignores `suggested_delay_blocks` forfeits
  the protection
- Network-layer timing correlation (gossip propagation, IP, peer
  patterns) is out of scope

Full T14 closure would require constant-rate decoy traffic,
mix-network protocols, or decoy-based ZK proofs — all multi-month
research efforts. The honest assessment is that T14 cannot be
`[DEFENDED]` without changing the project's fundamental
cryptographic approach.

Implementation uses `secrets.randbelow()` for crypto-quality
randomness. The `suggested_delay_blocks` attribute lives only on
the wallet-side return value and does NOT leak into the on-chain
serialization (verified by test).

`randomize_delay=False` opt-out parameter exists for deterministic
tests.

Added 5 new tests in `test_t14_randomized_delays.py` covering
range check, deterministic opt-out, distribution non-degeneracy,
serialization isolation, and secure-by-default behavior. Python
total 361 → 366, project total 492 → 497.

---

### 1.12 End-to-end demo + T20 save/load round-trip regression fix

**Status:** ✅ Shipped (post-publication, grant-requested). Added
a single-command end-to-end demo (`python -m qchain.demo.end_to_end`)
that exercises every major capability of QChain — transparent
transactions, M4 anonymous transactions, STARK shielded deposits,
STARK-anon partial spends (M8.11), mixer deposits, delayed mixer
withdrawals (T13 + T14), persistence (T18), and wallet encryption
(T21). Runtime ~4-5 seconds; output goes to stdout in structured
sections.

The first run of the demo caught a real bug in the T20
implementation: `ShieldTransaction.to_dict()` and
`MixerDepositTransaction.to_dict()` were explicitly enumerating
fields and didn't include the new `chain_id` field. A chain saved
with bound shield or mixer-deposit txs would reload with chain_id
silently dropped to None, breaking signature verification on
replay. The bug existed because:

- The 12 T20 unit tests checked in-memory operations and admission
  behavior, but did not exercise the save → reload → is_valid
  pipeline against bound txs
- `Transaction` uses `asdict(self)` so it picked up the new field
  automatically; the other two types enumerated fields manually

Fix: both `to_dict` methods now conditionally emit chain_id (only
when set, keeping legacy bytes identical) and both `from_dict`
methods now read it back with a None default. Added 2 regression
tests (`test_t20_shield_chain_id_survives_save_load_roundtrip`,
`test_t20_mixer_deposit_chain_id_survives_save_load_roundtrip`)
that exercise the to_dict → from_dict → verify cycle.

Honest note: this is the kind of bug end-to-end demos exist to
catch. Unit tests verified the in-memory behavior; the demo
verified the lifecycle. Both are needed.

Files added:
- `qchain/demo/__init__.py`
- `qchain/demo/end_to_end.py` — 6-section runnable demo
- `qchain/demo/README.md` — what the demo demonstrates, how to read it

Files modified:
- `qchain/chain/shield_tx.py` — to_dict/from_dict include chain_id
- `qchain/chain/mixer_tx.py` — same for MixerDepositTransaction
- `qchain/tests/test_t20_chain_id.py` — +2 round-trip regression tests

Python total 366 → 368, project total 497 → 499.

---

### 1.13 Deployment prep — systemd-based 3-node VM deployment

**Status:** ✅ Shipped (post-publication, grant-requested). Added
deployment artifacts that bring up a 3-node QChain network on a
single Linux VM via systemd. Designed for a "grant reviewer hits
a URL and sees a working chain" use case.

**Topology:**
- 3 QChain nodes peering via localhost (internal-only p2p)
- 1 public-facing dashboard on node 1, port 8101
- 2 internal-only debug dashboards on nodes 2/3 (curl-only, not
  exposed to public)
- 1 auto-miner periodically hitting `POST /api/mine` so the chain
  produces blocks every ~15 seconds without manual interaction

**Security posture (honest):**
- Dashboard auth via bearer token (T22)
- HTTP only (no TLS); reviewers hit `http://VM_IP:8101/`. Adding
  TLS via Caddy is documented as a follow-up.
- P2P ports bind to 0.0.0.0 but are firewall-blocked from external
  access (the dashboard.server CLI currently couples its p2p and
  dashboard bind addresses; the firewall is the actual boundary).
- Chain is ephemeral (in-memory, resets on systemctl restart). Fine
  for a demo; persistent state is a future enhancement.
- Single-validator PoW mining via node 1; nodes 2 and 3 replay-
  verify via gossip. Research-grade consensus, not production.

**New operational tool:**
- `qchain/tools/auto_mine.py` — stdlib-only HTTP client that hits
  the dashboard's mine endpoint at a configurable interval. No
  external deps. Graceful handling of transient dashboard outages.

**Files added:**
- `deploy/README.md` — step-by-step VM setup guide (11 numbered
  steps: user creation, dependencies, env setup, systemd install,
  firewall, service start, verification, troubleshooting)
- `deploy/firewall-setup.md` — ufw / iptables / cloud-firewall
  configurations
- `deploy/env/qchain.env.example` — environment file template with
  token, ports, intervals, all documented inline
- `deploy/systemd/qchain-node-1.service` — bootstrap + dashboard
- `deploy/systemd/qchain-node-2.service` — follower
- `deploy/systemd/qchain-node-3.service` — follower (connects to
  both node-1 and node-2 for full-mesh peering)
- `deploy/systemd/qchain-automine.service` — periodic mining
- `qchain/tools/__init__.py`
- `qchain/tools/auto_mine.py`

**Verified end-to-end:** smoke-tested the 3-node + auto-miner
design locally. Three nodes start, peer with each other via
localhost, and converge on the same chain height after mining.
The deployment design is known-working before you touch the VM.

No threat-model changes; no test count changes (the deployment
artifacts are deploy-time, not run-time tested by the suite).

---

## 2. Heavy candidates

These are multi-month research-shaped work. Each one is a serious
commitment that would dominate the codebase's direction for its
duration. None should be started without explicit alignment.

### 2.1 Recursive STARKs / proof aggregation

**Pitch.** Build a STARK that verifies other STARKs. Lets a block
include N shielded txs but only do one verification.

**Cost.** 6-12 months at production quality. At toy quality, maybe
2-3 months — but the toy doesn't help anyone.

**Destabilizes.** Cryptographic core. The recursion AIR is its own
audit-readiness story; the existing m86 work doesn't transfer. Most
of the differential-AIR infrastructure would need extension or
rewrite. AUDIT-PACKAGE.md becomes partially obsolete on day one of
this work.

**Prerequisites.** Winterfell doesn't natively support recursion;
either build it on top of Winterfell (very hard) or migrate to a
recursion-capable framework (Plonky2, RISC Zero zkVM). Each
migration is its own decision with months of work attached.

**What you get.** The capability to scale shielded txs without
per-tx verification cost. Real but not unique — most production zk
projects use this approach.

**Honest take.** Do NOT start this without (a) finishing the
external audit of current work, (b) deciding whether to migrate
the cryptographic framework, and (c) committing months of focused
work. As a "next milestone" this would consume the project for the
rest of the year. If you're doing this, you're doing it because
this IS the project's central direction now.

### 2.2 Real Byzantine-fault-tolerant consensus

**Pitch.** Replace the current PoW + QRNG-seeded-proposer setup with
a real BFT consensus protocol (HotStuff, Tendermint, etc.).

**Cost.** 3-6 months at honest quality.

**Destabilizes.** Network layer, fork-resolution logic, the entire
chain-replay validation path. Existing network tests get rewritten.
Probably affects persistence (consensus state needs to survive
restart).

**Prerequisites.** Decision about which consensus protocol. Each
has different liveness/safety guarantees and different audit
profiles. Library availability varies widely (PBFT is well-studied;
HotStuff has decent implementations; Tendermint has Cosmos's
production codebase but that's a different language).

**What you get.** Honest "could-be-a-real-blockchain" consensus
properties. Currently QChain's consensus is barely simulated.

**Honest take.** This is the most foundationally important "real
blockchain" upgrade. Also the most expensive. If the project's
identity is "research demo of post-quantum cryptography + zk
shielded payments", real BFT is unnecessary. If the project's
identity becomes "a chain people could actually use", real BFT
becomes essential. Decide what the project IS first.

### 2.3 Multi-asset support

**Pitch.** Don't just track QChain coins; let multiple asset IDs
flow through the shielded pool with conservation per asset.

**Cost.** 2-4 months.

**Destabilizes.** The AIR. Specifically, the value-conservation
constraint becomes per-asset, requiring an asset_id public input
bound via FS. The Phase 1 + Phase 2 differential-AIR work survives
(structure is the same) but the security claims C1-C10 in
AUDIT-PACKAGE.md need extension.

**Prerequisites.** Decision about asset model (UTXO-style with
explicit asset IDs? account-style?). Decision about how assets
enter the system (chain-native issuance? off-chain bridging?).

**What you get.** Reusable shielded-pool infrastructure for
multi-asset scenarios. Practical relevance limited to
non-prototype settings.

**Honest take.** Don't do this unless there's a real use case
pulling for it. The current single-asset design is what makes the
cryptographic argument crisp. Multi-asset is a "fork in the road"
that you can't easily back out of.

### 2.4 Formal verification of m86_air's polynomial constraints

**Pitch.** Use a SAT/SMT solver (Z3, CVC5) or Lean/Coq proof
assistant to symbolically verify that the polynomial expressions in
`m86_air.rs::evaluate_transition` correctly encode the round
function and the security claims.

**Cost.** 6+ months for honest coverage; longer if Lean/Coq.

**Destabilizes.** Nothing; this is read-only with respect to the
AIR code.

**Prerequisites.** Significant formal-methods expertise. The
project's existing differential-AIR work checks "the trace satisfies
the constraints"; formal verification checks "the constraints are
the right constraints."

**What you get.** The strongest possible statement of AIR soundness.
Far beyond what most production zk projects achieve.

**Honest take.** This is audit-time work, not pre-audit work. An
external auditor with formal-methods background might do something
in this direction. Doing it ourselves before audit would be massive
effort for a thing the auditor would arguably be hired to do.

---

## 3. Don't do (yet, or ever)

### 3.1 Switching cryptographic frameworks (Winterfell → Plonky2 / RISC Zero)

**Why not.** The existing work is built on Winterfell. The
audit-readiness arc is built on Winterfell. The differential-AIR
infrastructure is Winterfell-shaped. A framework switch invalidates
all of it. If recursive STARKs (2.1) requires a switch, do that
analysis carefully as part of that decision — but do not switch for
its own sake.

### 3.2 Rewriting in another language

**Why not.** Same logic as 3.1 plus: language choices are tribal,
the existing Python+Rust split is reasonable, and the rewrite would
be 100% effort for 0% security improvement.

### 3.3 Adding new consensus features incrementally

**Why not.** Consensus is one of those areas where partial work is
worse than no work. Adding "just slashing" without the protocol that
makes slashing meaningful is harmful. If consensus changes, they
should be one coherent pass (item 2.2), not a series of small
additions.

### 3.4 Side-channel hardening of the prover

**Why not.** Listed as `[NOT DEFENDED]` in AUDIT-PACKAGE.md. Real
side-channel hardening is hardware-aware work that requires a
target deployment. For a research demo running on a laptop, the
threat model doesn't justify the effort. If the project moves toward
real deployment, this becomes relevant — but only then.

### 3.5 Marketing-driven scope expansion

**Why not.** No comment needed. The codebase's distinctive feature
is honest scope notes. Adding things for narrative reasons rather
than security/usability reasons would erode that.

---

## Recommendation

If I had to pick one path:

1. **Engage an external auditor** (1.1).
2. While the audit is in flight, write the publication writeup (1.3).
3. After the audit comes back, decide based on findings whether to
   do remediation, polish (1.2, 1.4, 1.5, 1.6), or move to one of
   the heavy candidates.
4. Do NOT start any heavy candidate (2.1-2.4) before completing
   external audit on the current scope.

The path I would specifically NOT recommend: stringing together
items 1.2-1.6 as "more audit-readiness" without engaging an
external auditor. Marginal improvements after this point have
diminishing returns; the next big improvement comes from external
eyes.

## What's NOT in this roadmap

- **Bug fixes for newly-discovered issues.** Those happen when
  needed and don't need pre-scoping.
- **Documentation refreshes.** The doc-cleanup pass that landed
  DOCS.md and refreshed README/THREAT-MODEL covered the immediate
  doc-debt. Future passes are needed as the codebase evolves but
  don't belong in a roadmap.
- **Test infrastructure improvements.** If something specific
  breaks (e.g., the `test_concurrent_blocks_resolved_by_extension`
  flakiness), fix it then; don't plan it now.
- **Performance work.** No part of QChain is currently performance-
  critical for its intended use. Performance work would be premature.

## Document version

| Version | Date | Notes |
|---|---|---|
| 1 | 2026-05-22 | Initial roadmap after audit-readiness arc completion. |

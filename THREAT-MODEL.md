# QChain — Threat Model

**Status: DRAFT for internal review. NOT a formal security assessment.**

This document was produced as honest self-documentation by the same
party that wrote most of the code (an LLM-assisted developer, with
the LLM having significant authorship). It should not be treated as
an independent security audit. Its value is in being explicit about
what the project claims to defend against, so that a real external
review has a starting point.

## Scope

This threat model covers the QChain research blockchain as of the
end of the M10 + persistence + hardening + UI-fix + audit-followup
+ M8.9 (depth-20 sparse Merkle) + M-timing (T13 defense) +
property-testing arc.

In scope:

- Post-quantum signatures (Dilithium via reference impl)
- IBM-QRNG-influenced consensus (PoS variant)
- M4 Schnorr-ZK anonymous transactions
- M8.x STARK-anon shielded pool (with M8.11 partial spends)
- M10 mixer layer (depth-20 denomination pool, with M-timing anchor defense)
- P2P gossip + fork resolution
- Persistence (JSON files for chain and wallet)
- Dashboard UI

Out of scope:

- Dilithium itself — assumed correct per NIST PQC standardization
- Winterfell STARK soundness — assumed correct per its public review
- BLAKE3 / SHA-256 / standard hash primitives — assumed pre-image
  resistant and collision-resistant
- Network transport security (TLS, MTLS) — not implemented; out of
  scope for a research demo running on localhost
- Side-channel attacks on cryptographic operations
- Hardware attacks
- Supply-chain attacks on dependencies

## Adversaries

We define five adversary classes. Each entry specifies their
capabilities so individual threat claims can reference them precisely.

### A1: Curious observer

Can read all network traffic, all on-disk chain state, all dashboard
state. Cannot sign valid transactions (no private keys). Cannot mine
blocks. Read-only access.

This is the weakest adversary and the one most privacy claims must
defend against.

### A2: Active network participant

Has all of A1, plus the ability to gossip arbitrary messages to
peers. Can send malformed payloads, forged-but-unsigned messages,
replay messages, withhold messages from selected peers. Cannot
produce valid Dilithium signatures over messages without the
corresponding private key.

This is the canonical "Byzantine peer" adversary.

### A3: Malicious miner

Has all of A2, plus they win some fraction of block-production
rounds (PoW: solve nonces; PoS: be selected by the QRNG-influenced
validator selection). Can include or exclude transactions in their
blocks. Cannot forge other validators' signatures. In PoW, their
mining power is bounded by hash rate; in PoS, by their stake fraction.

### A4: Compromised validator quorum (PoS)

In PoS mode only: an attacker who controls a sufficient fraction of
the stake to influence consensus. Roadmap-noted as a hard problem;
the M3 spec includes single-validator PoS for demo use and does not
defend against a malicious quorum.

### A5: Chain-analysis adversary

A1-equivalent in capabilities, but with significant offline compute
and intent to deanonymize. Can do pattern matching, timing analysis,
amount correlation, anonymity-set partitioning. The threat model
this adversary tests is privacy, not safety.

## Threats and mechanism mapping

The notation `[FORMAL]` means a claim that should follow from the
cryptographic primitives (assuming they're sound). `[HEURISTIC]`
means a claim that depends on parameter choices, network topology,
implementation correctness in ways that aren't formally provable
in our setting. `[NOT DEFENDED]` means the project does not currently
defend against this; the absence is documented or implicit.

### T1: Spending without authorization (transparent)

**Goal:** A1/A2 wants to debit Alice's transparent balance without
her signature.

**Mechanism:** `Transaction.verify()` checks a Dilithium signature
over `(sender, recipient, amount, timestamp, nonce)`. Mining and
fork resolution both reject blocks containing transactions with
invalid signatures.

**Claim:** `[FORMAL]` Under Dilithium's standard EUF-CMA assumption,
A1 cannot produce a valid signature for a sender they don't
control.

**Code:** `qchain/chain/transaction.py:verify()`,
`qchain/crypto/dilithium.py`.

**Tests:** `test_chain.py` covers basic signature verification.

### T2: Double-spending (transparent)

**Goal:** A1 wants to spend the same balance twice.

**Mechanism:** Balances are derived from chain replay. Each block's
transactions are applied to the latest state; insufficient-balance
transactions are rejected at mempool admission and again at block
validation. Fork resolution always converges on the longest valid
chain.

Additionally, `Blockchain.mined_txids: Set[str]` tracks every
mined non-coinbase txid. The same `Transaction` object cannot be
re-submitted after being mined, nor mined into a second block —
both admission and `is_valid` enforce this. This closes a
transparent-tx replay vulnerability found by the property-testing
pass (see [`PROPERTY-TESTING-README.md`](docs/milestones/PROPERTY-TESTING-README.md)).

**Claim:** `[FORMAL]` once a block is finalized in the longest
chain, txs in earlier blocks cannot be replayed against the same
balance because the chain replay accounts for them AND the
`mined_txids` check rejects re-submission/re-mining. `[HEURISTIC]`
during reorg windows, double-spend attempts can succeed if the
attacker's chain wins the fork race.

**Code:** `qchain/chain/blockchain.py` balance derivation + mempool
admission + `_apply_block_state` (mined_txids tracking) + `is_valid`
(replay-side duplicate-txid check).

**Tests:** `test_chain.py` covers basic double-spend rejection;
`test_network.py` covers fork resolution;
`test_properties.py::test_property_resubmit_same_transparent_tx_rejected`
+ two regression tests cover txid replay.

### T3: Coin minting (transparent)

**Goal:** A3 wants to credit themselves without spending input.

**Mechanism:** Block reward is fixed at 10 per block via coinbase.
All other transactions must conserve value (sender balance debited
by amount, recipient credited by amount). Block validation rejects
blocks where coinbase exceeds the allowed reward.

**Claim:** `[FORMAL]` Conservation is enforced by the validation
rule. Coinbase amount is parameter-fixed.

**Code:** `qchain/chain/blockchain.py` coinbase handling.

### T4: Block reward inflation by malicious miner

**Goal:** A3 wants their block to credit them more than 10 coins.

**Mechanism:** Block validation checks the coinbase amount equals
`COINBASE_REWARD`.

**Claim:** `[FORMAL]` if validation is enforced consistently across
all honest nodes.

### T5: Forged block (any node)

**Goal:** A2 wants peers to accept their forged block.

**Mechanism:** Each block contains transactions with their own
Dilithium signatures. Block validation re-verifies all signatures.
PoW blocks require a valid hash with sufficient leading zeros (the
difficulty parameter). PoS blocks require the QRNG-influenced
validator selection to have chosen the block proposer.

**Claim:** `[FORMAL]` PoW forging requires solving the hash puzzle;
PoS forging requires being selected. `[HEURISTIC]` the QRNG step
is influenced but not strictly determined by the IBM Quantum
backend; classical fallback exists.

### T6: STARK pool unauthorized spend

**Goal:** A1/A2 wants to spend a STARK-anon note they don't own.

**Mechanism:** The STARKAnonTransaction includes a STARK proof
attesting to knowledge of `(sk, r, v)` such that
`H(sk, r, v) = leaf` for some leaf in the pool's Merkle tree, and
that `nullifier = H(sk+1, r, v)` is well-formed.

**Claim:** `[FORMAL, MODULO]` Winterfell soundness. If the AIR is
correctly constructed and Winterfell is sound, the only way to
produce a valid proof is to know `(sk, r, v)`. Pre-image
resistance of the leaf hash ensures the prover can't construct
a leaf they don't have secrets for. Forgery would require either
breaking Winterfell or finding a hash collision.

**Code:** `qstark/src/m86_air.rs`, `qchain/chain/anon_stark_tx.py`.

**Tests:** `qstark/tests/m86_soundness.rs` (10 tests),
`qstark/tests/m86_gap_a_soundness.rs` (13 tests),
`qstark/tests/m86_partial_spend_soundness.rs` (11 tests),
plus M8.x integration tests.

### T7: STARK pool double-spend

**Goal:** A1 wants to spend the same STARK-anon note twice.

**Mechanism:** Each spend reveals a nullifier `H(sk+1, r, v)`.
Chain tracks all seen nullifiers; replays at block validation.

**Claim:** `[FORMAL]` distinct spend attempts of the same note
reveal the same nullifier (deterministic from `(sk, r, v)`).
Chain rejects the second attempt.

**Code:** `qchain/chain/blockchain.py:stark_nullifiers`.

**Tests:** covered in m86_soundness.

### T8: STARK pool inflation/destruction

**Goal:** A1 wants to spend a note of value V but credit unshield
+ fee + change-out totaling != V.

**Mechanism:** The AIR enforces `v_in == unshield + fee + v_out`.

**Claim:** `[FORMAL, MODULO]` Winterfell soundness.

**Code:** `qstark/src/m86_air.rs` value-conservation constraint.

**Tests:** `m86_gap_a_soundness.rs` covers gap-A attacks;
`m86_partial_spend_soundness.rs` covers partial-spend attacks.

### T9: STARK pool stale-root attack

**Goal:** A2 gossips a stale STARK-spend proof against an old pool
root after the pool has changed.

**Mechanism:** Proof's public input `merkle_root` is FS-bound.
Chain verifies against current root at apply time. Block validation
checks root match at the block's tx order.

**Claim:** `[FORMAL, MODULO]` Winterfell binding of merkle_root in
the FS transcript.

**Tests:** explicitly covered in m86 soundness suites.

### T10: Mixer pool unauthorized withdraw

**Goal:** Same as T6, applied to mixer pool.

**Mechanism:** Same AIR (m86_air) reused with mapping `v_in =
denomination, unshield = 0, fee = 0, v_out = denomination`. Mixer
nullifiers tracked separately from STARK pool nullifiers.

**Claim:** `[FORMAL, MODULO]` Winterfell soundness — inherited
from T6.

### T11: Mixer pool inflation across denomination boundary

**Goal:** A1 deposits a 1-coin note and withdraws as if it were
a 1000-coin note.

**Mechanism:** AIR enforces `v_in == v_out`. The output_leaf is
`H(sk_out, r_out, v_out)` and is FS-bound. The deposit's leaf is
`H(sk, r, v_in)` where `v_in` was committed at deposit time via
the `MixerDepositTransaction.amount` field (signed).

**Claim:** `[FORMAL]` The constraint catches this directly.

**Tests:** `test_hardening_withdraw_amount.py` covers
denomination-invariant chain state. `test_mixer_soundness.py`
covers explicit inflation attempts.

### T12: Mixer denomination-set partition

**Goal:** A5 wants to know which denomination a withdrawal was at,
to reduce anonymity set.

**Mechanism (after hardening pass):** No `withdraw_amount` field
on `MixerWithdrawTransaction`. Denomination is hidden inside
`output_leaf` via the spender's secrets.

**Claim:** `[HEURISTIC]` A5 cannot directly read the denomination
from the withdrawal. They COULD attempt other attacks (timing,
amount-flow at the chain edge) — see T14.

**Tests:** `test_hardening_withdraw_amount.py` (6 tests) cover
this explicitly.

### T13: Mixer same-block linkability

**Goal:** A5 sees a deposit and a withdrawal in the same block;
they can link depositor to withdrawal.

**Mechanism:** Anchor-root design. Mixer withdrawals must reference
a mixer-tree root from a block at least `MIXER_WITHDRAWAL_DELAY = 5`
blocks old. Withdrawing in the same block as the deposit is
mechanically impossible — the depositor's leaf isn't yet in any
historical root the withdrawal could anchor to. Enforced at both
admission (`submit_mixer_withdraw`) and chain replay (`is_valid`).

**Claim:** `[DEFENDED]` against same-block and within-DELAY-block
linkability. Anchor-root verification is symmetric across all nodes;
the mempool, chain replay, and fork-resolution paths share the same
check.

**Code:** `qchain/chain/blockchain.py::submit_mixer_withdraw` and
the mixer section of `is_valid`. `qchain/chain/blockchain.py` also
maintains `mixer_root_history` as the append-only historical-root
list (`mixer_root_history[i]` = mixer-tree root after block `i`'s
deposits and before its withdrawals).

**Tests:** `test_mixer_timing.py` (8 tests covering anchor age,
root match, history append-only, persistence round-trip).

See [`MIXER-TIMING-README.md`](docs/milestones/MIXER-TIMING-README.md) for the
mechanism's full design and rationale.

### T14: Mixer timing analysis across blocks

**Goal:** A5 correlates deposit time with withdrawal time even
across multiple blocks, linking a depositor to their later
withdrawal via timing patterns rather than the cryptographic
anonymity set.

**Mechanism (partial mitigation):** Two layers of defense compose:

1. **Chain-side deterministic floor (T13 + M-timing):** Mixer
   withdrawals must reference a mixer-tree root from a block at
   least `MIXER_WITHDRAWAL_DELAY = 5` blocks old. This prevents
   trivial same-block linkability (T13) and creates a hard
   minimum wait between deposit and withdrawal.

2. **Wallet-side randomized additional delay (this pass):** The
   wallet's `create_mixer_withdrawal()` attaches a randomized
   `suggested_delay_blocks` ~ Uniform[0,
   `MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX` (=20)] to each
   withdrawal. The caller is expected to hold the withdrawal
   off-chain for that many additional blocks before submitting.
   With the chain-side floor of 5 blocks, total deposit→submit
   wait is uniformly distributed in [5, 25] blocks.

The randomization uses `secrets.randbelow()` (crypto-quality
randomness), not a PRNG.

**Claim:** `[HEURISTIC]` Two-layer defense raises the cost of
naive timing-correlation attacks: an attacker correlating a
specific deposit at block N can no longer assume the matching
withdrawal lands at a specific block; it must search a 20-block
window. The chain-side deterministic floor is `[DEFENDED]` against
same-block and near-same-block linkability (covered separately in
T13). The wallet-side randomization is `[HEURISTIC]` because it
cannot be enforced — an honest user benefits from it; a careless
user might submit immediately and forfeit the protection.

`[NOT DEFENDED]` against:
- A determined statistical attacker who observes many transactions
  over a long window and applies correlation analysis. The 20-block
  randomization widens the attacker's search window but doesn't
  break statistical linkability when the anonymity set is small
  or deposit/withdrawal patterns are otherwise distinctive.
- Network-layer correlation (timing of gossip propagation, IP
  addresses, peer-to-peer connection patterns). Out of scope for
  the mixer-protocol layer; an operational deployment would need
  Tor/I2P-style network anonymity.
- An attacker who controls the wallet code itself (e.g., a
  malicious wallet that ignores the suggested delay).

**Full closure** would require one of: constant-rate decoy traffic
(every block contains background mixer txs to mask real ones),
mix-network protocols (Tor-style multi-step routing of withdrawals
through intermediaries), or decoy-based ZK proofs (Zcash Sapling
"dummy spend" patterns). All three are multi-month research and
explicitly out of scope; see ROADMAP 2.x for the discussion.

**Code:**
- `qchain/chain/mixer_tx.py::MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX`
  (the constant, default 20)
- `qchain/chain/wallet.py::Wallet.create_mixer_withdrawal` (the
  randomization, attaches `suggested_delay_blocks` to the returned
  withdrawal)

**Tests:** `test_t14_randomized_delays.py` — 5 tests covering
range check, deterministic opt-out (`randomize_delay=False`),
distribution non-degeneracy (sanity check on the random source),
serialization isolation (the suggested delay must NOT leak into
the on-chain tx representation), and secure-by-default behavior.

### T15: Mixer DoS via gossip flood

**Goal:** A2 floods the network with invalid mixer withdrawal
proofs to make honest nodes burn CPU on verification.

**Mechanism:** Per-peer per-message-type sliding-window rate limit
in `Node._handle_message`. Tx-class messages (including mixer
withdrawals) are capped at 100/sec/peer; other categories have
their own limits. Messages over the limit are dropped silently
before any signature or proof verification.

**Claim:** `[DEFENDED]` against single-peer floods. An attacker
sending 10k garbage proofs/sec from one peer hits the limiter
after 100 and the other 9,900 are dropped at zero CPU cost. The
defense is rate-limited only by the cost of decoding the message
envelope and checking the type.

`[NOT DEFENDED]` against an attacker who opens N parallel
connections — they get N × 100/sec aggregate. Closing this gap
requires authentication or per-IP connection-rate limits, which
are out of this pass's scope.

**Code:** `qchain/network/rate_limit.py::SlidingWindowRateLimiter`
(primitive), `qchain/network/node.py::_handle_message` (gate),
constants `RATE_LIMIT_TX_PER_SEC`, `RATE_LIMIT_BLOCK_PER_SEC`,
`RATE_LIMIT_SYNC_PER_SEC`, `RATE_LIMIT_HELLO_PER_SEC`.

**Tests:** `test_rate_limit.py::TestNetworkRateLimits` — 4 tests
covering per-peer caps, per-message-type isolation, per-peer
independence, and unknown-type handling. Plus the primitive's
own 8 unit tests in `TestSlidingWindowRateLimiter`.

See [`RATE-LIMITING-README.md`](docs/milestones/RATE-LIMITING-README.md) for the
full design and what's deliberately out of scope.

### T16: M4 anon pool unauthorized spend

**Goal:** A1 wants to spend an M4 anon note they don't own.

**Mechanism:** Schnorr ZK proof of knowledge of (sk, r). Nullifier
tracking.

**Claim:** `[FORMAL]` Under Schnorr soundness and the random
oracle model.

**Code:** `qchain/chain/anon_tx.py`, `qchain/crypto/anon.py`.

**Tests:** `test_anon.py`, `test_shielded.py`.

### T17: M4 anon pool double-spend

**Goal:** Spend the same M4 note twice.

**Mechanism:** Nullifier tracking, same pattern as T7.

**Claim:** `[FORMAL]` deterministic nullifier; second attempt
rejected.

### T18: Persistence corruption

**Goal:** A1 corrupts the on-disk chain file or wallet file.

**Mechanism:** `Blockchain.load()` rebuilds derived state from
blocks, then (T18 closure) calls `is_valid()` on the reconstructed
chain before returning. `is_valid()` re-verifies the hash chain,
PoW for PoW-mined blocks, every transparent signature, every M4
anon-tx against pool state at the moment of inclusion, every shield
tx signature, and every STARK-anon proof against the STARK pool
state at the moment of inclusion. Any corruption that breaks
internal consistency — tampered hash linking, forged signature,
substituted block, fabricated extra block, modified timestamp that
invalidates the PoW puzzle — is caught at load and rejected with a
clear `ValueError`. Wallet load similarly raises on corrupt JSON
and on a wrong passphrase (when encryption is in use).

The `validate=False` opt-out parameter exists for tests that
deliberately work with invalid chain state; the safe default is
`validate=True`.

**Claim:** `[DEFENDED]` against corrupt-but-parseable persistence
files. Any tampering that breaks block-chain integrity, signature
integrity, or STARK proof integrity is caught at load. See
`test_audit_followup.py::test_t18_*` (7 tests).

**Code:** `qchain/chain/blockchain.py::Blockchain.load()` (validate
parameter; calls `is_valid()` by default).

**Tests:** `test_audit_followup.py::test_t18_*` covers malformed
JSON, missing keys, inconsistent block hashes, tampered block
index, clean-chain regression, empty-genesis regression, and the
`validate=False` opt-out path.

**Residual risk:** A file corrupted in a way that produces a
DIFFERENT but still-valid chain (e.g., a malicious replacement with
a genuinely valid alternative history) would not be detected by
`is_valid()` alone — the chain looks fine in isolation. Defending
against that requires out-of-band integrity (file hashes pinned
elsewhere, signed snapshots, etc.), which is operational and out
of scope for this layer.

### T19: Cross-block-format-version persistence

**Goal:** A wallet or chain file saved by one project version is
silently mis-loaded by another, causing data loss or corruption
without an error.

**Mechanism:** All three persistence formats now carry explicit
version tags:

- **Chain JSON**: `version: 2` field (since M-timing). load() rejects
  unknown future versions; legacy version-1 files load with inferred
  version=1 (only mixer-free pre-2 saves load fine — mixer-containing
  pre-2 saves are rejected via is_valid()).
- **Encrypted wallet**: `wallet_format: "encrypted-v1"`. load()
  rejects unknown format strings.
- **Plaintext wallet**: `wallet_format: "plaintext-v1"` (T19
  closure). load() accepts this and the legacy unversioned form
  (backward compat for existing user wallets); rejects unknown
  plaintext-v* versions.

Wallet load() also has field-presence migration safety for
`mixer_notes` / `stark_notes` (added in the persistence pass), so
even WITHIN a version, optional fields can be added without breaking
old saves.

**Claim:** `[DEFENDED]` against silent schema-drift mis-loading.
All three formats refuse unknown future versions at the load
boundary rather than producing a wallet/chain object with
silently-corrupted state. Legacy unversioned plaintext wallet
files continue to load (no break for existing users).

`[NOT DEFENDED]` against:
- A schema change WITHIN the same version number that adds a
  required field without migration code (defensive coding required;
  not enforced by versioning alone)
- Adversarial version-field manipulation (e.g., relabeling a v2
  file as v1 to trick loading; the file would still fail is_valid()
  for the chain or fail to deserialize for the wallet, but the
  failure mode wouldn't be the version-mismatch error)

**Code:**
- `qchain/chain/blockchain.py::PERSISTENCE_VERSION` and `Blockchain.load`
- `qchain/chain/wallet.py::ENCRYPTED_FORMAT_VERSION`,
  `PLAINTEXT_FORMAT_VERSION`, `Wallet.save`, `Wallet.load`

**Tests:**
- `test_audit_followup.py::test_t19_*` — 7 tests covering chain
  version field present, legacy chain loads, future chain version
  rejected, plaintext wallet save includes version, legacy plaintext
  wallet still loads, unknown plaintext version rejected, round-trip
  preserves data
- `test_wallet_encryption.py::test_unknown_format_version_rejected`
  — encrypted-v999 rejection
- `test_wallet_encryption.py::test_legacy_plaintext_format_still_loads`
  — legacy plaintext path

### T20: Replay across networks

**Goal:** A1 takes a tx signed for one network and replays it on
another network that shares the same keypair format.

**Mechanism:** `Blockchain.CHAIN_ID` identifies the network (currently
`"qchain-v1"`). Transactions carry a `chain_id` field that is bound
into the security layer of each tx type:

| Tx type | Binding |
|---------|---------|
| `Transaction` (transparent) | chain_id in `_payload()` → covered by Dilithium signature |
| `ShieldTransaction` | chain_id in `_payload()` → covered by Dilithium signature |
| `MixerDepositTransaction` | chain_id hashed into the signed payload → covered by Dilithium signature |
| `AnonTransaction` (M4) | chain_id is a serialized field; checked at admission |
| `STARKAnonTransaction` | chain_id is a serialized field; checked at admission |
| `MixerWithdrawTransaction` | chain_id is a serialized field; checked at admission |

For Dilithium-signed txs the binding is **cryptographic** — any
post-broadcast tampering with chain_id breaks the signature. For
STARK/Schnorr proof-bearing txs, chain_id is **NOT bound to the
proof** (doing so would require modifying the M86 AIR — explicitly
out of scope this pass; see ROADMAP 3.x for the discussion); it is
checked at chain admission only.

The chain admission path (`Blockchain.submit*`) calls `_check_chain_id`
for every incoming tx: chain_id=None is accepted as legacy (backward
compat for pre-T20 chain files), chain_id equal to `self.CHAIN_ID` is
accepted, anything else is rejected with a clear ValueError.

**Claim:** `[DEFENDED]` against the standard cross-network replay
threat: a tx that was correctly signed for network A is rejected
when submitted to network B. For Dilithium-signed txs this defense
is cryptographic (binding is in the signature). For STARK-bearing
txs it is at the admission layer.

`[NOT DEFENDED]` against:
- An active attacker who modifies the `chain_id` field on a
  STARK-bearing tx after broadcast and re-submits to a different
  network. Such an attacker would also need to re-target to the
  target network's chain_id — which would be caught by THAT
  network's admission check. The carve-out is for the case where
  both the source tx and the target chain id are picked by the
  attacker simultaneously.
- An attacker who can convince a legitimate user to manually re-sign
  the same payload on another chain. Out of scope (social).

**Code:**
- `qchain/chain/blockchain.py::Blockchain.CHAIN_ID` (the identifier)
- `qchain/chain/blockchain.py::Blockchain._check_chain_id` (the helper)
- `qchain/chain/blockchain.py::Blockchain.submit / submit_anon /
  submit_stark_anon / submit_shield / submit_mixer_deposit /
  submit_mixer_withdraw` (the wiring)
- `qchain/chain/transaction.py::Transaction._payload` (the
  cryptographic binding for transparent)
- `qchain/chain/shield_tx.py::ShieldTransaction._payload`
- `qchain/chain/mixer_tx.py::MixerDepositTransaction._payload`
- `qchain/chain/anon_tx.py::AnonTransaction.chain_id` (admission field)
- `qchain/chain/anon_stark_tx.py::STARKAnonTransaction.chain_id`
- `qchain/chain/mixer_tx.py::MixerWithdrawTransaction.chain_id`

**Tests:** `test_t20_chain_id.py` — 12 tests covering cryptographic
binding (signature breaks on mutation), legacy backward compatibility
(chain_id=None still verifies), forged-binding rejection (signing
unbound then claiming binding fails), admission acceptance of
matching/legacy txs, admission rejection of wrong-chain txs across
all 6 tx types, and serialization roundtrip.

### T21: Wallet key compromise

**Goal:** A1 reads a wallet file on disk and gains spending power.

**Mechanism:** Wallet secret key (and shielded-note bookkeeping) is
encrypted at rest by default via `save(path, passphrase=...)`. The
encryption uses argon2id (memory-hard KDF, OWASP 2023 parameters)
plus AES-256-GCM (authenticated cipher). On disk, the encrypted
wallet contains only the KDF parameters, salt, nonce, and
ciphertext — the secret key bytes are not recoverable without the
passphrase.

**Encryption is the default** (wallet-security pass). A bare
`save(path)` with no passphrase raises `ValueError` with a message
explaining what to do. Plaintext is available only via an explicit
opt-out: `save(path, allow_plaintext=True)`. The opt-out parameter
is keyword-only so a positional argument can't accidentally enable
plaintext. Empty-string passphrases (`passphrase=""`) raise the same
error — empty strings aren't passphrases.

`load(path)` auto-detects the format via a `wallet_format` field
and accepts both encrypted (`encrypted-v1`) and legacy plaintext
formats. Existing plaintext wallet files on disk continue to load
without issues — the behavior change only affects new saves.

**Claim:** `[DEFENDED]` by default. An attacker with read access to
a saved wallet file but not to a running process and not to the
passphrase cannot recover the secret key without an exhaustive
search over the passphrase space (rate-limited by argon2id
memory-hardness). Previously this defense required user opt-in;
post-wallet-security pass, the user must explicitly opt OUT to
disable it.

`[NOT DEFENDED]` against:
- Memory-resident attackers (the decrypted key sits in process RAM
  while the wallet is in use)
- Keyloggers or other passphrase-capture attacks
- Trivially weak passphrases (the KDF helps but only so much)
- Users who explicitly invoke the `allow_plaintext=True` opt-out

**Code:** `qchain/chain/wallet.py::save / load /
_encrypt_payload / _decrypt_payload`. The keyword-only
`allow_plaintext` parameter on `save` enforces the secure default.
Constants live at module level (`DEFAULT_KDF_MEMORY_KIB`,
`DEFAULT_KDF_ITERATIONS`, etc.) so they can be tuned without code
changes to the algorithm.

**Tests:** `test_wallet_encryption.py` — 20+ tests covering the
new default-encryption behavior (4 wallet-security-pass tests),
roundtrip, wrong-passphrase rejection, GCM tampering detection,
backward compatibility for loading legacy plaintext, KDF parameter
storage, and unknown-format rejection.

See [`WALLET-KEY-ENCRYPTION-README.md`](docs/milestones/WALLET-KEY-ENCRYPTION-README.md)
for the original threat model, parameter choices, and what's
explicitly out of scope.

### T22: Dashboard endpoint abuse

**Goal:** A1 with HTTP access to the dashboard can call /api/mine,
/api/mixer/deposit, /api/stark/spend etc.

**Mechanism (defense in depth, in order of execution):**

1. **Bearer-token authentication** (FastAPI middleware, runs first).
   All `/api/*` endpoints and the `/ws` WebSocket require a token
   provided as `Authorization: Bearer <token>` header or `?token=...`
   query parameter. Token comparison is constant-time via
   `hmac.compare_digest`. Token can be supplied via `--auth-token`
   CLI flag, `QCHAIN_DASHBOARD_TOKEN` env var, or auto-generated at
   startup and printed to stdout.

2. **Per-IP rate limiting** (runs after auth). POST endpoints capped
   at 5/sec/IP, GET at 50/sec/IP. Configurable.

3. **Default 127.0.0.1 binding** (network-level). Limits reachability
   to the local machine unless the user explicitly opts into a wider
   bind.

**Claim:** `[DEFENDED]` against scripted abuse and unauthorized
access. An attacker without the token gets a clean 401 before any
endpoint work runs (and without consuming rate-limit budget). An
attacker with the token is still rate-limited.

The Authorization-header form is CSRF-immune (the browser does not
auto-send custom headers cross-origin). The query-parameter form
for WebSockets is also CSRF-immune because cross-origin pages can't
read WS responses.

`[NOT DEFENDED]` against:
- A user who shares their token, posts it publicly, or commits it
  to a repository
- An attacker with filesystem read access (the token may be visible
  in `--auth-token` CLI history, `QCHAIN_DASHBOARD_TOKEN` env, or
  the dashboard stdout log)
- Multi-user role-based access (everyone with the token has full
  privileges; there's no read-only / admin split)
- Token rotation, expiry, or refresh-token mechanics — the token
  lives for the dashboard process lifetime
- TLS — the token travels in HTTP cleartext. Production deployments
  should put the dashboard behind a TLS-terminating reverse proxy.

**Code:** `qchain/dashboard/server.py::create_app` auth middleware
plus the `_token_matches`, `_generate_auth_token`,
`_extract_bearer_token` helpers. WebSocket auth check in the
`/ws` endpoint itself.

**Tests:** `test_dashboard_auth.py` — 30 tests covering token
primitives, HTTP API gating (header form, query-param form,
malformed headers, header-precedence-over-query, POST gating),
WebSocket gating, auth-disabled mode, ordering against rate
limiting, and non-API bypass.

See [`DASHBOARD-AUTH-README.md`](docs/milestones/DASHBOARD-AUTH-README.md) for the
full design and what's deliberately out of scope.

### T23: Memory exhaustion via large block

**Goal:** A3 mines a block with so many transactions that honest
nodes OOM.

**Mechanism:** `MAX_BLOCK_TX_COUNT = 10_000` in
`qchain/chain/blockchain.py`. Checked at both the network admission
path (`Node._handle_new_block` — drops oversized blocks before any
chain-side work) and in chain replay (`Blockchain.is_valid`). The
count is the sum across all six tx categories (transparent + anon +
stark-anon + shield + mixer-deposit + mixer-withdraw).

10,000 is ~100× the most a research-demo chain would produce in a
single block. An attacker emitting a 1,000,000-tx block hits both
the admission and replay rejection paths.

**Claim:** `[DEFENDED]` against memory-exhaustion via count. The
constant matches the M8.10 admission-vs-replay-consistency pattern:
both paths enforce the same rule.

`[NOT DEFENDED]` against memory-exhaustion via byte-size if a
caller produces 10,000 unusually large txs. Byte-size limit is a
follow-up; the 10,000-count cap already bounds the worst realistic
case to a few MB.

**Code:** `qchain/chain/blockchain.py::MAX_BLOCK_TX_COUNT` constant,
size check in `is_valid()`, and `qchain/network/node.py::_handle_new_block`
size check.

**Tests:** `test_rate_limit.py::TestMaxBlockSize` — 3 tests covering
rejection by `is_valid` and by admission, and not-rejected-for-size
when the block is under the cap.

## Mechanism inventory

For reference, the cryptographic and protocol mechanisms QChain uses:

| Mechanism | Defends | Tests |
|---|---|---|
| Dilithium-3 signatures | T1, T5 | `test_chain.py`, integration |
| BLAKE3 / SHA-256 hashing | T6, T10 (preimage resistance) | indirect |
| Schnorr ZK | T16, T17 | `test_anon.py` |
| zk-STARK (Winterfell + m86_air) | T6, T7, T8, T9, T10, T11 | 38 Rust soundness tests + integration |
| Nullifier tracking | T7, T17 | covered in pool tests |
| Merkle tree (depth 16) | T6, T10 | included in m86_air |
| Block reward fixed at 10 | T3, T4 | chain tests |
| Longest-chain rule | T2, T5 | network tests |
| FS transcript binding | T9, plus implicit T6, T10 | m86_soundness |

## What's NOT in the project (vs claimed elsewhere)

These are gaps where roadmap aspirations exceed implementation, OR
items now closed by recent passes. Annotated current state:

1. **Anonymity-set delay enforcement (T13).** `[DEFENDED]` via the
   M-timing pass — withdrawals must anchor at least
   MIXER_WITHDRAWAL_DELAY blocks behind the tip, defeating
   same-block linkability.
2. **DoS hardening (T15, T23).** `[DEFENDED]` via ROADMAP 1.5 —
   per-peer per-message-type rate limiting and MAX_BLOCK_TX_COUNT
   cap.
3. **Wallet encryption (T21).** `[DEFENDED]` via ROADMAP 1.4 plus
   the wallet-security pass — argon2id + AES-256-GCM encryption-at-
   rest, NOW THE DEFAULT. Plaintext requires explicit
   `allow_plaintext=True` opt-out. The opt-out parameter is
   keyword-only to prevent accidental positional misuse.
4. **Dashboard auth (T22).** `[DEFENDED]` via the auth pass —
   bearer-token authentication on all `/api/*` and `/ws` endpoints,
   layered with the rate limiting above.
5. **On-load chain validation (T18).** `[DEFENDED]` via the T18-
   closure pass — `Blockchain.load()` now calls `is_valid()` on the
   reconstructed chain before returning. `validate=False` opt-out
   exists for tests.
6. **Version-tagged persistence (T19).** `[DEFENDED]` via the T19-
   closure pass — all three formats (chain JSON, encrypted wallet,
   plaintext wallet) now carry explicit version tags. Unknown
   future versions are rejected at the load boundary. Legacy
   unversioned files continue to load (backward compat).
7. **Cross-network replay (T20).** `[DEFENDED]` via the T20-closure
   pass — chain identifier (`Blockchain.CHAIN_ID = "qchain-v1"`) is
   cryptographically bound into Dilithium-signed tx payloads and
   checked at chain admission for STARK/Schnorr-proof-bearing txs.
   Cryptographic binding for transparent/shield/mixer-deposit;
   admission-only check for anon/stark-anon/mixer-withdraw (proof
   modification deferred as larger work). Legacy unbound txs
   accepted for backward compat.
8. **Mixer timing analysis (T14) partial mitigation.**
   `[HEURISTIC]` via the T14 partial-mitigation pass — the chain
   already enforces a deterministic 5-block minimum delay from
   deposit to withdrawal (T13 + M-timing); the wallet now adds
   a randomized [0, 20]-block extra delay (uniform distribution
   from `secrets.randbelow()`), giving total deposit→submit waits
   in [5, 25] blocks. Honest: this raises the cost of naive timing
   correlation but does NOT defeat statistical analysis over many
   blocks. Full closure (constant-rate decoys, mix nets, decoy-
   based ZK) is multi-month research and out of scope.
9. **No M3 BFT for malicious-quorum PoS (T-ish: A4).** Single-
   validator PoS for demos only. Out of scope for any near-term
   plan.

## What a real auditor would do next

This document is honest self-documentation, not a security audit.
A real audit would:

1. **Independently re-derive the soundness claims for m86_air** from
   the AIR transition constraints and boundary constraints, not
   trust the test suite.
2. **Stress-test Winterfell's binding** of the public inputs we
   rely on (merkle_root, nullifier, output_leaf, unshield, fee).
3. **Differential fuzz** the mixer/STARK boundary against
   adversarial inputs.
4. **Review the network message handlers** for parser-driven
   memory exhaustion and integer overflow.
5. **Threat-model the persistence layer** with respect to local
   adversaries (T18-T21).
6. **Run static analysis** on the Rust AIR for off-by-one and
   integer-cast issues.

The audit-notes document (see `AUDIT-NOTES.md`) catalogs gaps in
test coverage against this threat model and suggests test additions
where they'd be cheap to write and high-value.

# QChain end-to-end demo

A single-command demonstration that the project's working model actually
works. Useful for reviewers, grant evaluators, and anyone who wants to
verify QChain's claims with running code rather than reading specs.

## Run it

From the repo root:

```bash
python -m qchain.demo.end_to_end
```

Expected runtime: 4-5 seconds (most of the time is in STARK proving;
wallet encryption with argon2id KDF takes ~1.5 s).

Output goes to stdout. No arguments, no configuration, no network setup.

## What it demonstrates

The demo runs every major capability of QChain in a single process:

1. **Transparent transactions** — Dilithium post-quantum signatures
   with T20 chain_id binding. Includes a demonstration that a
   transaction targeting a different chain (e.g., `qchain-fake-network`)
   is rejected at admission.

2. **M4 anonymous transactions** — Schnorr proofs over the M4 anon
   pool, with Pedersen commitments for value-hiding and the chain_id
   field on the on-chain serialization.

3. **Shielded (STARK pool) deposits + STARK-anonymous spends** —
   hand-rolled zk-STARKs (Goldilocks AIR via Winterfell, with the
   M86 partial-spend AIR). Demonstrates the M8.11 partial-spend
   feature: a 20-coin note is split into 15 unshielded (to Bob)
   plus 5 change (returned to the spender as a new shielded note).

4. **Mixer deposit + delayed withdrawal** — full T13 chain-side
   deterministic delay (5 blocks minimum) plus T14 wallet-side
   randomized additional delay (uniform [0, 20] blocks). The
   withdrawal proves spend authorization against a historical
   mixer root.

5. **Persistence** — chain save/load with T18 on-load validation.
   Includes a demonstration that a tampered chain file is detected
   and rejected.

6. **Wallet encryption at rest** — T21 (strengthened in the wallet-
   security pass): bare `save(path)` is rejected; encrypted save
   uses argon2id + AES-256-GCM. The on-disk file does not contain
   the secret key in plaintext.

## What it doesn't demonstrate

- **Networking** — the demo is single-process. Multi-node gossip,
  peer authentication, and rate limiting are in the test suite
  (`test_network.py`, `test_rate_limit.py`) but not in this demo.
  Live deployment is a separate concern.

- **Failure paths** — error conditions, edge cases, double-spend
  prevention, etc. are exhaustively tested in the 499-test suite
  but not narrated here.

- **Concurrent activity** — the demo runs each operation
  sequentially. Property-based tests (`test_property_*`) and
  multi-node tests cover concurrent scenarios.

## Reading the output

Each section is bannered with a header and a one-line description of
what it demonstrates. Within a section:

- `>` lines show steps being taken
- `✓` lines show positive results
- `•` lines show supplementary information (numbers, timings, etc.)

The final summary lists which defenses were exercised during the run.

## Caveats

- The demo's `random` content (transaction nonces, fresh keypairs,
  fresh notes, the randomized T14 delay) is genuinely random on each
  run. Two consecutive runs will produce different numbers in the
  output. The structure of the output is the same.

- The demo silently calls `keypair.sign()` once per transaction. On
  most machines this is sub-millisecond; on very slow machines the
  total demo time may stretch beyond 4-5 seconds.

- STARK proving in section 3 takes ~30-70 ms on a typical machine.
  The demo reports the actual timing.

- Wallet encryption uses argon2id with OWASP 2023 parameters
  (~1.3 seconds). This is intentional — the KDF is supposed to be
  expensive to slow down passphrase-guessing attacks.

## Honest scope of the demo

The demo is a smoke test of correctness, not a benchmark or a
production simulation. The numbers it prints (timings, balances,
tree sizes) are real — they come from actual operations — but they
shouldn't be interpreted as production performance.

The fact that the demo runs end-to-end without errors is meaningful:
it means every capability that QChain advertises actually composes
when used together. That's a stronger claim than "all unit tests
pass" because integration bugs (e.g., the T20 save/load round-trip
bug caught during the demo's first run, and now covered by
regression tests) only surface in end-to-end use.

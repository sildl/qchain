# RATE-LIMITING-README

Implementation of ROADMAP item 1.5: per-peer network rate limits,
per-IP dashboard rate limits, and a max-block-size cap. Closes three
threats from [`THREAT-MODEL.md`](../../THREAT-MODEL.md):

- **T15** — Mixer DoS via gossip flood
- **T22** — Dashboard endpoint abuse (partial; still no auth)
- **T23** — Memory exhaustion via large block

Also fixes a pre-existing protocol flake (`test_concurrent_blocks_
resolved_by_extension`) as a side-effect of investigating the rate
limiter's interaction with same-height-fork ping-pong.

## What this pass adds

### A reusable rate-limiter primitive

`qchain/network/rate_limit.py::SlidingWindowRateLimiter` — thread-safe
per-key sliding-window limiter. Constructor takes `capacity` (max
actions per window) and `window_seconds`. One method:
`try_consume(key) -> bool`.

The primitive is small (~80 lines) and reusable for any future
ROADMAP work that needs rate limiting (auth retry caps, audit-log
flood protection, etc.).

### Network per-peer per-message-type rate limits (T15)

`Node._handle_message` now gates every incoming message against a
per-message-type limiter keyed by the peer's `(host, port)` address
string. The limiters and their default capacities (per 1-second window):

| Message types | Limit/sec/peer | Rationale |
|---|---:|---|
| `new_tx`, `new_anon_tx`, `new_stark_anon_tx`, `new_shield_tx`, `new_mixer_deposit`, `new_mixer_withdraw` | 100 | Gossip multiplication can produce honest bursts; well above any human-driven rate |
| `new_block` | 50 | Fork recovery / catch-up bursts up to ~50 blocks/sec/peer |
| `get_blocks`, `blocks` | 50 | Same shape as new_block for sync flows |
| `hello` | 10 | Sent once per handshake; high enough for reconnect cycles |

Messages over the limit are dropped silently before any signature
verification, proof verification, or state-mutation work. A counter
(`Node._rate_limited_drops`) tracks drops for diagnostics.

### Dashboard per-IP per-method rate limits (T22)

FastAPI middleware in `create_app` checks every request to `/api/*`
against a per-`request.client.host` limiter. Two buckets:

| HTTP method | Limit/sec/IP | Rationale |
|---|---:|---|
| POST (action endpoints: /api/mine, /api/stark/spend, etc.) | 5 | Bound the rate at which an attacker can drive the node |
| GET (query endpoints: /api/state, /api/peers, etc.) | 50 | Dashboard polls these; humans can't beat the cap, scripts get throttled |

Configurable via `create_app(rate_limit_action_per_sec=..., ...)` or
environment variables `QCHAIN_DASHBOARD_ACTION_RATE` and
`QCHAIN_DASHBOARD_QUERY_RATE`. Setting to 0 disables the limiter
entirely — used by integration tests that need to issue rapid
sequences.

Over-limit requests get HTTP 429 with a JSON body
`{"error": "rate limit exceeded", "limit": "action"|"query",
"retry_after_seconds": 1.0}` and a `Retry-After` header.

### Max block size cap (T23)

`qchain/chain/blockchain.py::MAX_BLOCK_TX_COUNT = 10_000` checked at
two places, matching the M8.10 admission-vs-replay pattern:

1. **Admission**: `Node._handle_new_block` drops oversized blocks
   before any chain-side work
2. **Replay**: `Blockchain.is_valid()` rejects chains containing
   oversized blocks

The count is summed across all six tx categories (transparent + anon
+ STARK-anon + shield + mixer-deposit + mixer-withdraw). A malicious
miner can't bypass the cap by splitting abuse across categories.

10,000 is ~100× the most any honest chain would produce in a single
block.

### Bonus: protocol fix for same-height-fork ping-pong

When two nodes have competing blocks at the same height, the
pre-existing `_handle_blocks` logic re-requested the full chain
from peers on any failed-to-adopt scenario — including when the
"alternative" chain was the same length as the local chain. This
created an infinite `get_blocks`/`blocks` ping-pong between peers.

The rate limiter exposed this: with the limiter throttling sync
messages, the ping-pong loop saturated the sync rate limit, which
broke `test_concurrent_blocks_resolved_by_extension` deterministically.
Investigation surfaced the underlying inefficiency; the fix is a
one-line check in `_handle_blocks`:

```python
# Only re-request if the alternative is LONGER than our current chain.
# Same-length forks should just wait for the next block to extend one.
if not adopted and len(new_blocks) > 0:
    alt_height = new_blocks[-1].index
    if alt_height > my_height:
        self._request_from_all(from_height=1)
```

This makes the test pass deterministically in ~1 second instead of
flaking with a 6-second timeout. The README's longstanding "gossip
dedup" honest-scope note can come off (or partially come off — the
fix doesn't cover every gossip-multiplication scenario).

## What this pass does NOT do

Listed honestly so callers don't over-trust the mechanism:

- **No authentication.** T22 still needs an auth pass to fully
  close. Rate limiting bounds the blast radius but doesn't prevent
  an attacker from driving operations at the rate-limited rate.
- **No per-IP network limit.** Network limits are per-peer (by
  socket-identified endpoint). An attacker opening N connections
  from N IPs gets N × the per-peer rate. This is the fundamental
  ceiling of per-peer rate limiting.
- **No proof-of-payment.** T15's mitigation note mentioned this as
  an alternative. It would require a fee-burning mechanism — bigger
  scope. Rate limiting is the simpler intervention that handles the
  realistic threat.
- **No byte-size limit on blocks.** Only count is capped. 10,000
  oversized txs would still exceed memory; but the 10,000 cap bounds
  the realistic case to a few MB.
- **No DDoS at the OS level.** SYN floods, connection-rate limits,
  raw bandwidth shaping — all need OS-level tooling, out of scope
  for a Python research demo.
- **No persistence of rate-limit state.** State is per-process. A
  node restart resets all limiters. This is fine for our use case
  (limiters reset to empty windows; honest peers reconnect cleanly).
- **No exponential backoff or progressive penalties.** The limiter
  is binary: under-capacity allowed, over rejected. An attacker
  hitting the limit repeatedly doesn't accrue additional penalties.

## Design notes

### Why sliding window vs. token bucket?

Token-bucket is a more sophisticated rate-limiting algorithm with
better burst handling. We chose sliding-window because:

- The implementation is shorter (~80 lines vs ~150 for an honest
  token-bucket with burst support)
- The semantics are more obvious for the threat model: "N messages
  in any 1-second window"
- Tests are easier to reason about deterministically with explicit
  `now=` timestamps

Token-bucket would be a reasonable upgrade if real production
deployment surfaced specific burst-vs-sustained tradeoffs we don't
currently see.

### Why per-peer not per-IP for the network?

The peer key is the socket's remote endpoint (`host:port`). One IP
opening many sockets gets one bucket per socket. This is the wrong
shape for an internet-facing service but fine for a research demo
where peer endpoints are configured manually.

Per-IP would prevent the "N connections from one IP" multiplication
attack. It also breaks legitimate scenarios where one host runs
multiple node instances behind the same IP.

For QChain's deployment shape (localhost or LAN, manually-configured
peer addresses), per-peer is the right granularity.

### Why GET vs POST split on the dashboard?

GETs are polled by the live dashboard UI; an open dashboard might
hit `/api/state` 10× per second normally. POSTs are driving
actions — a human clicking can't beat 5/sec. The split lets the
dashboard work smoothly under polling while still aggressively
throttling action endpoints.

### Why MAX_BLOCK_TX_COUNT = 10,000?

Order-of-magnitude analysis: the largest single-block in any
QChain test is the property-testing scenarios with ~30 ops, where
each op contributes at most ~1 tx. Real chains might hit hundreds
of txs/block under realistic load. 10,000 is comfortable headroom
above any realistic honest case and well below the levels that
exhaust memory.

A production deployment would tune this based on actual block
size statistics. The constant is one location to change.

### Why is the rate-limit drop silent?

The alternative is to send the peer a "you've been rate-limited"
notification. We chose silent drops because:

- The peer might be honest but bursty; notifying them creates
  back-and-forth that wastes more bandwidth than dropping
- An attacker SEEKS feedback to tune their attack; silence
  forces them to operate blind
- The per-peer counter (`_rate_limited_drops`) gives us local
  visibility for diagnostics

The dashboard DOES return 429 because HTTP clients need to know
they were throttled (browsers retry, etc.). Different layer,
different conventions.

## Implementation

### New file: `qchain/network/rate_limit.py` (~80 lines)

The `SlidingWindowRateLimiter` class. Self-contained, thread-safe,
no external dependencies beyond `collections` and `threading`.

### Modified: `qchain/network/node.py`

- Added module constants for rate limits
- Added `SlidingWindowRateLimiter` import
- Added four limiters in `Node.__init__`: `_rl_tx`, `_rl_block`,
  `_rl_sync`, `_rl_hello`
- Added `_rate_limited_drops` counter
- `_handle_message` now takes `peer_addr` and checks the limiter
- New helper `_limiter_for_type` maps msg_type to limiter
- `_handle_new_block` gained the MAX_BLOCK_TX_COUNT admission check
- `_handle_blocks` gained the same-height-fork ping-pong guard

### Modified: `qchain/chain/blockchain.py`

- Added `MAX_BLOCK_TX_COUNT = 10_000` constant
- `is_valid()` checks total tx count per block against the cap

### Modified: `qchain/dashboard/server.py`

- Added `DASHBOARD_RL_*` constants
- `create_app()` gained `rate_limit_action_per_sec`,
  `rate_limit_query_per_sec`, `rate_limit_window_seconds` parameters
- Added FastAPI middleware that gates `/api/*` requests
- `main()` reads `QCHAIN_DASHBOARD_*_RATE` environment variables

### Modified: `qchain/tests/test_dashboard.py`,
`qchain/tests/test_dashboard_mixer.py`,
`qchain/tests/test_ui_mixer_denomination_display.py`

These call `create_app` or `main()` and would otherwise hit the
rate limit during test execution. Updated to pass
`rate_limit_action_per_sec=0` (disable) or set the corresponding
env var.

### New file: `qchain/tests/test_rate_limit.py` (~340 lines, 22 tests)

Four test classes:

1. **`TestSlidingWindowRateLimiter`** (8 tests): primitive unit tests
   with deterministic `now=` parameters
2. **`TestNetworkRateLimits`** (4 tests): integration via
   `Node._handle_message`
3. **`TestDashboardRateLimits`** (6 tests): TestClient-driven
   end-to-end including 429 response shape
4. **`TestMaxBlockSize`** (3 tests): T23 admission + replay

Plus 1 integration sanity test that low-rate traffic passes through
cleanly.

### Modified: THREAT-MODEL.md

T15, T22, T23 updated from `[NOT DEFENDED]` to `[DEFENDED]` (with
explicit caveats about what's still out of scope for each).

## Test results

| Layer | Pre-1.5 | Post-1.5 |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 245 | **267** (+22 rate-limit tests) |
| **Total** | **376** | **398** |

All green. Runtime impact:
- Rate-limit suite: ~29 seconds (mostly TestClient overhead)
- Existing suite: no regressions; `test_concurrent_blocks_resolved_by_extension`
  is now reliably ~1 second instead of intermittently failing at 6 seconds

## What this gives the project

- Three more T-numbered threats move from `[NOT DEFENDED]` to
  `[DEFENDED]` (with documented caveats for T22)
- A reusable rate-limiter primitive for any future work that
  needs it
- A protocol bug fixed as a side-effect (the same-height-fork
  ping-pong)
- A previously-flaky test now passes deterministically

## What's next

ROADMAP status after this pass:

| Item | Status |
|------|--------|
| 1.1 External audit engagement | Recommended, calendar-bound |
| 1.2 Differential AIR Phase 3 | Open |
| 1.3 Publication writeup | Open |
| 1.4 Wallet key encryption at rest | ✅ Shipped |
| 1.5 Rate limiting / DoS hardening | ✅ Shipped (this pass) |
| 1.6 Persistent wallet shielded-note tracking | Open |

Closest follow-ups:
- **1.6** is the natural next step if continuing through next-up
- **Dashboard authentication** would be a real T22 closure (rate
  limiting is only partial). Would be a new ROADMAP item.

# DASHBOARD-AUTH-README

Bearer-token authentication for the dashboard's HTTP API and
WebSocket. Closes T22 (Dashboard endpoint abuse) in
[`THREAT-MODEL.md`](../../THREAT-MODEL.md) fully — rate limiting
(ROADMAP 1.5) had partially defended; auth removes the "any HTTP
client can drive the node" gap.

## What this is

A FastAPI middleware that requires a bearer token on every
`/api/*` HTTP request, plus a token check on the `/ws` WebSocket
endpoint. Token comparison uses `hmac.compare_digest` for
constant-time semantics.

## What the threat is

T22 says: anyone reachable to the dashboard HTTP port can call
the action endpoints (`/api/mine`, `/api/mixer/withdraw`,
`/api/stark/spend`, etc.). Before this work, the only mitigations
were the default 127.0.0.1 binding (network-level) and the
per-IP rate limit from 1.5 (bounds blast radius).

Realistic scenarios that auth defends against:

- **Same-machine attackers.** A multi-user box, or co-tenant
  containers. The localhost binding is no help against another
  process on the same machine.
- **Accidental wide binding.** Someone types `--host 0.0.0.0` and
  unknowingly exposes the dashboard to the LAN.
- **Port forwarding / SSH tunnels.** User tunnels the dashboard
  for remote viewing; without auth, anyone with the tunnel
  endpoint has full control.
- **Cross-site request forgery from a browser tab.** A malicious
  page can't read a bearer-token-protected API because the browser
  refuses to auto-send the Authorization header cross-origin.

What auth does NOT defend against (listed honestly so users don't
over-trust the mechanism):

- A user who shares their token, posts it publicly, or commits it
  to a repository
- An attacker with filesystem read access (the token may be in
  shell history, environment, or stdout logs)
- A keylogger or memory-resident attacker
- Multi-user role-based access (everyone with the token has full
  privileges; there's no read-only / admin split)
- Token rotation, expiry, or refresh tokens — the token lives for
  the dashboard process lifetime
- TLS — the token travels in HTTP cleartext. Production
  deployments should put the dashboard behind a TLS-terminating
  reverse proxy.

## Design choices

### Why bearer token, not password+session?

Options considered:

1. **Bearer token (chosen).** Simple, stateless, no password
   hashing needed. CSRF-immune via the Authorization header.
2. **Username/password with session cookie.** Requires login UI,
   session storage, password hashing, CSRF token. Significant
   scope; the dashboard is a research demo, not a multi-user
   webapp.
3. **HTTP Basic Auth.** Browser-handled; no logout; awkward
   credential caching.
4. **Localhost-only enforcement (no auth).** Doesn't defend
   against same-machine threats — the original T22 concern.

Bearer token is the right answer for a single-user research
dashboard: it defends against the realistic scenarios without
requiring infrastructure (password hashing, session management,
CSRF protection) that would dwarf the rest of the dashboard.

### Token source resolution

When the dashboard starts via `main()`, the token comes from:

1. **`--auth-token <token>`** CLI flag (explicit, scriptable). Pass
   `--auth-token disabled` to disable auth entirely (only safe on
   trusted-localhost-only deployments).
2. **`QCHAIN_DASHBOARD_TOKEN`** environment variable (deploy-
   friendly). Empty string disables auth.
3. **Auto-generated and printed to stdout.** If neither of the
   above is set, the dashboard generates a fresh
   `secrets.token_urlsafe(32)` token and prints it prominently
   along with a copy-pasteable URL containing the token as a
   query parameter.

This gives three usability modes:

- **Zero config.** Just run the server, copy the URL from stdout,
  paste into a browser. Token rotates each restart.
- **Pinned token.** Set `QCHAIN_DASHBOARD_TOKEN` once; it survives
  restarts. Useful for bookmarks.
- **Trusted localhost.** Disable auth entirely with `--auth-token
  disabled` or empty env. Same as pre-T22 behavior.

### Two channels: header vs. query parameter

The middleware accepts the token from either:

- **`Authorization: Bearer <token>`** header (preferred — CSRF-
  immune because browsers don't auto-send custom headers
  cross-origin)
- **`?token=<token>`** query parameter (fallback — needed for the
  WebSocket path because browser WS APIs can't set custom headers,
  and useful for bookmarkable URLs that need to authenticate the
  initial page load)

When both are present, the header wins. Test:
`test_header_takes_precedence_over_query`.

### Constant-time comparison

`_token_matches` wraps `hmac.compare_digest` so two presented
tokens of equal length compare in constant time. The wrapper also
handles unequal-length inputs (which would otherwise leak length
information through the time the comparison takes) by returning
False immediately when either side is empty or None.

The exception message returned on auth failure is intentionally
vague ("authentication required") — it doesn't say "wrong token"
vs. "no token", so an attacker can't distinguish "no Authorization
header" from "wrong token" via response shape.

### Middleware ordering

FastAPI middleware runs LIFO (last added → first executed). The
auth middleware is added AFTER the rate-limit middleware, so it
runs BEFORE the rate limiter. This means:

- An unauthenticated request gets 401 without consuming any
  rate-limit budget.
- A legitimate user's rate budget can't be exhausted by an
  attacker spamming unauthenticated requests.

Test: `test_unauth_requests_do_not_consume_rate_budget` — 100
unauthenticated requests are all 401'd, then a single
authenticated request still succeeds (rate budget intact).

Authenticated traffic IS still rate-limited. Test:
`test_authenticated_traffic_still_rate_limited`.

### Non-API paths bypass auth

The `/` index page (and any future static assets) is served
without auth. Reason: the user needs to be able to land on the
dashboard with the token in the URL query string and have the JS
read it. If `/` required auth, the user would face a chicken-and-
egg problem.

The index page is just static HTML/JS — there's nothing sensitive
on it. The JS does need to send the token on subsequent API calls.
The dashboard HTML is read-only without API calls; an unauthenticated
browser landing on `/` sees an empty/error state.

### WebSocket auth via query parameter

Browser WebSocket APIs (the standard `new WebSocket(url)`) cannot
set custom HTTP headers on the upgrade request. The Authorization
header form thus doesn't work for the dashboard's `/ws` endpoint.

The token goes in the URL: `ws://host:port/ws?token=<token>`. The
WebSocket endpoint checks `websocket.query_params.get("token")`
and rejects with WS close code 1008 (policy violation) if it
doesn't match.

Trade-off: query-parameter tokens may appear in server access logs
or browser history. This is a known limitation of browser WS
APIs; if logging is sensitive, configure the reverse proxy /
access log filter to redact `?token=`.

## File format

There is no file format — the token is in-memory only. It either:

- Comes from a CLI flag (process arg)
- Comes from an environment variable
- Is auto-generated at process start and printed to stdout

The token doesn't persist across dashboard restarts unless the
user pins it via env var.

## What's NOT in this pass

- **Token rotation.** Once auto-generated or set, the token is
  immutable for the process lifetime. Rotating means restart.
- **Token expiry.** No TTL.
- **Refresh tokens.** Single-token model.
- **Multi-user accounts.** One token, one privilege level.
- **Role-based access (read-only vs admin).** All authenticated
  users have full privileges.
- **Password hashing.** The token is the secret; it's compared
  directly via constant-time compare_digest. No KDF / hash chain.
- **TLS.** Plain HTTP. Use a reverse proxy.
- **Logging of auth failures.** No audit trail of who tried to
  authenticate. Could be added for diagnostics.
- **Cookie-based session auth.** Would require login form, CSRF
  token, session expiry — significant scope.
- **OAuth, OIDC, SAML, mTLS.** Enterprise auth flavors out of
  scope for a single-user research demo.

## Test coverage

`test_dashboard_auth.py` — 30 tests in 6 categories:

| Category | Tests | What's verified |
|---|---:|---|
| Token primitive (`_token_matches`) | 5 | Equal/unequal/different-length/None/empty |
| Token generation | 3 | Length, uniqueness across 100 calls, URL-safety |
| Token extraction | 4 | Header form, query form, missing, case-insensitive "Bearer" |
| HTTP API gating | 7 | No-token 401, wrong-token 401, malformed-header 401, correct header 200, correct query 200, POST gating, header-precedence |
| Non-API bypass | 2 | Index page no-auth, index with token still works |
| Auth disabled | 3 | None disables, empty disables, garbage tokens ignored |
| Auth + rate-limit order | 2 | Unauth doesn't consume budget, authenticated still rate-limited |
| WebSocket gating | 4 | No-token rejected, wrong-token rejected, correct-token accepted, disabled bypasses |

Runtime: ~1 second total. The WS tests use FastAPI's TestClient
WebSocket helper.

## Test results

| Layer | Pre-auth | Post-auth |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 282 | **312** (+30 auth tests) |
| **Total** | **413** | **443** |

All green. No regressions in any existing test suite. One
integration test file (`test_dashboard.py`) gained an env-var line
disabling auth, analogous to how it already disables rate limiting.

## What changed in the repo

| File | Change |
|---|---|
| `qchain/dashboard/server.py` | +~150 lines: `_generate_auth_token`, `_token_matches`, `_extract_bearer_token`, auth middleware, WS auth check, `auth_token` parameter on `create_app`, CLI flag and env-var resolution in `main` |
| `qchain/tests/test_dashboard_auth.py` | New file, 30 tests |
| `qchain/tests/test_dashboard.py` | One env-var line to disable auth (analogous to existing rate-limit disable) |
| `qchain/THREAT-MODEL.md` | T22 updated from partial to `[DEFENDED]`; honest-scope summary at the bottom updated for current state of T13/T15/T21/T22/T23 |
| `qchain/DASHBOARD-AUTH-README.md` | This document |

No changes to:
- The chain protocol, network layer, or wallet
- Existing dashboard endpoint signatures or response shapes
- Rate limiting behavior (just runs after auth now)
- Wallet encryption (T21 already shipped in 1.4)

## Backward compatibility

`auth_token=None` is the default for `create_app`. Existing callers
that don't pass the parameter get the legacy unauthenticated
behavior. All 282 pre-auth tests pass without modification.

The `main()` entry point auto-generates a token when run interactively,
so the out-of-the-box dashboard experience changes — but the user
sees the token printed prominently and can either copy-paste the URL
or pin a token via env var. For tests, the env var is set to empty
to disable auth.

## What this gives the project

- T22 fully closes from partial-defense to `[DEFENDED]`
- The combined defense-in-depth pattern (auth → rate limit → handler)
  matches how production web services are typically secured
- A small, reusable bearer-token primitive (`_token_matches`,
  `_extract_bearer_token`) that future auth-requiring endpoints
  can reuse
- The honest-scope summary at the bottom of THREAT-MODEL is now
  current with the actual state of multiple recently-closed threats

## What's next

ROADMAP status after this pass:

| Item | Status |
|------|--------|
| 1.1 External audit engagement | Recommended; requires budget |
| 1.2 Differential AIR Phase 3 | Open, low expected ROI |
| 1.3 Publication writeup | Open |
| 1.4 Wallet key encryption at rest | ✅ Shipped |
| 1.5 Rate limiting / DoS hardening | ✅ Shipped |
| 1.6 Persistent wallet shielded-note tracking | ✅ Shipped |
| (this pass) Dashboard auth (closes T22 fully) | ✅ Shipped |

All originally-planned next-up items are done. THREAT-MODEL's
remaining `[NOT DEFENDED]` items are honest scope limitations
(M3 BFT, T18 on-load validation, T19 schema versioning) rather
than gaps the current scope intends to fix.

The strong recommendation continues: **stop adding code; engage
external eyes.** The codebase has 443 tests, 36 markdown
documents, and a self-disclosed track record of finding and
fixing its own debts. The marginal value of further internal
hardening is much lower than the marginal value of an actual
external auditor reviewing the protocol design.

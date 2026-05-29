"""Tests for dashboard bearer-token authentication.

Closes T22 (Dashboard endpoint abuse) in THREAT-MODEL fully — rate
limiting (ROADMAP 1.5) already partially defended; auth removes the
"any HTTP client can drive the node" gap.

Test categories:
  1. Auth primitive (`_token_matches`, `_generate_auth_token`,
     `_extract_bearer_token`)
  2. HTTP API auth gating — no token, wrong token, header form,
     query-param form
  3. WebSocket auth gating
  4. Auth-disabled mode (legacy behavior + integration test bypass)
  5. Interaction with rate limiter — auth runs first
  6. Non-API paths bypass auth

Honest scope: the tests verify the MECHANISM is wired up correctly,
not that bearer tokens are sufficient against every threat model.
See DASHBOARD-AUTH-README.md for what's deliberately out of scope
(token rotation, multi-user, role-based access, TLS, etc.).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from qchain.dashboard.server import (
    _extract_bearer_token,
    _generate_auth_token,
    _token_matches,
    create_app,
    Dashboard,
)
from qchain.network.node import Node


# ---------------------------------------------------------------------------
# 1. Auth primitive functions
# ---------------------------------------------------------------------------

class TestTokenMatches:
    def test_equal_strings_match(self):
        assert _token_matches("abc123", "abc123") is True

    def test_unequal_strings_do_not_match(self):
        assert _token_matches("abc123", "abc124") is False

    def test_different_lengths_do_not_match(self):
        """Different-length tokens never match — important because
        compare_digest only works on equal-length inputs at byte level.
        Our wrapper handles unequal-length without leaking info via
        exception type or timing."""
        assert _token_matches("short", "shortlonger") is False
        assert _token_matches("shortlonger", "short") is False

    def test_none_does_not_match(self):
        """A missing token (None) is never a match, even against an
        empty expected. Defensive against passing through unset state."""
        assert _token_matches(None, "any") is False

    def test_empty_string_does_not_match(self):
        """Empty presented token is rejected. An attacker sending an
        empty Authorization should not be treated as authenticated."""
        assert _token_matches("", "any") is False


class TestGenerateAuthToken:
    def test_generated_token_is_long_enough(self):
        """token_urlsafe(32) produces ~43 url-safe chars. Below 32 is
        suspicious (insufficient entropy for any realistic threat)."""
        for _ in range(10):
            t = _generate_auth_token()
            assert len(t) >= 32, f"token too short: {len(t)}"

    def test_generated_tokens_are_unique(self):
        """Each call returns a different token. Pulls from os.urandom
        via `secrets`; collision in 100 trials is astronomically
        unlikely."""
        tokens = {_generate_auth_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_generated_token_is_url_safe(self):
        """Token can be placed in a URL query parameter without escaping.
        secrets.token_urlsafe guarantees this; we verify it stays true."""
        import string
        url_safe = set(string.ascii_letters + string.digits + "-_")
        for _ in range(10):
            t = _generate_auth_token()
            assert set(t).issubset(url_safe), f"non-URL-safe chars: {set(t) - url_safe}"


# ---------------------------------------------------------------------------
# 2. HTTP API auth gating
# ---------------------------------------------------------------------------

def _make_app(auth_token=None, action_rate=0, query_rate=0):
    """Build a dashboard TestClient with optional auth + rate limit
    disabled. action_rate/query_rate=0 disables rate limiting."""
    node = Node(host="127.0.0.1", port=0, node_id="authtest")
    dash = Dashboard(node)
    app = create_app(
        dash,
        rate_limit_action_per_sec=action_rate,
        rate_limit_query_per_sec=query_rate,
        auth_token=auth_token,
    )
    return TestClient(app)


class TestApiAuthGating:
    """When `auth_token` is set, /api/* endpoints require the token."""

    def test_no_auth_header_returns_401(self):
        client = _make_app(auth_token="secret-token")
        r = client.get("/api/state")
        assert r.status_code == 401
        body = r.json()
        assert body["error"] == "authentication required"

    def test_wrong_token_returns_401(self):
        client = _make_app(auth_token="secret-token")
        r = client.get("/api/state", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_malformed_authorization_header_returns_401(self):
        """Authorization header that isn't `Bearer <token>` is rejected."""
        client = _make_app(auth_token="secret-token")
        r = client.get(
            "/api/state",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},  # base64 user:pass
        )
        assert r.status_code == 401

    def test_correct_token_in_header_returns_200(self):
        client = _make_app(auth_token="secret-token")
        r = client.get(
            "/api/state", headers={"Authorization": "Bearer secret-token"},
        )
        assert r.status_code == 200

    def test_correct_token_in_query_param_returns_200(self):
        """Query-param token works (the WS path needs this, and bookmarkable
        URLs benefit from it too)."""
        client = _make_app(auth_token="secret-token")
        r = client.get("/api/state?token=secret-token")
        assert r.status_code == 200

    def test_post_endpoint_also_requires_auth(self):
        """Verify auth gating applies to POSTs, not just GETs."""
        client = _make_app(auth_token="secret-token")
        # No token → 401
        r = client.post("/api/peers/connect", json={"host": "127.0.0.1", "port": 1})
        assert r.status_code == 401
        # With token → reaches handler (any status code except 401 is fine)
        r = client.post(
            "/api/peers/connect",
            json={"host": "127.0.0.1", "port": 1},
            headers={"Authorization": "Bearer secret-token"},
        )
        assert r.status_code != 401

    def test_header_takes_precedence_over_query(self):
        """When BOTH a header and a query param are present, the header
        wins. This matches HTTP convention (Authorization is the
        authoritative auth channel)."""
        client = _make_app(auth_token="real-token")
        # Header is right, query is wrong → succeeds
        r = client.get(
            "/api/state?token=wrong",
            headers={"Authorization": "Bearer real-token"},
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 3. Non-API paths bypass auth
# ---------------------------------------------------------------------------

class TestNonApiPathsBypass:
    """Auth only protects /api/* — the index page and any future static
    assets are served without auth so the user can land on the dashboard
    with a token in the URL."""

    def test_index_page_no_auth_required(self):
        client = _make_app(auth_token="secret-token")
        r = client.get("/")
        assert r.status_code == 200

    def test_index_with_query_token_works(self):
        """User can bookmark the dashboard URL with their token; the
        page still loads regardless."""
        client = _make_app(auth_token="secret-token")
        r = client.get("/?token=secret-token")
        assert r.status_code == 200
        # And with wrong token still works (index isn't gated)
        r = client.get("/?token=wrong")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 4. Auth-disabled mode (legacy behavior)
# ---------------------------------------------------------------------------

class TestAuthDisabled:
    """When `auth_token` is None or empty, auth is disabled — the legacy
    behavior. Tests, trusted-localhost deployments, etc. use this."""

    def test_auth_token_none_disables_auth(self):
        client = _make_app(auth_token=None)
        r = client.get("/api/state")
        assert r.status_code == 200

    def test_auth_token_empty_string_disables_auth(self):
        """Empty token is treated as None — auth disabled. This matches
        the rate-limit-disable-on-zero pattern from 1.5."""
        client = _make_app(auth_token="")
        r = client.get("/api/state")
        assert r.status_code == 200

    def test_disabled_auth_ignores_any_token_value(self):
        """When auth is off, even an obviously-wrong Authorization
        header doesn't cause rejection. The middleware bypass is total."""
        client = _make_app(auth_token=None)
        r = client.get(
            "/api/state", headers={"Authorization": "Bearer garbage"},
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 5. Auth + rate limit interaction
# ---------------------------------------------------------------------------

class TestAuthRateLimitOrder:
    """Auth middleware should run BEFORE rate-limit middleware. An
    unauthenticated request should get 401 without consuming any
    rate-limit budget. This means an attacker without the token can't
    exhaust a legit user's rate budget."""

    def test_unauth_requests_do_not_consume_rate_budget(self):
        """Send 100 unauthenticated requests; then send one authenticated
        request — it should succeed (rate budget not exhausted)."""
        # 5 query/sec — would be obliterated by 100 hits if rate limit ran first
        client = _make_app(auth_token="real", action_rate=0, query_rate=5)
        for _ in range(100):
            r = client.get("/api/state")
            assert r.status_code == 401, (
                f"expected 401 (auth before rate-limit), got {r.status_code}"
            )
        # Now authenticated — should succeed within the rate-limit window
        r = client.get("/api/state", headers={"Authorization": "Bearer real"})
        assert r.status_code == 200, (
            "auth should run before rate limit; rate budget intact for legit requests"
        )

    def test_authenticated_traffic_still_rate_limited(self):
        """Auth doesn't bypass rate limiting — once you're authenticated,
        the rate limit still applies. (Otherwise an authenticated
        attacker could trivially DoS.)"""
        client = _make_app(auth_token="real", action_rate=0, query_rate=3)
        headers = {"Authorization": "Bearer real"}
        for _ in range(3):
            r = client.get("/api/state", headers=headers)
            assert r.status_code == 200
        # 4th hits the rate limit
        r = client.get("/api/state", headers=headers)
        assert r.status_code == 429


# ---------------------------------------------------------------------------
# 6. WebSocket auth
# ---------------------------------------------------------------------------

class TestWebSocketAuth:
    """The WebSocket path can't use Authorization headers (browser API
    limitation), so it accepts the token via ?token=<...> query param.

    `TestClient.websocket_connect` raises on connection rejection — we
    detect auth failure via the exception."""

    def test_websocket_requires_token_when_auth_enabled(self):
        from starlette.websockets import WebSocketDisconnect
        client = _make_app(auth_token="real")
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws"):
                pass  # should not reach here

    def test_websocket_with_wrong_token_rejected(self):
        from starlette.websockets import WebSocketDisconnect
        client = _make_app(auth_token="real")
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws?token=wrong"):
                pass

    def test_websocket_with_correct_token_accepted(self):
        client = _make_app(auth_token="real")
        with client.websocket_connect("/ws?token=real") as ws:
            # Connection succeeded if we got this far. The server sends
            # a snapshot first; receive it to confirm liveness.
            msg = ws.receive_json()
            assert msg["type"] == "snapshot"

    def test_websocket_no_auth_when_disabled(self):
        """When auth is off, WebSocket connections succeed without
        any token, matching the legacy behavior."""
        client = _make_app(auth_token=None)
        with client.websocket_connect("/ws") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "snapshot"


# ---------------------------------------------------------------------------
# 7. _extract_bearer_token helper
# ---------------------------------------------------------------------------

def test_extract_bearer_token_from_header():
    """The Authorization header form is preferred (CSRF-immune)."""
    # Build a fake Request via Starlette's helpers
    from starlette.requests import Request
    scope = {
        "type": "http",
        "headers": [(b"authorization", b"Bearer my-token-123")],
        "query_string": b"",
    }
    req = Request(scope)
    assert _extract_bearer_token(req) == "my-token-123"


def test_extract_bearer_token_from_query():
    """Query-param fallback for clients that can't set headers (browsers
    opening a WS, bookmarked URLs)."""
    from starlette.requests import Request
    scope = {
        "type": "http",
        "headers": [],
        "query_string": b"token=qparam-token",
    }
    req = Request(scope)
    assert _extract_bearer_token(req) == "qparam-token"


def test_extract_bearer_token_returns_none_when_missing():
    from starlette.requests import Request
    scope = {
        "type": "http",
        "headers": [],
        "query_string": b"",
    }
    req = Request(scope)
    assert _extract_bearer_token(req) is None


def test_extract_bearer_token_case_insensitive_bearer():
    """'Bearer' should match regardless of case ('bearer', 'BEARER').
    HTTP scheme names are case-insensitive per RFC 7235."""
    from starlette.requests import Request
    for variant in ("Bearer", "bearer", "BEARER", "BeArEr"):
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"{variant} my-token".encode())],
            "query_string": b"",
        }
        req = Request(scope)
        assert _extract_bearer_token(req) == "my-token", (
            f"failed for variant {variant!r}"
        )

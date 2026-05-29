"""Periodic mining trigger for live QChain deployments.

Runs in the background, hits POST /api/mine on a dashboard endpoint
every N seconds. Used in deployed networks so the chain produces
blocks at a steady rate without requiring manual interaction.

Usage:
    python -m qchain.tools.auto_mine \\
        --target http://127.0.0.1:8101 \\
        --interval 15 \\
        --auth-token "$QCHAIN_DASHBOARD_TOKEN"

If --auth-token is omitted, falls back to the QCHAIN_DASHBOARD_TOKEN
env var. If both are unset, requests go without auth header (works
only if the dashboard was started with auth disabled).

This is an operational tool, not part of the chain's correctness
layer. It just drives activity via the public API. The dashboard's
existing auth (T22) is what protects /api/mine from unauthorized
callers — the auto-miner is just one such authorized caller.

Honest scope: no fancy retry strategy, no exponential backoff, no
metrics export. If the dashboard is briefly down, we log the error
and move on. If the dashboard is down for a long time, systemd's
service-restart policy is what handles it (see
deploy/systemd/qchain-automine.service).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def mine_once(
    target: str,
    auth_token: str | None,
    timeout_seconds: float,
) -> tuple[bool, str]:
    """POST {} to <target>/api/mine. Returns (success, message).

    On success, message is a brief description of the mined block.
    On failure, message is an error description.
    """
    url = f"{target.rstrip('/')}/api/mine"
    body = b"{}"
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            data = resp.read()
            try:
                payload = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                return True, f"mined (unparseable response: {data[:80]!r})"
            # Block summary shape: {'index': N, 'hash': '...', 'tx_count': K, ...}
            idx = payload.get("index", "?")
            tx_count = payload.get("tx_count", "?")
            return True, f"mined block #{idx} ({tx_count} txs)"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"network: {e.reason}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def main() -> int:
    p = argparse.ArgumentParser(description="Periodic mining trigger")
    p.add_argument(
        "--target",
        default="http://127.0.0.1:8101",
        help="Dashboard base URL (default: http://127.0.0.1:8101)",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=15.0,
        help="Seconds between mining attempts (default: 15)",
    )
    p.add_argument(
        "--auth-token",
        default=None,
        help="Bearer token. Falls back to QCHAIN_DASHBOARD_TOKEN env var.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout per request (default: 10s)",
    )
    p.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="Exit after this many consecutive failures (0 = run forever).",
    )
    args = p.parse_args()

    token = args.auth_token or os.environ.get("QCHAIN_DASHBOARD_TOKEN") or None

    print(f"qchain-automine: target={args.target} interval={args.interval}s "
          f"auth={'set' if token else 'none'}", flush=True)

    consecutive_failures = 0
    blocks_mined = 0
    started_at = time.time()

    while True:
        ok, msg = mine_once(args.target, token, args.timeout)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        if ok:
            blocks_mined += 1
            consecutive_failures = 0
            print(f"[{ts}] OK: {msg} (lifetime: {blocks_mined} blocks "
                  f"in {time.time() - started_at:.0f}s)", flush=True)
        else:
            consecutive_failures += 1
            print(f"[{ts}] FAIL ({consecutive_failures} in a row): {msg}",
                  flush=True, file=sys.stderr)
            if args.max_failures and consecutive_failures >= args.max_failures:
                print(f"[{ts}] giving up after {consecutive_failures} "
                      f"consecutive failures", flush=True, file=sys.stderr)
                return 1
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

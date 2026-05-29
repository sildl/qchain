"""Tests for milestone 7: dashboard backend.

These are integration tests that boot the FastAPI app in a background
thread and exercise it via HTTP/WebSocket. Run with:
    python -m qchain.tests.test_dashboard
"""

import asyncio
import json
import socket
import threading
import time
from urllib.request import Request, urlopen


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


_started_servers = []


def _start_server(node_id: str, p2p_port: int, http_port: int, peer: str | None = None):
    """Boot a dashboard server in a daemon thread. Returns the http port."""
    # ROADMAP 1.5: disable dashboard rate limits during this integration test.
    # The test issues rapid GET+POST sequences that would hit the production
    # 5/sec POST limit; rate limiting is exercised by test_dashboard_rate_limit.py.
    # Dashboard auth (follow-up to 1.5): empty token = disabled; auth is
    # exercised by test_dashboard_auth.py.
    import os
    os.environ["QCHAIN_DASHBOARD_ACTION_RATE"] = "0"
    os.environ["QCHAIN_DASHBOARD_QUERY_RATE"] = "0"
    os.environ["QCHAIN_DASHBOARD_TOKEN"] = ""

    def run():
        import sys
        sys.argv = [
            "server", "--node-id", node_id,
            "--port", str(p2p_port), "--http", str(http_port),
            "--host", "127.0.0.1",
        ]
        if peer:
            sys.argv += ["--peer", peer]
        from qchain.dashboard.server import main
        main()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    _started_servers.append((node_id, http_port))
    # Wait for HTTP to come up
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            urlopen(f"http://127.0.0.1:{http_port}/api/state", timeout=0.2).read()
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"server {node_id} didn't start")


def _get(http_port: int, path: str):
    return json.loads(urlopen(f"http://127.0.0.1:{http_port}{path}").read())


def _post(http_port: int, path: str, body: dict):
    req = Request(
        f"http://127.0.0.1:{http_port}{path}",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body).encode(),
    )
    return json.loads(urlopen(req).read())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_serves_index_page():
    p2p, http = _free_port(), _free_port()
    _start_server("solo", p2p, http)
    html = urlopen(f"http://127.0.0.1:{http}/").read().decode()
    assert "QChain Dashboard" in html
    assert "react" in html.lower()
    print("  ✓ Serves the HTML page")


def test_state_endpoint():
    p2p, http = _free_port(), _free_port()
    _start_server("alpha", p2p, http)
    state = _get(http, "/api/state")
    assert state["node_id"] == "alpha"
    assert state["height"] == 0
    assert state["anon_pool_size"] == 0
    assert state["nullifier_count"] == 0
    assert "miner_address" in state
    print("  ✓ /api/state returns correct snapshot")


def test_mine_endpoint():
    p2p, http = _free_port(), _free_port()
    _start_server("mine-test", p2p, http)
    block = _post(http, "/api/mine", {"use_pos": False})
    assert block["index"] == 1
    state = _get(http, "/api/state")
    assert state["height"] == 1
    assert state["miner_balance"] == 10.0  # one block reward
    print("  ✓ /api/mine produces and applies a block")


def test_pos_mine_endpoint():
    p2p, http = _free_port(), _free_port()
    _start_server("pos-test", p2p, http)
    block = _post(http, "/api/mine", {"use_pos": True})
    assert "|qrng=" in block["proposer"]
    print("  ✓ /api/mine with use_pos=True uses QRNG proposer")


def test_shield_endpoint():
    p2p, http = _free_port(), _free_port()
    _start_server("shield-test", p2p, http)
    resp = _post(http, "/api/anon/shield", {"amount": 5})
    assert "txid" in resp
    state = _get(http, "/api/state")
    assert len(state["anon_mempool"]) == 1
    # Mine it in
    _post(http, "/api/mine", {"use_pos": False})
    state2 = _get(http, "/api/state")
    assert state2["anon_pool_size"] == 1
    print("  ✓ /api/anon/shield queues and persists anon tx")


def test_stark_shield_endpoint():
    """M8.7-D: shielding to the STARK pool now goes through a signed
    on-chain ShieldTransaction. The shield enters the mempool first
    and only populates the pool when mined.
    """
    p2p, http = _free_port(), _free_port()
    _start_server("stark-shield", p2p, http)

    state0 = _get(http, "/api/state")
    assert state0["stark_pool_size"] == 0
    assert state0["owned_stark_notes"] == []

    # Mine a block first to fund the dashboard's miner_wallet.
    # Block reward is 10, so we need 8 blocks to shield 75.
    for _ in range(8):
        _post(http, "/api/mine", {"use_pos": False})

    resp = _post(http, "/api/stark/shield", {"value": 75})
    assert "txid" in resp
    assert resp["value"] == 75
    assert "depositor" in resp  # the miner_wallet address that signed

    # After shield submission but before mining: the tx is in the
    # shield mempool, not yet in the pool.
    state_pending = _get(http, "/api/state")
    assert state_pending["stark_pool_size"] == 0
    # The note IS already tracked locally so the user can spend it
    # post-mining without re-discovering its position.
    assert len(state_pending["owned_stark_notes"]) == 1
    assert state_pending["owned_stark_notes"][0]["value"] == 75

    # Mine the shield into a block
    _post(http, "/api/mine", {"use_pos": False})
    state_after = _get(http, "/api/state")
    assert state_after["stark_pool_size"] == 1
    print("  ✓ /api/stark/shield submits signed shield tx, mining populates pool")


def test_stark_spend_endpoint():
    """M8.7-D: end-to-end fund → shield → mine → spend → mine flow."""
    p2p, http = _free_port(), _free_port()
    _start_server("stark-spend", p2p, http)

    # Mine to fund the miner_wallet so it has 100+ coins to shield
    for _ in range(10):
        _post(http, "/api/mine", {"use_pos": False})

    # Shield a note (enters shield mempool)
    _post(http, "/api/stark/shield", {"value": 100})
    # Mine the shield in
    _post(http, "/api/mine", {"use_pos": False})

    state = _get(http, "/api/state")
    assert state["stark_pool_size"] == 1
    assert state["stark_nullifier_count"] == 0

    # Spend the note (note_index=0)
    resp = _post(http, "/api/stark/spend", {
        "note_index": 0,
        "unshield_recipient": "dave",
        "unshield_amount": 100,
        "fee": 0,
    })
    assert "txid" in resp
    assert resp["unshield_amount"] == 100
    assert resp["proof_bytes"] > 1000  # real STARK proof, must be substantial

    # The mempool should have the tx; owned_stark_notes should be cleared
    state2 = _get(http, "/api/state")
    assert len(state2["stark_anon_mempool"]) == 1
    assert state2["owned_stark_notes"] == []

    # Mine it in
    block = _post(http, "/api/mine", {"use_pos": False})
    assert block["n_stark_anon_txs"] == 1
    state3 = _get(http, "/api/state")
    assert state3["stark_nullifier_count"] == 1
    print("  ✓ /api/stark/spend end-to-end fund → shield → mine → spend → mine works")


def test_stark_spend_rejects_invalid_note_index():
    """Spending a note_index out of range should 400."""
    from urllib.error import HTTPError
    p2p, http = _free_port(), _free_port()
    _start_server("stark-bad", p2p, http)
    try:
        _post(http, "/api/stark/spend", {
            "note_index": 99,
            "unshield_recipient": "dave",
            "unshield_amount": 10,
            "fee": 0,
        })
        assert False, "should have raised HTTPError"
    except HTTPError as e:
        assert e.code == 400
    print("  ✓ /api/stark/spend rejects out-of-range note_index")



    """Two dashboards connected via P2P should converge on the same chain."""
    p2p_a, http_a = _free_port(), _free_port()
    p2p_b, http_b = _free_port(), _free_port()
    _start_server("A", p2p_a, http_a)
    _start_server("B", p2p_b, http_b, peer=f"127.0.0.1:{p2p_a}")
    time.sleep(1.0)  # let peers connect

    _post(http_a, "/api/mine", {"use_pos": False})
    _post(http_a, "/api/mine", {"use_pos": False})

    # Poll until B catches up
    deadline = time.time() + 5
    while time.time() < deadline:
        a = _get(http_a, "/api/state")
        b = _get(http_b, "/api/state")
        if a["head_hash"] == b["head_hash"] and a["height"] == 2:
            break
        time.sleep(0.1)
    a = _get(http_a, "/api/state")
    b = _get(http_b, "/api/state")
    assert a["head_hash"] == b["head_hash"], f"A: {a['head_hash']} B: {b['head_hash']}"
    print("  ✓ Two dashboards converge on the same chain via P2P")


def test_websocket_pushes_block_event():
    """A mined block should arrive at the WebSocket subscribers."""
    try:
        import websockets
    except ImportError:
        print("  - skipped (websockets package not installed)")
        return

    p2p, http = _free_port(), _free_port()
    _start_server("ws-test", p2p, http)

    async def run():
        async with websockets.connect(f"ws://127.0.0.1:{http}/ws") as ws:
            # Snapshot first
            snap = json.loads(await ws.recv())
            assert snap["type"] == "snapshot"
            # Trigger a mine from a separate thread
            def trig():
                time.sleep(0.3)
                _post(http, "/api/mine", {"use_pos": False})
            threading.Thread(target=trig, daemon=True).start()
            # Wait for the block event
            block_seen = False
            for _ in range(10):
                msg = json.loads(
                    await asyncio.wait_for(ws.recv(), timeout=3.0)
                )
                if msg.get("type") == "block":
                    block_seen = True
                    break
            assert block_seen

    asyncio.run(run())
    print("  ✓ WebSocket pushes block events to subscribers")


if __name__ == "__main__":
    print("Running milestone 7 dashboard tests...\n")
    test_serves_index_page()
    test_state_endpoint()
    test_mine_endpoint()
    test_pos_mine_endpoint()
    test_shield_endpoint()
    test_stark_shield_endpoint()
    test_stark_spend_endpoint()
    test_stark_spend_rejects_invalid_note_index()
    test_two_dashboards_converge()
    test_websocket_pushes_block_event()
    print("\nAll milestone 7 dashboard tests passed ✓")

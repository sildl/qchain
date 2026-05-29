"""M10 Phase 4 dashboard UX tests — mixer deposit/withdraw via HTTP API.

Uses FastAPI's TestClient (no real network, no uvicorn). Verifies:
  * /api/state exposes mixer pool size, nullifier count, denominations,
    mempools, and owned mixer notes
  * /api/mixer/deposit creates a deposit, debits the miner, tracks the note
  * /api/mixer/withdraw rejects pre-mining and succeeds post-mining,
    moves the note from owned_mixer_notes to owned_stark_notes
  * Bad denominations rejected at the endpoint level
  * Full mixer flow leaves the chain in a state where is_valid() passes
"""

from __future__ import annotations

import socket

import pytest

# httpx is needed by FastAPI's TestClient. The dashboard module itself
# doesn't depend on it, but these tests do.
pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

from fastapi.testclient import TestClient

from qchain.dashboard.server import Dashboard, create_app
from qchain.network.node import Node


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _fresh_client() -> tuple[TestClient, Dashboard]:
    """Spin up a Dashboard against a fresh Node (no TCP server started)."""
    n = Node("127.0.0.1", _free_port(), node_id="A")
    dash = Dashboard(n)
    app = create_app(dash, rate_limit_action_per_sec=0, rate_limit_query_per_sec=0)  # disable for tests
    return TestClient(app), dash


# ---------------------------------------------------------------------------
# State endpoint exposes mixer fields
# ---------------------------------------------------------------------------

def test_m10_dashboard_state_exposes_mixer_fields():
    """/api/state must include mixer pool size, nullifier count,
    denominations, mempools, and owned mixer notes — all expected
    keys present, sensible initial values."""
    client, _ = _fresh_client()
    r = client.get("/api/state")
    assert r.status_code == 200
    s = r.json()
    assert s["mixer_pool_size"] == 0
    assert s["mixer_nullifier_count"] == 0
    assert s["mixer_denominations"] == [1, 10, 100, 1000]
    assert s["mixer_deposit_mempool"] == []
    assert s["mixer_withdraw_mempool"] == []
    assert s["owned_mixer_notes"] == []


# ---------------------------------------------------------------------------
# Happy-path deposit
# ---------------------------------------------------------------------------

def test_m10_dashboard_deposit_then_state_reflects_pending():
    """A POST to /api/mixer/deposit returns a txid + denomination,
    and the next /api/state shows the pending deposit + owned note."""
    client, _ = _fresh_client()
    # Mine enough to fund a 100-coin deposit (block reward = 10 each)
    for _ in range(15):
        r = client.post("/api/mine", json={"use_pos": False})
        assert r.status_code == 200, r.text

    r = client.post("/api/mixer/deposit", json={"denomination": 100})
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["denomination"] == 100
    assert "txid" in result
    assert "leaf" in result

    s = client.get("/api/state").json()
    assert len(s["mixer_deposit_mempool"]) == 1
    assert len(s["owned_mixer_notes"]) == 1
    assert s["owned_mixer_notes"][0]["value"] == 100


# ---------------------------------------------------------------------------
# Withdraw rejected pre-mining, succeeds post-mining
# ---------------------------------------------------------------------------

def test_m10_dashboard_withdraw_rejected_before_mining():
    """The deposit must be mined before the leaf is on-chain (and at
    least MIXER_WITHDRAWAL_DELAY blocks must pass thereafter, per the
    timing-attack defense). Until then, the withdrawal endpoint
    returns 400 with a useful message."""
    client, _ = _fresh_client()
    for _ in range(15):
        client.post("/api/mine", json={"use_pos": False})
    client.post("/api/mixer/deposit", json={"denomination": 100})

    r = client.post("/api/mixer/withdraw", json={"note_index": 0})
    assert r.status_code == 400
    # M-timing: the new message says "not present in mixer tree at the
    # latest valid anchor", reflecting that the deposit is too recent
    # to be anchorable.
    assert "not present in mixer tree" in r.json()["detail"] or \
           "chain too young" in r.json()["detail"]


def test_m10_dashboard_full_deposit_withdraw_flow():
    """End-to-end: deposit → mine → wait DELAY → withdraw → mine. After all that:
      * mixer pool grew by 1 (deposit)
      * mixer nullifier set grew by 1 (withdrawal consumed deposit)
      * STARK pool grew by 1 (withdrawal credited a new shielded note)
      * owned bookkeeping moved the note from mixer_notes to stark_notes
      * Chain is_valid() still passes
    """
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    client, dash = _fresh_client()
    # Fund
    for _ in range(15):
        client.post("/api/mine", json={"use_pos": False})

    # Deposit
    r = client.post("/api/mixer/deposit", json={"denomination": 100})
    assert r.status_code == 200, r.text
    client.post("/api/mine", json={"use_pos": False})
    # M-timing: wait DELAY blocks so the deposit is anchorable
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        client.post("/api/mine", json={"use_pos": False})

    s = client.get("/api/state").json()
    assert s["mixer_pool_size"] == 1
    assert len(s["owned_mixer_notes"]) == 1

    # Withdraw
    r = client.post("/api/mixer/withdraw", json={"note_index": 0})
    assert r.status_code == 200, r.text
    wd = r.json()
    # withdraw_amount is no longer in the response — denomination is
    # private at the network level after the binding-hardening pass
    assert "withdraw_amount" not in wd
    assert wd["proof_bytes"] > 1000  # real STARK proof
    assert wd["new_stark_note_value"] == 100

    # Mine the withdrawal
    client.post("/api/mine", json={"use_pos": False})
    s = client.get("/api/state").json()

    # Pool counters
    assert s["mixer_pool_size"] == 1, "mixer pool retains the consumed deposit's leaf"
    assert s["mixer_nullifier_count"] == 1, "withdrawal marks one mixer nullifier"
    assert s["stark_pool_size"] == 1, "withdrawal credits one STARK pool leaf"

    # Owned-note bookkeeping
    assert len(s["owned_mixer_notes"]) == 0
    assert len(s["owned_stark_notes"]) == 1
    assert s["owned_stark_notes"][0]["value"] == 100

    # Full chain replay
    assert dash.node.chain.is_valid()


# ---------------------------------------------------------------------------
# Bad denomination rejected
# ---------------------------------------------------------------------------

def test_m10_dashboard_bad_denomination_rejected():
    """Denominations not in MIXER_DENOMINATIONS produce a 400 with a
    clear message listing the allowed set."""
    client, _ = _fresh_client()
    for _ in range(10):
        client.post("/api/mine", json={"use_pos": False})

    r = client.post("/api/mixer/deposit", json={"denomination": 7})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "7 not in" in detail
    assert "[1, 10, 100, 1000]" in detail


# ---------------------------------------------------------------------------
# Withdraw with bad note_index rejected
# ---------------------------------------------------------------------------

def test_m10_dashboard_withdraw_bad_note_index_rejected():
    """Out-of-range note_index returns 400."""
    client, _ = _fresh_client()
    r = client.post("/api/mixer/withdraw", json={"note_index": 99})
    assert r.status_code == 400
    assert "out of range" in r.json()["detail"]

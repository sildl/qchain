"""Dashboard UX refinement — surface denomination for local-owned
mixer withdrawals, keep it private for remote (gossiped) ones.

Context: the hardening pass removed the chain-level `withdraw_amount`
field, which had a side-effect of also hiding the denomination from
the local user's own dashboard view. That was over-correction — the
local user IS the wallet owner and already knows what they withdrew.

These tests verify that the dashboard distinguishes the two cases by
matching the withdrawal's nullifier against currently-owned mixer
notes (which the dashboard holds because /api/mixer/withdraw built
the proof from them).
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx", reason="httpx required for FastAPI TestClient")

import socket
import time

from fastapi.testclient import TestClient

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    create_mixer_deposit_tx, create_mixer_withdraw_tx,
)
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote
from qchain.dashboard.server import Dashboard, create_app
from qchain.network.node import Node


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _fresh_dash() -> tuple[TestClient, Dashboard]:
    n = Node("127.0.0.1", _free_port(), node_id="A")
    dash = Dashboard(n)
    app = create_app(dash, rate_limit_action_per_sec=0, rate_limit_query_per_sec=0)  # disable for tests
    return TestClient(app), dash


def _captured_events(dash: Dashboard) -> list:
    """Drain everything currently on the event bus into a list."""
    out = []
    # The EventBus uses a Queue; drain non-blocking.
    while True:
        try:
            out.append(dash.bus.queue.get_nowait())
        except Exception:
            break
    return out


# ---------------------------------------------------------------------------
# Local withdrawal shows denomination
# ---------------------------------------------------------------------------

def test_ui_local_mixer_withdraw_event_includes_denomination():
    """A withdrawal triggered via /api/mixer/withdraw should produce
    a WebSocket event with is_local=True and the denomination value."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    client, dash = _fresh_dash()
    # Fund + deposit + mine
    for _ in range(15):
        client.post("/api/mine", json={"use_pos": False})
    r = client.post("/api/mixer/deposit", json={"denomination": 100})
    assert r.status_code == 200
    client.post("/api/mine", json={"use_pos": False})
    # M-timing: wait DELAY blocks so the deposit is anchorable
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        client.post("/api/mine", json={"use_pos": False})

    # Drain events from setup so we only see what comes from the withdraw
    _ = _captured_events(dash)

    # Local withdrawal
    r = client.post("/api/mixer/withdraw", json={"note_index": 0})
    assert r.status_code == 200

    events = _captured_events(dash)
    mixer_withdraw_events = [e for e in events if e.get("type") == "mixer_withdraw"]
    assert len(mixer_withdraw_events) >= 1, \
        "should see at least one mixer_withdraw event from local withdraw"

    ev = mixer_withdraw_events[0]
    assert ev["data"]["is_local"] is True, \
        "local-triggered withdrawal must be marked is_local=True"
    assert ev["data"]["denomination"] == 100, \
        "denomination should be visible for locally-owned withdrawals"


# ---------------------------------------------------------------------------
# Remote (foreign) withdrawal keeps denomination private
# ---------------------------------------------------------------------------

def test_ui_foreign_mixer_withdraw_event_hides_denomination():
    """A withdrawal whose mixer note we DON'T own should produce an
    event with is_local=False and no denomination key.

    We simulate this by manually constructing a withdrawal for a note
    the dashboard's wallet never deposited (so it's not in
    owned_mixer_notes). The mixer pool has to contain the leaf
    independently — set up via direct chain APIs."""
    client, dash = _fresh_dash()
    # Fund the dashboard's miner — so we can mine blocks. Note that the
    # mixer note used below is owned by a SEPARATE wallet (the "stranger"),
    # not by dash.miner_wallet. From the dashboard's POV this is foreign.
    # Mine enough for the dashboard to fund the stranger (>= 200) and
    # for the stranger to deposit (>= 100 of their own balance).
    for _ in range(25):
        client.post("/api/mine", json={"use_pos": False})

    # Build a separate wallet and have IT deposit
    stranger = Wallet()
    # Fund the stranger by sending coins from dash.miner_wallet
    client.post("/api/tx/send", json={
        "recipient": stranger.address, "amount": 200,
    })
    client.post("/api/mine", json={"use_pos": False})

    # Construct the deposit transaction outside the dashboard
    # (so dash.owned_mixer_notes stays empty for this note)
    stranger_note = STARKNote.random(value=100)
    foreign_deposit = create_mixer_deposit_tx(stranger, 100, stranger_note)
    dash.node.chain.submit_mixer_deposit(foreign_deposit)
    client.post("/api/mine", json={"use_pos": False})
    # M-timing: wait DELAY blocks so the foreign deposit is anchorable
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        client.post("/api/mine", json={"use_pos": False})

    # Confirm: dashboard does NOT own this note
    assert dash.owned_mixer_notes == [], \
        "test setup: dashboard should not own the foreign deposit's note"

    # Drain prior events
    _ = _captured_events(dash)

    # Construct the withdrawal externally and submit it via the node.
    # This mimics what would happen if a peer gossiped it to us.
    # M-timing: build proof against the latest valid anchor.
    output_note = STARKNote.random(value=100)
    anchor_idx = dash.node.chain.latest_valid_mixer_anchor()
    anchored_tree = dash.node.chain.historical_mixer_tree_for_block(anchor_idx)
    foreign_mwtx = create_mixer_withdraw_tx(
        note=stranger_note,
        leaf_idx=0,
        mixer_tree=anchored_tree,
        output_note=output_note,
        anchor_block_index=anchor_idx,
    )
    dash.node.submit_mixer_withdraw_tx(foreign_mwtx)

    # Mine to apply and observe the event
    client.post("/api/mine", json={"use_pos": False})

    events = _captured_events(dash)
    mixer_withdraw_events = [e for e in events if e.get("type") == "mixer_withdraw"]
    assert len(mixer_withdraw_events) >= 1

    ev = mixer_withdraw_events[0]
    assert ev["data"]["is_local"] is False, \
        "foreign-owned withdrawal must be marked is_local=False"
    assert "denomination" not in ev["data"], \
        "denomination must NOT appear for foreign withdrawals (privacy)"


# ---------------------------------------------------------------------------
# Mixed: own + foreign in the same session
# ---------------------------------------------------------------------------

def test_ui_mixed_withdrawals_correctly_distinguished():
    """Submitting one local withdrawal and one foreign withdrawal in
    the same session must produce events with different is_local flags.
    Catches any state-leak bug where ownership detection accidentally
    becomes sticky.
    """
    client, dash = _fresh_dash()
    # Mine enough to fund everyone
    for _ in range(25):
        client.post("/api/mine", json={"use_pos": False})

    # Local: dashboard deposits + mines + withdraws
    r = client.post("/api/mixer/deposit", json={"denomination": 10})
    assert r.status_code == 200
    client.post("/api/mine", json={"use_pos": False})

    # Foreign: stranger deposits via direct chain API
    stranger = Wallet()
    client.post("/api/tx/send", json={
        "recipient": stranger.address, "amount": 200,
    })
    client.post("/api/mine", json={"use_pos": False})
    stranger_note = STARKNote.random(value=100)
    foreign_deposit = create_mixer_deposit_tx(stranger, 100, stranger_note)
    dash.node.chain.submit_mixer_deposit(foreign_deposit)
    client.post("/api/mine", json={"use_pos": False})
    # M-timing: wait DELAY blocks so BOTH deposits become anchorable
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        client.post("/api/mine", json={"use_pos": False})

    _ = _captured_events(dash)  # drain

    # Local withdrawal (note_index 0 is the dashboard's denomination-10 note)
    r = client.post("/api/mixer/withdraw", json={"note_index": 0})
    assert r.status_code == 200

    # Foreign withdrawal (constructed externally, submitted via node).
    # M-timing: build against the latest valid anchor.
    output_note = STARKNote.random(value=100)
    anchor_idx = dash.node.chain.latest_valid_mixer_anchor()
    anchored_tree = dash.node.chain.historical_mixer_tree_for_block(anchor_idx)
    foreign_mwtx = create_mixer_withdraw_tx(
        note=stranger_note,
        leaf_idx=1,  # second leaf in mixer pool (dashboard's was leaf 0)
        mixer_tree=anchored_tree,
        output_note=output_note,
        anchor_block_index=anchor_idx,
    )
    dash.node.submit_mixer_withdraw_tx(foreign_mwtx)
    client.post("/api/mine", json={"use_pos": False})

    events = _captured_events(dash)
    mw_events = [e for e in events if e.get("type") == "mixer_withdraw"]
    # We expect two — one local, one foreign
    assert len(mw_events) >= 2, f"expected >=2 mixer_withdraw events, got {len(mw_events)}"

    # Find local and foreign events by their is_local flag
    local_events = [e for e in mw_events if e["data"]["is_local"] is True]
    foreign_events = [e for e in mw_events if e["data"]["is_local"] is False]
    assert len(local_events) >= 1, "must see at least one local event"
    assert len(foreign_events) >= 1, "must see at least one foreign event"

    # Local event has denomination 10 (the dashboard's deposit)
    assert local_events[0]["data"]["denomination"] == 10

    # Foreign event has no denomination key
    assert "denomination" not in foreign_events[0]["data"]

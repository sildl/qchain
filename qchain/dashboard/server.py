"""
Dashboard backend for QChain.

Wraps a `Node` instance with:
  * REST endpoints for chain state, mempool, anon pool, peers, balances
  * WebSocket push of every new block, tx, and anon tx as they arrive
  * Tx-submission endpoints so the UI can drive activity
  * A static HTML/JS frontend served at the root path

Run with:
    python -m qchain.dashboard.server --port 19101 --http 8101 \
        --peer 127.0.0.1:19102 --peer 127.0.0.1:19103

For a three-node demo, run three of these on different ports.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from qchain.chain.anon_tx import AnonOutput, AnonTransaction, compute_net_blinding
from qchain.chain.anon_stark_tx import STARKAnonTransaction, create_stark_anon_tx
from qchain.chain.block import Block
from qchain.chain.mixer_tx import (
    MIXER_DENOMINATIONS,
    MixerDepositTransaction,
    MixerWithdrawTransaction,
    create_mixer_deposit_tx,
    create_mixer_withdraw_tx,
)
from qchain.chain.proposer import Validator
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.transaction import Transaction
from qchain.chain.wallet import Wallet
from qchain.crypto.anon import new_anon_note, prove_anon_spend
from qchain.crypto.anon_stark import STARKNote
from qchain.crypto.schnorr import generate_keypair
from qchain.network.node import Node
from qchain.quantum.qrng import QRNG


# ---------------------------------------------------------------------------
# Event bus: bridges Node's sync callbacks → async WebSocket pushes
# ---------------------------------------------------------------------------
# The Node fires callbacks from worker threads; FastAPI WebSockets live in
# the asyncio event loop. We bridge with a thread-safe Queue and an async
# drain task that fans events out to all connected sockets.

class EventBus:
    def __init__(self) -> None:
        self.queue: Queue = Queue()
        self.subscribers: List[WebSocket] = []
        self._lock = threading.Lock()
        # Recent events kept so a newly-connected dashboard can backfill
        self.history: List[dict] = []
        self.history_max = 200

    def publish(self, event: dict) -> None:
        """Called from Node callback threads."""
        self.queue.put(event)

    async def drain_loop(self) -> None:
        """Drain the queue and push to every websocket."""
        loop = asyncio.get_running_loop()
        while True:
            # Use run_in_executor so we don't block the event loop on Queue.get
            try:
                event = await loop.run_in_executor(None, self.queue.get, True, 0.5)
            except Empty:
                continue
            except RuntimeError:
                # Loop is shutting down; bail out cleanly.
                return
            if event is None:
                continue
            self.history.append(event)
            if len(self.history) > self.history_max:
                self.history = self.history[-self.history_max:]
            with self._lock:
                subs = list(self.subscribers)
            for ws in subs:
                try:
                    await ws.send_text(json.dumps(event))
                except Exception:
                    with self._lock:
                        if ws in self.subscribers:
                            self.subscribers.remove(ws)

    def subscribe(self, ws: WebSocket) -> None:
        with self._lock:
            self.subscribers.append(ws)

    def unsubscribe(self, ws: WebSocket) -> None:
        with self._lock:
            if ws in self.subscribers:
                self.subscribers.remove(ws)


# ---------------------------------------------------------------------------
# Block / tx → dict helpers (UI-friendly summaries, not raw serialization)
# ---------------------------------------------------------------------------

def block_summary(b: Block) -> dict:
    return {
        "index": b.index,
        "hash": b.hash(),
        "previous_hash": b.previous_hash,
        "timestamp": b.timestamp,
        "proposer": b.proposer,
        "n_transparent_txs": len(b.transactions),
        "n_anon_txs": len(b.anon_transactions),
        "n_stark_anon_txs": len(b.stark_anon_transactions),
        "transparent_txids": [tx.txid() for tx in b.transactions],
        "anon_txids": [tx.txid() for tx in b.anon_transactions],
        "stark_anon_txids": [tx.txid() for tx in b.stark_anon_transactions],
    }


def tx_summary(tx: Transaction) -> dict:
    return {
        "kind": "transparent",
        "txid": tx.txid(),
        "sender": tx.sender,
        "recipient": tx.recipient,
        "amount": tx.amount,
    }


def anon_tx_summary(atx: AnonTransaction) -> dict:
    return {
        "kind": "anon",
        "txid": atx.txid(),
        "n_inputs": len(atx.inputs),
        "n_outputs": len(atx.outputs),
        "shield_in": atx.shield_in,
        "unshield_out": atx.unshield_out,
        "unshield_recipient": atx.unshield_recipient,
        "fee": atx.fee,
        # What an observer sees per input:
        "inputs_revealed": [
            {
                "nullifier": inp.statement.nullifier.hex()[:16] + "...",
                "leaf_spent": inp.statement.leaf_commitment.hex()[:16] + "...",
                "pubkey_commit": inp.statement.pubkey_commit_bytes.hex()[:16] + "...",
            }
            for inp in atx.inputs
        ],
    }


def stark_anon_tx_summary(stx) -> dict:
    """M8.5/M8.6 STARK-anonymous transaction summary.

    Shows what the chain sees publicly: nullifier, root, recipient, amounts,
    proof size. The nullifier is bound to the proof in M8.6, so the chain
    can detect double-spends even though the leaf identity is hidden.
    """
    # nullifier and root are 4-tuples of u64; show first element + ellipsis
    null_short = f"{stx.nullifier[0]:016x}..."
    root_short = f"{stx.merkle_root[0]:016x}..."
    return {
        "kind": "stark_anon",
        "txid": stx.txid(),
        "nullifier": null_short,
        "merkle_root": root_short,
        "unshield_recipient": stx.unshield_recipient,
        "unshield_amount": stx.unshield_amount,
        "fee": stx.fee,
        "proof_bytes": len(stx.proof),
    }


def shield_tx_summary(shtx) -> dict:
    """M8.7-D shield-transaction summary: depositor + amount + leaf."""
    return {
        "kind": "shield",
        "txid": shtx.txid(),
        "depositor": shtx.sender[:12] + "...",
        "amount": shtx.amount,
        "leaf": f"{shtx.leaf[0]:016x}...",
    }


# ---------------------------------------------------------------------------
# The dashboard app
# ---------------------------------------------------------------------------

class Dashboard:
    """Holds a Node, an EventBus, and a couple of helper wallets so the
    UI's quick-action buttons work without needing the user to manage keys."""

    def __init__(self, node: Node, wallet_path: Optional[str] = None) -> None:
        self.node = node
        self.bus = EventBus()
        self.wallet_path = wallet_path
        # Load or create the miner wallet
        if wallet_path and Path(wallet_path).exists():
            self.miner_wallet = Wallet.load(wallet_path, passphrase=None)
            print(f"Loaded wallet from {wallet_path}")
            print(f"  address: {self.miner_wallet.address}")
        else:
            self.miner_wallet = Wallet()
            if wallet_path:
                self._save_wallet()
                print(f"Created new wallet at {wallet_path}")
                print(f"  address: {self.miner_wallet.address}")
            else:
                print(f"Ephemeral wallet (no --wallet path): {self.miner_wallet.address}")
        self.demo_alice_anon = generate_keypair()
        # Track every anon note we own here so we can spend them via the UI
        self.owned_anon_notes: List[Any] = []  # list of (AnonNote, leaf_index)
        # M8.6: Track STARK-anon notes the same way
        # Each entry: (STARKNote, leaf_index_in_stark_pool)
        self.owned_stark_notes: List[Any] = []
        # M10: Track owned mixer notes (deposited by THIS dashboard).
        # Each entry: (STARKNote, pending_mixer_idx) where pending_mixer_idx
        # is the expected leaf index at apply time. Same race caveat as
        # owned_stark_notes — fine for the demo, not for production.
        self.owned_mixer_notes: List[Any] = []
        # Wire Node callbacks
        node.on_block = self._on_block
        node.on_tx = self._on_tx
        node.on_anon_tx = self._on_anon_tx
        node.on_stark_anon_tx = self._on_stark_anon_tx
        node.on_shield_tx = self._on_shield_tx
        # M10 mixer callbacks (added in M10 Phase 3)
        node.on_mixer_deposit = self._on_mixer_deposit
        node.on_mixer_withdraw = self._on_mixer_withdraw

    # ---- wallet persistence -------------------------------------------------

    def _save_wallet(self) -> None:
        """Persist wallet to disk if a path was configured."""
        if self.wallet_path:
            try:
                self.miner_wallet.save(
                    self.wallet_path, passphrase=None, allow_plaintext=True,
                )
            except Exception as e:
                print(f"WARNING: wallet save failed: {e}")

    # ---- node callbacks (called from peer threads) -----------------------

    def _on_block(self, block: Block) -> None:
        self.bus.publish({
            "type": "block",
            "node_id": self.node.node_id,
            "data": block_summary(block),
            "ts": time.time(),
        })
        # Auto-save wallet after every block so mined balance and
        # shielded notes survive a node restart.
        self._save_wallet()

    def _on_tx(self, tx: Transaction) -> None:
        self.bus.publish({
            "type": "tx",
            "node_id": self.node.node_id,
            "data": tx_summary(tx),
            "ts": time.time(),
        })

    def _on_anon_tx(self, atx: AnonTransaction) -> None:
        self.bus.publish({
            "type": "anon_tx",
            "node_id": self.node.node_id,
            "data": anon_tx_summary(atx),
            "ts": time.time(),
        })

    def _on_stark_anon_tx(self, stx) -> None:
        """Emit a WebSocket event for a new M8.5/M8.6 STARK-anon tx.

        Wired into the p2p gossip layer as of M8.7, so this also fires
        when a peer's STARK tx arrives via new_stark_anon_tx.
        """
        self.bus.publish({
            "type": "stark_anon_tx",
            "node_id": self.node.node_id,
            "data": stark_anon_tx_summary(stx),
            "ts": time.time(),
        })

    def _on_shield_tx(self, shtx) -> None:
        """Emit a WebSocket event for a new M8.7-D shield tx.

        Fires both for local submissions (via /api/stark/shield) and for
        shield txs received via p2p (new_shield_tx).
        """
        self.bus.publish({
            "type": "shield_tx",
            "node_id": self.node.node_id,
            "data": shield_tx_summary(shtx),
            "ts": time.time(),
        })

    def _on_mixer_deposit(self, mdtx) -> None:
        """M10: WebSocket event for a new mixer deposit (local or gossiped)."""
        self.bus.publish({
            "type": "mixer_deposit",
            "node_id": self.node.node_id,
            "data": {
                "txid": mdtx.txid(),
                "sender": mdtx.sender,
                "amount": mdtx.amount,
                "leaf": f"{mdtx.leaf[0]:016x}...",
            },
            "ts": time.time(),
        })

    def _on_mixer_withdraw(self, mwtx) -> None:
        """M10: WebSocket event for a new mixer withdrawal (local or gossiped).

        Privacy property: the protocol does NOT carry the denomination
        (`withdraw_amount` was removed during the binding-hardening
        pass). For arbitrary on-chain observers, the denomination is
        only knowable via the spender's `(sk_out, r_out)` secrets.

        UX refinement: the dashboard IS the local user's wallet, so for
        withdrawals of OWNED mixer notes (i.e., consumed via the
        local /api/mixer/withdraw endpoint) we can surface the
        denomination without breaking privacy — the dashboard already
        knows because it just spent the note. We detect this by matching
        the withdrawal's nullifier against the nullifiers of currently-
        owned mixer notes. A match means "this is a local withdrawal
        we triggered"; no match means "this is gossip from a peer" and
        the denomination stays private at the UI level.

        Why scan at callback time: the local-vs-remote signal isn't
        plumbed through the Node's callback. Scanning is O(N) where N
        is the number of owned mixer notes — typically <10 for a demo
        node, trivially fast. A production design would track this
        in the wallet rather than reverse-derive it.
        """
        owner_denomination: Optional[int] = None
        # _on_mixer_withdraw fires from submit_mixer_withdraw_tx BEFORE
        # /api/mixer/withdraw pops the note from owned_mixer_notes,
        # so at this moment the matching mixer note is still present.
        for owned_note, _pending_idx in self.owned_mixer_notes:
            if owned_note.nullifier() == mwtx.nullifier:
                owner_denomination = int(owned_note.value)
                break
        event_data: Dict[str, Any] = {
            "txid": mwtx.txid(),
            "nullifier": f"{mwtx.nullifier[0]:016x}...",
            "output_leaf": f"{mwtx.output_leaf[0]:016x}...",
            "proof_bytes": len(mwtx.proof),
            # is_local True only when WE own the mixer note being consumed
            "is_local": owner_denomination is not None,
        }
        if owner_denomination is not None:
            # Surface denomination ONLY for the local owner's view.
            # A peer running their own dashboard sees this same gossip
            # event with is_local=False and no denomination field.
            event_data["denomination"] = owner_denomination
        self.bus.publish({
            "type": "mixer_withdraw",
            "node_id": self.node.node_id,
            "data": event_data,
            "ts": time.time(),
        })

    # ---- state snapshots --------------------------------------------------

    def snapshot(self) -> dict:
        with self.node.lock:
            blocks_summary = [block_summary(b) for b in self.node.chain.blocks[-20:]]
            mempool = [tx_summary(tx) for tx in self.node.chain.mempool]
            anon_mempool = [anon_tx_summary(a) for a in self.node.chain.anon_mempool]
            stark_anon_mempool = [
                stark_anon_tx_summary(s) for s in self.node.chain.stark_anon_mempool
            ]
            # M8.7-D: shield mempool (pending shield txs that will populate
            # the STARK pool on next block)
            shield_mempool = [
                shield_tx_summary(sh) for sh in self.node.chain.shield_mempool
            ]
            # Expose owned STARK notes so the UI can offer them as spendable
            owned_stark = [
                {
                    "idx": leaf_idx,
                    "value": int(note.value),
                    "leaf": f"{note.leaf()[0]:016x}...",
                }
                for (note, leaf_idx) in self.owned_stark_notes
            ]
            # M10: mixer mempools (pending deposits/withdrawals)
            mixer_deposit_mempool = [
                {
                    "txid": d.txid(),
                    "sender": d.sender,
                    "amount": d.amount,
                    "leaf": f"{d.leaf[0]:016x}...",
                }
                for d in self.node.chain.mixer_deposit_mempool
            ]
            mixer_withdraw_mempool = [
                {
                    "txid": w.txid(),
                    "nullifier": f"{w.nullifier[0]:016x}...",
                    "output_leaf": f"{w.output_leaf[0]:016x}...",
                }
                for w in self.node.chain.mixer_withdraw_mempool
            ]
            # M10: owned mixer notes (deposited by us, withdrawable once mined)
            owned_mixer = [
                {
                    "idx": pending_idx,
                    "value": int(note.value),
                    "leaf": f"{note.leaf()[0]:016x}...",
                }
                for (note, pending_idx) in self.owned_mixer_notes
            ]
            return {
                "node_id": self.node.node_id,
                "host": self.node.host,
                "port": self.node.port,
                "height": self.node.chain.height,
                "head_hash": self.node.chain.head.hash() if self.node.chain.blocks else None,
                "anon_pool_size": self.node.chain.anon_tree.size,
                "nullifier_count": len(self.node.chain.nullifiers),
                # M8.5/M8.6 STARK pool
                "stark_pool_size": len(self.node.chain.stark_anon_tree),
                "stark_nullifier_count": len(self.node.chain.stark_nullifiers),
                # M10: mixer pool counters
                "mixer_pool_size": self.node.chain.mixer_tree._next_idx,
                "mixer_nullifier_count": len(self.node.chain.mixer_nullifiers),
                "mixer_denominations": list(MIXER_DENOMINATIONS),
                "peer_count": self.node.peer_count(),
                "miner_address": self.miner_wallet.address,
                "miner_balance": self.node.chain.balance_of(self.miner_wallet.address),
                "recent_blocks": blocks_summary,
                "mempool": mempool,
                "anon_mempool": anon_mempool,
                "stark_anon_mempool": stark_anon_mempool,
                "shield_mempool": shield_mempool,
                "owned_stark_notes": owned_stark,
                # M10 mixer state
                "mixer_deposit_mempool": mixer_deposit_mempool,
                "mixer_withdraw_mempool": mixer_withdraw_mempool,
                "owned_mixer_notes": owned_mixer,
            }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ConnectRequest(BaseModel):
    host: str
    port: int


class SendTxRequest(BaseModel):
    recipient: str
    amount: float


class ShieldRequest(BaseModel):
    amount: int  # transparent → anon pool


class StarkShieldRequest(BaseModel):
    """Shield a fresh note into the M8.6 STARK pool.
    A new (sk, randomness, value) is sampled server-side; the dashboard
    tracks the note so it can later be spent via /api/stark/spend.
    """
    value: int


class StarkSpendRequest(BaseModel):
    """Spend a STARK-pool note. `note_index` refers to position in
    `owned_stark_notes` (NOT the leaf index in the chain's tree)."""
    note_index: int
    unshield_recipient: str
    unshield_amount: int
    fee: int = 0


class MineRequest(BaseModel):
    use_pos: bool = False


class MixerDepositRequest(BaseModel):
    """M10: deposit `denomination` transparent coins into the mixer pool.
    Must be one of MIXER_DENOMINATIONS. A fresh note is sampled server-side;
    the dashboard tracks the note so the user can later withdraw it.
    """
    denomination: int


class MixerWithdrawRequest(BaseModel):
    """M10: withdraw an owned mixer note (referenced by position in
    `owned_mixer_notes`). The withdrawal credits a new STARK pool leaf
    of matching value, which the dashboard adds to `owned_stark_notes`.
    """
    note_index: int


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------

# ROADMAP 1.5 (T22 closure): per-client-IP rate limits on dashboard
# endpoints. Action endpoints (POSTs like /api/mine, /api/stark/spend)
# are gated tighter than query endpoints (GETs like /api/state, polled
# by the live UI). Limits are generous enough for honest human use of
# the dashboard but devastating against scripted abuse.
#
# Note: this is RATE limiting, not authentication. T22's full closure
# would require auth, which is a separate ROADMAP item. Rate limiting
# reduces the BLAST RADIUS of an attacker who can reach the dashboard
# but does not lock them out. The dashboard's primary defense remains
# its default 127.0.0.1 binding.
DASHBOARD_RL_WINDOW_SECONDS = 1.0
DASHBOARD_RL_ACTION_PER_SEC = 5    # POST endpoints (driving operations)
DASHBOARD_RL_QUERY_PER_SEC = 50    # GET endpoints (polled by UI)


# ROADMAP follow-up: bearer-token authentication (closes T22 fully).
#
# All /api/* endpoints (and the /ws WebSocket) require an Authorization
# header `Authorization: Bearer <token>` or a ?token=<token> query
# parameter (the WebSocket form, since browser WS APIs can't set
# custom headers).
#
# The dashboard HTML page at `/` is served without auth so the user
# can land there with a token in the URL query string and have the
# JS save it to localStorage for subsequent API calls.
#
# Constant-time comparison via `hmac.compare_digest` prevents timing-
# attack disclosure of the token.
#
# Threat model:
#   * Defends against: same-machine attackers, accidental 0.0.0.0
#     binding, port-forwarding exposure, CSRF from a malicious tab
#     (the Authorization header is not auto-sent cross-origin)
#   * Does NOT defend against: a user who shares their token, a
#     compromised wallet file, an attacker with process-memory or
#     filesystem read access. Token travels in HTTP cleartext —
#     for TLS, put the dashboard behind a reverse proxy.
#
# When token is None or empty, auth is DISABLED. This is the legacy
# behavior — tests and trusted-localhost-only deployments use this.

def _generate_auth_token() -> str:
    """Generate a fresh URL-safe random token (32 bytes → ~43 chars).

    Used when no token is provided via parameter or env var. The
    token is printed at startup so the user can copy it.
    """
    import secrets
    return secrets.token_urlsafe(32)


def _token_matches(presented: Optional[str], expected: str) -> bool:
    """Constant-time bearer-token comparison.

    Returns True iff `presented` is exactly `expected`. The
    constant-time semantics prevent an attacker from learning the
    token byte-by-byte via timing differences.
    """
    if presented is None or not presented:
        return False
    import hmac
    # compare_digest only works on str-or-bytes of equal length;
    # presenting a longer string would otherwise leak length info
    # through the comparison time. We force-encode and compare.
    return hmac.compare_digest(
        presented.encode("utf-8"),
        expected.encode("utf-8"),
    )


def _extract_bearer_token(request: Request) -> Optional[str]:
    """Extract a bearer token from either the Authorization header
    or the ?token=<...> query parameter.

    The header form is preferred (CSRF-immune); the query form is
    for the WebSocket path and for bookmarkable URLs.
    """
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[len("bearer "):].strip()
    # Fall back to query parameter
    return request.query_params.get("token")


def create_app(
    dash: Dashboard,
    rate_limit_action_per_sec: int = DASHBOARD_RL_ACTION_PER_SEC,
    rate_limit_query_per_sec: int = DASHBOARD_RL_QUERY_PER_SEC,
    rate_limit_window_seconds: float = DASHBOARD_RL_WINDOW_SECONDS,
    auth_token: Optional[str] = None,
) -> FastAPI:
    """Create the FastAPI app for the dashboard.

    Rate limiting parameters can be overridden via constructor args.
    Tests typically pass `rate_limit_action_per_sec=10_000` to
    effectively disable rate limiting while exercising endpoints. The
    DEFAULTS reflect production-appropriate values; the OVERRIDES let
    test harnesses opt out of the test-irrelevant safety check.

    Pass `rate_limit_*_per_sec=0` to disable that limiter entirely
    (a 0 capacity would crash the SlidingWindowRateLimiter, so we
    special-case 0 as "no limit").

    Auth: if `auth_token` is non-empty, all /api/* and /ws requests
    require the token as either an `Authorization: Bearer <token>`
    header or a `?token=<token>` query parameter. If `auth_token` is
    None or empty, auth is disabled (legacy behavior — used by tests
    and trusted-localhost-only deployments).
    """
    app = FastAPI(title=f"QChain Dashboard — {dash.node.node_id}")

    # Per-IP sliding-window limiters. Stored on the app so tests can
    # reach in and reset between cases. Capacity=0 → disabled.
    from qchain.network.rate_limit import SlidingWindowRateLimiter
    app.state.rl_action = (
        SlidingWindowRateLimiter(
            capacity=rate_limit_action_per_sec,
            window_seconds=rate_limit_window_seconds,
        ) if rate_limit_action_per_sec > 0 else None
    )
    app.state.rl_query = (
        SlidingWindowRateLimiter(
            capacity=rate_limit_query_per_sec,
            window_seconds=rate_limit_window_seconds,
        ) if rate_limit_query_per_sec > 0 else None
    )
    # Auth token, or None to disable. Stored on app.state for the
    # WebSocket endpoint and any test introspection.
    app.state.auth_token = auth_token if auth_token else None

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """Per-IP rate limiting. POST endpoints get the tighter
        action limit; GETs get the generous query limit. WebSocket
        upgrade requests bypass (the dashboard polls via WS for a
        single open connection per client; rate-limiting that breaks
        the UI without security benefit)."""
        # Skip non-API paths and websocket upgrades
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        if request.method == "POST":
            limiter = app.state.rl_action
            limit_name = "action"
        else:
            limiter = app.state.rl_query
            limit_name = "query"

        # If the limiter was disabled (capacity=0), skip the check.
        if limiter is not None and not limiter.try_consume(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate limit exceeded",
                    "limit": limit_name,
                    "retry_after_seconds": rate_limit_window_seconds,
                },
                headers={"Retry-After": str(int(rate_limit_window_seconds) or 1)},
            )
        return await call_next(request)

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        """Bearer-token authentication on /api/* endpoints.

        Runs FIRST in the middleware chain (FastAPI middleware is LIFO;
        this was added AFTER rate_limit_middleware so it executes BEFORE
        it). Unauthenticated requests get a clean 401 without
        consuming rate-limit budget.

        Non-API paths (index, static, etc.) bypass auth so the user
        can land on the dashboard with a token in the URL.

        WebSocket upgrade requests are handled by the WS endpoint
        directly (not via this HTTP middleware), so the WS auth
        check lives there.
        """
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)
        if app.state.auth_token is None:
            # Auth disabled
            return await call_next(request)
        presented = _extract_bearer_token(request)
        if not _token_matches(presented, app.state.auth_token):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "authentication required",
                    "detail": (
                        "Provide a valid bearer token via "
                        "'Authorization: Bearer <token>' header or "
                        "'?token=<token>' query parameter"
                    ),
                },
            )
        return await call_next(request)

    @app.on_event("startup")
    async def _startup():
        asyncio.create_task(dash.bus.drain_loop())

    # ---- index page ------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return INDEX_HTML

    # ---- REST endpoints --------------------------------------------------

    @app.get("/api/state")
    def get_state():
        return dash.snapshot()

    @app.get("/api/wallet")
    def get_wallet():
        """Return the node's wallet address and public key hex."""
        return {
            "address": dash.miner_wallet.address,
            "public_key_hex": dash.miner_wallet.keypair.public_key.hex(),
            "balance": dash.node.chain.balance_of(dash.miner_wallet.address),
            "mixer_notes": len(dash.miner_wallet.mixer_notes),
            "stark_notes": len(dash.miner_wallet.stark_notes),
        }

    @app.get("/api/block/{index}")
    def get_block(index: int):
        with dash.node.lock:
            if index < 0 or index >= len(dash.node.chain.blocks):
                raise HTTPException(status_code=404, detail="block out of range")
            return block_summary(dash.node.chain.blocks[index])

    @app.get("/api/peers")
    def get_peers():
        with dash.node._peers_lock:
            return list(dash.node._peers.keys())

    @app.post("/api/peers/connect")
    def connect_peer(req: ConnectRequest):
        ok = dash.node.connect_to(req.host, req.port)
        return {"ok": ok}

    @app.post("/api/tx/send")
    def send_tx(req: SendTxRequest):
        try:
            tx = Wallet(dash.miner_wallet.keypair).create_tx(
                recipient=req.recipient, amount=req.amount,
            )
            dash.node.submit_tx(tx)
            return {"txid": tx.txid()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/anon/shield")
    def shield(req: ShieldRequest):
        """Shield `amount` transparent coins into a new anon note owned
        by this node's demo Alice keypair."""
        try:
            note = new_anon_note(value=req.amount, recipient_pk=dash.demo_alice_anon.pk)
            atx = AnonTransaction(
                inputs=[],
                outputs=[AnonOutput.from_note(note)],
                shield_in=req.amount,
                unshield_out=0,
                unshield_recipient="",
                fee=0,
                net_blinding=compute_net_blinding([], [note.value_blinding]),
            )
            dash.node.submit_anon_tx(atx)
            # Remember the note so the UI can spend it later
            # (We'll learn its leaf_index after it's mined into a block.)
            dash.owned_anon_notes.append(note)
            return {"txid": atx.txid(), "note_value": note.value}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/stark/shield")
    def stark_shield(req: StarkShieldRequest):
        """M8.7-D: shield a fresh note into the STARK pool via an on-chain
        ShieldTransaction signed by the dashboard's miner_wallet.

        This is the real path — the depositor (miner_wallet) is debited
        `value` coins on chain, the leaf is gossipped to peers as a
        new_shield_tx, and once mined into a block every node converges
        on the same STARK pool root.

        The miner_wallet must have at least `value` coins of mined balance
        already. Use POST /api/mine first to fund the wallet via coinbase
        rewards.
        """
        try:
            note = STARKNote.random(value=req.value)
            shtx = ShieldTransaction(
                sender="",  # filled by sign()
                leaf=note.leaf(),
                amount=float(req.value),
                timestamp=time.time(),
                nonce=int(time.time() * 1e6) ^ (req.value & 0xFFFF),
            )
            shtx.sign(dash.miner_wallet.keypair)
            # submit_shield_tx handles both local submission and p2p gossip.
            dash.node.submit_shield_tx(shtx)
            # Track the (note, eventual leaf_idx) — we won't know the leaf's
            # final index until the shield is mined. Store the note keyed by
            # txid; when the block is mined we'll resolve to an index.
            # For UI simplicity we just append the note here and let the
            # /api/state snapshot read leaf_idx via tree.size() after mining.
            # On the assumption that this shield will be the next leaf added,
            # its index is len(tree) at apply time — that's racy under
            # concurrent shields, but fine for the demo.
            pending_idx = len(dash.node.chain.stark_anon_tree) + len([
                s for s in dash.node.chain.shield_mempool
                if s.txid() != shtx.txid()
            ])
            dash.owned_stark_notes.append((note, pending_idx))
            return {
                "txid": shtx.txid(),
                "pending_leaf_idx": pending_idx,
                "value": req.value,
                "leaf": f"{note.leaf()[0]:016x}...",
                "depositor": dash.miner_wallet.address,
            }
        except ValueError as e:
            # Most likely "insufficient balance" — surface as a 400 with
            # a hint about mining first.
            raise HTTPException(
                status_code=400,
                detail=f"shield rejected: {e}. Did you mine a block first to fund the depositor?",
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/stark/spend")
    def stark_spend(req: StarkSpendRequest):
        """M8.6: spend a STARK-pool note we own.

        `note_index` is the position in `owned_stark_notes` (NOT the leaf
        index in the chain's tree). Generates a fresh M8.6 STARK proof
        binding the nullifier to (sk, r, v), submits the transaction to
        the chain's mempool, and emits a WebSocket event.
        """
        try:
            if req.note_index < 0 or req.note_index >= len(dash.owned_stark_notes):
                raise HTTPException(status_code=400, detail="note_index out of range")
            note, leaf_idx = dash.owned_stark_notes[req.note_index]
            with dash.node.lock:
                stx = create_stark_anon_tx(
                    note, leaf_idx, dash.node.chain.stark_anon_tree,
                    unshield_recipient=req.unshield_recipient,
                    unshield_amount=req.unshield_amount,
                    fee=req.fee,
                )
                dash.node.chain.submit_stark_anon(stx)
            # Mark the note as spent in our tracking (don't reuse it)
            dash.owned_stark_notes.pop(req.note_index)
            # Push WebSocket event
            dash._on_stark_anon_tx(stx)
            return {
                "txid": stx.txid(),
                "unshield_amount": req.unshield_amount,
                "proof_bytes": len(stx.proof),
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/mine")
    def mine(req: MineRequest):
        try:
            if req.use_pos:
                # Single-validator PoS for the demo: just this node's miner.
                validators = [Validator(address=dash.miner_wallet.address, stake=1.0)]
                qrng = QRNG(num_qubits=4, shots=32, prefer_hardware=False)
                block = dash.node.chain.propose_pending(validators, qrng)
            else:
                block = dash.node.chain.mine_pending(dash.miner_wallet.address)
            dash.node.broadcast_block(block)
            return block_summary(block)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/mixer/deposit")
    def mixer_deposit(req: MixerDepositRequest):
        """M10: deposit `denomination` coins into the mixer pool.

        Signs the deposit with the dashboard's miner_wallet (which must
        have at least `denomination` coins of mined balance — use POST
        /api/mine first if needed). The new note is tracked in
        owned_mixer_notes so the user can withdraw it after mining.
        """
        try:
            if req.denomination not in MIXER_DENOMINATIONS:
                raise HTTPException(
                    status_code=400,
                    detail=f"denomination {req.denomination} not in "
                           f"{list(MIXER_DENOMINATIONS)}",
                )
            note = STARKNote.random(value=req.denomination)
            deposit = create_mixer_deposit_tx(
                dash.miner_wallet, req.denomination, note,
            )
            # submit_mixer_deposit_tx handles local submission + p2p gossip
            dash.node.submit_mixer_deposit_tx(deposit)
            # Best-effort pending leaf index — racy under concurrent deposits
            # but fine for the demo. Same caveat as owned_stark_notes.
            pending_idx = (
                dash.node.chain.mixer_tree._next_idx
                + len([
                    d for d in dash.node.chain.mixer_deposit_mempool
                    if d.txid() != deposit.txid()
                ])
            )
            dash.owned_mixer_notes.append((note, pending_idx))
            return {
                "txid": deposit.txid(),
                "denomination": req.denomination,
                "pending_leaf_idx": pending_idx,
                "leaf": f"{note.leaf()[0]:016x}...",
                "depositor": dash.miner_wallet.address,
            }
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"mixer deposit rejected: {e}. "
                       "Did you mine a block first to fund the depositor?",
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/mixer/withdraw")
    def mixer_withdraw(req: MixerWithdrawRequest):
        """M10: withdraw an owned mixer note anonymously.

        `note_index` is the position in owned_mixer_notes (NOT the leaf
        index in the chain's mixer tree). Generates a STARK proof of
        membership in the mixer pool, produces a fresh STARK pool leaf
        of matching value, and gossips the withdrawal to peers.

        The deposit must already be mined into a block — until then, the
        leaf isn't on-chain and the withdrawal proof can't be built.
        """
        try:
            if req.note_index < 0 or req.note_index >= len(dash.owned_mixer_notes):
                raise HTTPException(
                    status_code=400, detail="note_index out of range",
                )
            note, _pending_idx = dash.owned_mixer_notes[req.note_index]
            # M-timing: build the proof against a HISTORICAL anchor at
            # least MIXER_WITHDRAWAL_DELAY blocks old. The wallet helper
            # could be used here, but the dashboard has its own
            # `owned_mixer_notes` bookkeeping separate from the wallet,
            # so we inline the logic instead.
            with dash.node.lock:
                anchor_idx = dash.node.chain.latest_valid_mixer_anchor()
                if anchor_idx < 0:
                    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"chain too young for mixer withdrawal "
                            f"(need at least {MIXER_WITHDRAWAL_DELAY} "
                            f"blocks; chain height is "
                            f"{dash.node.chain.height}). Mine more blocks."
                        ),
                    )
                anchored_tree = dash.node.chain.historical_mixer_tree_for_block(
                    anchor_idx,
                )
                # Look up the real leaf index in the anchored tree.
                target_leaf = note.leaf()
                real_idx = None
                for i in range(anchored_tree._next_idx):
                    if anchored_tree._layers[0][i] == target_leaf:
                        real_idx = i
                        break
            if real_idx is None:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"mixer note not present in mixer tree at the "
                        f"latest valid anchor (block {anchor_idx}). The "
                        f"deposit may still be in mempool, or may be too "
                        f"recent to satisfy the timing-attack defense — "
                        f"mine more blocks."
                    ),
                )
            # Fresh output note (the STARK pool credit)
            output_note = STARKNote.random(value=int(note.value))
            with dash.node.lock:
                mwtx = create_mixer_withdraw_tx(
                    note=note,
                    leaf_idx=real_idx,
                    mixer_tree=anchored_tree,
                    output_note=output_note,
                    anchor_block_index=anchor_idx,
                )
            # submit_mixer_withdraw_tx handles local submission + gossip
            dash.node.submit_mixer_withdraw_tx(mwtx)
            # Update owned-note bookkeeping:
            #   * remove the spent mixer note
            #   * add the new STARK pool note so it can be spent via /api/stark/spend
            dash.owned_mixer_notes.pop(req.note_index)
            pending_stark_idx = (
                dash.node.chain.stark_anon_tree._next_idx
                + len(dash.node.chain.mixer_withdraw_mempool)  # approximate
            )
            dash.owned_stark_notes.append((output_note, pending_stark_idx))
            return {
                "txid": mwtx.txid(),
                "output_leaf": f"{mwtx.output_leaf[0]:016x}...",
                "proof_bytes": len(mwtx.proof),
                "new_stark_note_value": int(output_note.value),
            }
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(
                status_code=400, detail=f"mixer withdrawal rejected: {e}",
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ---- WebSocket -------------------------------------------------------

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        # Auth check for WebSocket. Browser WS APIs can't set custom
        # headers, so we accept the token via `?token=<...>` query
        # parameter. If auth is disabled (app.state.auth_token is None),
        # all connections are allowed.
        if app.state.auth_token is not None:
            presented = websocket.query_params.get("token")
            if not _token_matches(presented, app.state.auth_token):
                # Reject with 1008 (policy violation) — standard for auth-fail
                await websocket.close(code=1008, reason="auth required")
                return
        await websocket.accept()
        # Send a snapshot + recent history so the UI starts populated
        await websocket.send_text(json.dumps({
            "type": "snapshot",
            "data": dash.snapshot(),
        }))
        for ev in dash.bus.history[-50:]:
            try:
                await websocket.send_text(json.dumps(ev))
            except Exception:
                break
        dash.bus.subscribe(websocket)
        try:
            while True:
                # We don't accept inbound messages; just keep the socket alive
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            dash.bus.unsubscribe(websocket)

    return app


# ---------------------------------------------------------------------------
# Inline frontend (single HTML file with React via CDN)
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>QChain Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<style>
  body { background: #0a0e1a; color: #d4d4d8; font-family: 'JetBrains Mono', ui-monospace, monospace; }
  .panel { background: #11162a; border: 1px solid #1f2540; border-radius: 8px; }
  .glow { box-shadow: 0 0 12px rgba(99, 102, 241, 0.2); }
  .event-block { background: rgba(34, 197, 94, 0.12); border-left: 3px solid #22c55e; }
  .event-tx { background: rgba(99, 102, 241, 0.12); border-left: 3px solid #6366f1; }
  .event-anon-tx { background: rgba(168, 85, 247, 0.18); border-left: 3px solid #a855f7; }
  .event-stark-tx { background: rgba(6, 182, 212, 0.18); border-left: 3px solid #06b6d4; }
  .mono-trunc { font-family: ui-monospace, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pulse-new { animation: pulse-new 1.5s ease-out; }
  @keyframes pulse-new {
    0% { background-color: rgba(99, 102, 241, 0.6); }
    100% { background-color: transparent; }
  }
</style>
</head>
<body class="min-h-screen">
<div id="root"></div>
<script type="text/babel">
const { useState, useEffect, useRef } = React;

// Auth token: read from ?token= in the URL, or prompt the user.
const _urlToken = new URLSearchParams(window.location.search).get("token");
let AUTH_TOKEN = _urlToken || "";
if (!AUTH_TOKEN) {
  AUTH_TOKEN = window.prompt("Enter dashboard auth token:", "") || "";
}
// Build headers with auth for every fetch call
function authHeaders(extra) {
  const h = {...(extra || {})};
  if (AUTH_TOKEN) h["Authorization"] = "Bearer " + AUTH_TOKEN;
  return h;
}
function authFetch(url, opts) {
  opts = opts || {};
  opts.headers = authHeaders(opts.headers);
  return fetch(url, opts);
}

function short(s, n=14) {
  if (!s) return "";
  if (s.length <= n) return s;
  return s.substring(0, n) + "…";
}

function ago(ts) {
  if (!ts) return "";
  const diff = Math.floor(Date.now()/1000 - ts);
  if (diff < 1) return "now";
  if (diff < 60) return diff + "s ago";
  return Math.floor(diff/60) + "m ago";
}

function App() {
  const [state, setState] = useState(null);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [peerHost, setPeerHost] = useState("127.0.0.1");
  const [peerPort, setPeerPort] = useState(19102);
  const [txRecipient, setTxRecipient] = useState("");
  const [txAmount, setTxAmount] = useState(1);
  const [shieldAmount, setShieldAmount] = useState(5);
  // M8.6 STARK controls
  const [starkShieldValue, setStarkShieldValue] = useState(50);
  const [starkSpendIdx, setStarkSpendIdx] = useState(0);
  const [starkSpendRecipient, setStarkSpendRecipient] = useState("");
  const [starkSpendAmount, setStarkSpendAmount] = useState(10);
  // M10 mixer controls
  const [mixerDenom, setMixerDenom] = useState(100);
  const [mixerWithdrawIdx, setMixerWithdrawIdx] = useState(0);
  const wsRef = useRef(null);
  const refreshTimerRef = useRef(null);

  // Debounced state refresh — coalesces rapid WS events into one fetch
  function scheduleRefresh() {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      authFetch("/api/state").then(r => r.json()).then(d => setState(d)).catch(() => {});
    }, 300);
  }

  // Initial state + WebSocket
  useEffect(() => {
    let cancelled = false;
    async function init() {
      try {
        const r = await authFetch("/api/state");
        const data = await r.json();
        if (!cancelled) setState(data);
      } catch (e) { console.error(e); }
    }
    init();

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const wsUrl = AUTH_TOKEN
      ? `${proto}://${window.location.host}/ws?token=${encodeURIComponent(AUTH_TOKEN)}`
      : `${proto}://${window.location.host}/ws`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "snapshot") {
        setState(msg.data);
      } else {
        setEvents(es => [{...msg, _id: Math.random()}, ...es.slice(0, 99)]);
        // Debounced refresh — multiple rapid events coalesce into one fetch
        scheduleRefresh();
      }
    };
    return () => { cancelled = true; ws.close(); if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current); };
  }, []);

  async function doConnect() {
    await authFetch("/api/peers/connect", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({host: peerHost, port: parseInt(peerPort)}),
    });
  }

  async function doSendTx() {
    if (!txRecipient || !txAmount) return;
    const r = await authFetch("/api/tx/send", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({recipient: txRecipient, amount: parseFloat(txAmount)}),
    });
    if (!r.ok) alert(await r.text());
  }

  async function doShield() {
    const r = await authFetch("/api/anon/shield", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({amount: parseInt(shieldAmount)}),
    });
    if (!r.ok) alert(await r.text());
  }

  async function doStarkShield() {
    const r = await authFetch("/api/stark/shield", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({value: parseInt(starkShieldValue)}),
    });
    if (!r.ok) alert(await r.text());
  }

  async function doStarkSpend() {
    if (!starkSpendRecipient) { alert("recipient required"); return; }
    const r = await authFetch("/api/stark/spend", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        note_index: parseInt(starkSpendIdx),
        unshield_recipient: starkSpendRecipient,
        unshield_amount: parseInt(starkSpendAmount),
        fee: 0,
      }),
    });
    if (!r.ok) alert(await r.text());
  }

  async function doMixerDeposit() {
    const r = await authFetch("/api/mixer/deposit", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({denomination: parseInt(mixerDenom)}),
    });
    if (!r.ok) alert(await r.text());
  }

  async function doMixerWithdraw() {
    const r = await authFetch("/api/mixer/withdraw", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({note_index: parseInt(mixerWithdrawIdx)}),
    });
    if (!r.ok) alert(await r.text());
  }

  async function doMine(use_pos=false) {
    const r = await authFetch("/api/mine", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({use_pos}),
    });
    if (!r.ok) alert(await r.text());
  }

  if (!state) return <div className="p-8">Loading...</div>;

  return (
    <div className="p-4 max-w-7xl mx-auto">
      <Header state={state} connected={connected} />
      <div className="grid grid-cols-12 gap-4 mt-4">
        {/* LEFT column: chain state */}
        <div className="col-span-12 lg:col-span-8 space-y-4">
          <Stats state={state} />
          <Blocks blocks={state.recent_blocks} />
          <Mempools state={state} />
        </div>
        {/* RIGHT column: controls + live feed */}
        <div className="col-span-12 lg:col-span-4 space-y-4">
          <Controls
            peerHost={peerHost} setPeerHost={setPeerHost}
            peerPort={peerPort} setPeerPort={setPeerPort} doConnect={doConnect}
            txRecipient={txRecipient} setTxRecipient={setTxRecipient}
            txAmount={txAmount} setTxAmount={setTxAmount} doSendTx={doSendTx}
            shieldAmount={shieldAmount} setShieldAmount={setShieldAmount}
            doShield={doShield}
            starkShieldValue={starkShieldValue} setStarkShieldValue={setStarkShieldValue}
            doStarkShield={doStarkShield}
            ownedStarkNotes={state.owned_stark_notes || []}
            starkSpendIdx={starkSpendIdx} setStarkSpendIdx={setStarkSpendIdx}
            starkSpendRecipient={starkSpendRecipient} setStarkSpendRecipient={setStarkSpendRecipient}
            starkSpendAmount={starkSpendAmount} setStarkSpendAmount={setStarkSpendAmount}
            doStarkSpend={doStarkSpend}
            mixerDenominations={state.mixer_denominations || [1, 10, 100, 1000]}
            mixerDenom={mixerDenom} setMixerDenom={setMixerDenom}
            doMixerDeposit={doMixerDeposit}
            ownedMixerNotes={state.owned_mixer_notes || []}
            mixerWithdrawIdx={mixerWithdrawIdx} setMixerWithdrawIdx={setMixerWithdrawIdx}
            doMixerWithdraw={doMixerWithdraw}
            doMine={doMine}
          />
          <EventFeed events={events} />
        </div>
      </div>
      <Footer />
    </div>
  );
}

function Header({ state, connected }) {
  return (
    <div className="flex justify-between items-center panel p-4 glow">
      <div>
        <div className="text-2xl font-bold text-indigo-300">QChain Dashboard</div>
        <div className="text-xs text-zinc-500 mt-1">Node {state.node_id} on {state.host}:{state.port}</div>
      </div>
      <div className="text-right">
        <div className={connected ? "text-green-400 text-sm" : "text-red-400 text-sm"}>
          ● {connected ? "live" : "disconnected"}
        </div>
        <div className="text-xs text-zinc-500">{state.peer_count} peer{state.peer_count===1?"":"s"}</div>
      </div>
    </div>
  );
}

function Stats({ state }) {
  const items = [
    { label: "Chain height", value: state.height, color: "text-indigo-300" },
    { label: "Anon pool (M4)", value: state.anon_pool_size, color: "text-purple-300" },
    { label: "Nullifiers (M4)", value: state.nullifier_count, color: "text-pink-300" },
    { label: "Miner balance", value: state.miner_balance, color: "text-green-300" },
    { label: "STARK pool (M8.6)", value: state.stark_pool_size ?? 0, color: "text-cyan-300" },
    { label: "STARK nullifiers", value: state.stark_nullifier_count ?? 0, color: "text-cyan-200" },
    { label: "Mixer pool (M10)", value: state.mixer_pool_size ?? 0, color: "text-emerald-300" },
    { label: "Mixer nullifiers", value: state.mixer_nullifier_count ?? 0, color: "text-emerald-200" },
  ];
  return (
    <div>
      {state.miner_address && (
        <div className="panel p-3 mb-3 flex items-center gap-2 text-sm">
          <span className="text-zinc-500 uppercase text-xs">Wallet</span>
          <code className="text-green-300 break-all select-all flex-1"
                style={{fontSize:"11px"}}>{state.miner_address}</code>
          <button className="text-xs text-zinc-500 hover:text-white px-2 py-1 border border-zinc-700 rounded"
                  onClick={() => {navigator.clipboard.writeText(state.miner_address)}}>Copy</button>
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {items.map((it, i) => (
          <div key={i} className="panel p-3">
            <div className="text-xs text-zinc-500 uppercase">{it.label}</div>
            <div className={`text-2xl font-bold ${it.color}`}>{it.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Blocks({ blocks }) {
  return (
    <div className="panel p-4">
      <div className="text-sm text-zinc-400 mb-3 uppercase tracking-wider">Recent Blocks</div>
      <div className="space-y-1.5">
        {[...blocks].reverse().map(b => (
          <div key={b.index} className="flex items-center text-sm py-1.5 border-b border-zinc-800">
            <div className="w-12 text-zinc-600">#{b.index}</div>
            <div className="flex-1 mono-trunc text-zinc-400">{short(b.hash, 16)}</div>
            <div className="w-32 mono-trunc text-xs text-zinc-500">
              {b.proposer.includes("|qrng=") ? "QRNG PoS" : short(b.proposer, 14)}
            </div>
            <div className="w-24 text-right space-x-1">
              {b.n_transparent_txs > 0 && (
                <span className="text-indigo-400">{b.n_transparent_txs}t</span>
              )}
              {b.n_anon_txs > 0 && (
                <span className="text-purple-400">{b.n_anon_txs}a</span>
              )}
              {(b.n_stark_anon_txs ?? 0) > 0 && (
                <span className="text-cyan-300">{b.n_stark_anon_txs}s</span>
              )}
            </div>
          </div>
        ))}
        {blocks.length === 0 && <div className="text-zinc-600 text-sm">no blocks yet</div>}
      </div>
    </div>
  );
}

function Mempools({ state }) {
  const starkMempool = state.stark_anon_mempool ?? [];
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <div className="panel p-4">
        <div className="text-sm text-zinc-400 mb-3 uppercase tracking-wider flex justify-between">
          <span>Transparent Mempool</span>
          <span className="text-indigo-400">{state.mempool.length}</span>
        </div>
        <div className="space-y-2 max-h-48 overflow-y-auto">
          {state.mempool.map((tx, i) => (
            <div key={i} className="text-xs panel event-tx p-2">
              <div className="mono-trunc">{short(tx.txid, 24)}</div>
              <div className="text-zinc-400 mt-0.5">
                {short(tx.sender, 10)} → {short(tx.recipient, 10)}: {tx.amount}
              </div>
            </div>
          ))}
          {state.mempool.length === 0 && <div className="text-zinc-600 text-xs">empty</div>}
        </div>
      </div>
      <div className="panel p-4">
        <div className="text-sm text-zinc-400 mb-3 uppercase tracking-wider flex justify-between">
          <span>Anon Mempool (M4)</span>
          <span className="text-purple-400">{state.anon_mempool.length}</span>
        </div>
        <div className="space-y-2 max-h-48 overflow-y-auto">
          {state.anon_mempool.map((tx, i) => (
            <div key={i} className="text-xs panel event-anon-tx p-2">
              <div className="mono-trunc">{short(tx.txid, 24)}</div>
              <div className="text-zinc-400 mt-0.5 flex justify-between">
                <span>{tx.n_inputs}in / {tx.n_outputs}out</span>
                <span>shield={tx.shield_in} unshield={tx.unshield_out} fee={tx.fee}</span>
              </div>
            </div>
          ))}
          {state.anon_mempool.length === 0 && <div className="text-zinc-600 text-xs">empty</div>}
        </div>
      </div>
      <div className="panel p-4">
        <div className="text-sm text-zinc-400 mb-3 uppercase tracking-wider flex justify-between">
          <span>STARK Mempool (M8.6)</span>
          <span className="text-cyan-300">{starkMempool.length}</span>
        </div>
        <div className="space-y-2 max-h-48 overflow-y-auto">
          {starkMempool.map((tx, i) => (
            <div key={i} className="text-xs panel event-stark-tx p-2">
              <div className="mono-trunc">{short(tx.txid, 24)}</div>
              <div className="text-zinc-400 mt-0.5 flex justify-between">
                <span>→ {short(tx.unshield_recipient, 10)}: {tx.unshield_amount}</span>
                <span>fee={tx.fee}</span>
              </div>
              <div className="text-zinc-500 mt-0.5 text-[0.65rem]">
                nullifier={tx.nullifier} · proof={tx.proof_bytes}B
              </div>
            </div>
          ))}
          {starkMempool.length === 0 && <div className="text-zinc-600 text-xs">empty</div>}
        </div>
      </div>
    </div>
  );
}

function Controls({ peerHost, setPeerHost, peerPort, setPeerPort, doConnect,
                    txRecipient, setTxRecipient, txAmount, setTxAmount, doSendTx,
                    shieldAmount, setShieldAmount, doShield,
                    starkShieldValue, setStarkShieldValue, doStarkShield,
                    ownedStarkNotes, starkSpendIdx, setStarkSpendIdx,
                    starkSpendRecipient, setStarkSpendRecipient,
                    starkSpendAmount, setStarkSpendAmount, doStarkSpend,
                    mixerDenominations, mixerDenom, setMixerDenom, doMixerDeposit,
                    ownedMixerNotes, mixerWithdrawIdx, setMixerWithdrawIdx,
                    doMixerWithdraw,
                    doMine }) {
  return (
    <div className="panel p-4 space-y-4">
      <div className="text-sm text-zinc-400 uppercase tracking-wider">Controls</div>

      <div>
        <div className="text-xs text-zinc-500 mb-1.5">Connect to peer</div>
        <div className="flex gap-1">
          <input className="bg-zinc-900 px-2 py-1 text-sm flex-1 rounded"
            value={peerHost} onChange={e => setPeerHost(e.target.value)} placeholder="host"/>
          <input className="bg-zinc-900 px-2 py-1 text-sm w-20 rounded"
            value={peerPort} onChange={e => setPeerPort(e.target.value)} placeholder="port"/>
          <button onClick={doConnect}
            className="bg-indigo-600 hover:bg-indigo-500 px-3 py-1 text-sm rounded">Go</button>
        </div>
      </div>

      <div>
        <div className="text-xs text-zinc-500 mb-1.5">Send transparent tx (from this node's miner)</div>
        <div className="flex gap-1">
          <input className="bg-zinc-900 px-2 py-1 text-sm flex-1 rounded mono-trunc"
            value={txRecipient} onChange={e => setTxRecipient(e.target.value)} placeholder="recipient addr"/>
          <input className="bg-zinc-900 px-2 py-1 text-sm w-16 rounded"
            value={txAmount} onChange={e => setTxAmount(e.target.value)} placeholder="amt"/>
          <button onClick={doSendTx}
            className="bg-indigo-600 hover:bg-indigo-500 px-3 py-1 text-sm rounded">Send</button>
        </div>
      </div>

      <div>
        <div className="text-xs text-zinc-500 mb-1.5">Shield to anon pool (M4)</div>
        <div className="flex gap-1">
          <input className="bg-zinc-900 px-2 py-1 text-sm w-20 rounded"
            value={shieldAmount} onChange={e => setShieldAmount(e.target.value)} placeholder="amt"/>
          <button onClick={doShield}
            className="bg-purple-600 hover:bg-purple-500 px-3 py-1 text-sm rounded flex-1">Shield {shieldAmount}</button>
        </div>
      </div>

      <div>
        <div className="text-xs text-cyan-400 mb-1.5">Shield to STARK pool (M8.6)</div>
        <div className="flex gap-1">
          <input className="bg-zinc-900 px-2 py-1 text-sm w-20 rounded"
            value={starkShieldValue} onChange={e => setStarkShieldValue(e.target.value)} placeholder="value"/>
          <button onClick={doStarkShield}
            className="bg-cyan-600 hover:bg-cyan-500 px-3 py-1 text-sm rounded flex-1">Shield {starkShieldValue} (STARK)</button>
        </div>
      </div>

      <div>
        <div className="text-xs text-cyan-400 mb-1.5">
          Spend STARK note ({ownedStarkNotes.length} owned)
        </div>
        {ownedStarkNotes.length > 0 ? (
          <div className="space-y-1">
            <select className="bg-zinc-900 px-2 py-1 text-xs rounded w-full"
              value={starkSpendIdx} onChange={e => setStarkSpendIdx(e.target.value)}>
              {ownedStarkNotes.map((n, i) => (
                <option key={i} value={i}>
                  #{i}: value={n.value} leaf={n.leaf}
                </option>
              ))}
            </select>
            <div className="flex gap-1">
              <input className="bg-zinc-900 px-2 py-1 text-xs flex-1 rounded mono-trunc"
                value={starkSpendRecipient} onChange={e => setStarkSpendRecipient(e.target.value)}
                placeholder="recipient"/>
              <input className="bg-zinc-900 px-2 py-1 text-xs w-14 rounded"
                value={starkSpendAmount} onChange={e => setStarkSpendAmount(e.target.value)} placeholder="amt"/>
              <button onClick={doStarkSpend}
                className="bg-cyan-600 hover:bg-cyan-500 px-3 py-1 text-xs rounded">Spend</button>
            </div>
          </div>
        ) : (
          <div className="text-xs text-zinc-600">shield first to create a spendable note</div>
        )}
      </div>

      <div>
        <div className="text-xs text-emerald-400 mb-1.5">Deposit to mixer (M10)</div>
        <div className="flex gap-1">
          <select className="bg-zinc-900 px-2 py-1 text-sm rounded"
            value={mixerDenom} onChange={e => setMixerDenom(e.target.value)}>
            {(mixerDenominations || [1, 10, 100, 1000]).map(d => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <button onClick={doMixerDeposit}
            className="bg-emerald-600 hover:bg-emerald-500 px-3 py-1 text-sm rounded flex-1">
            Deposit {mixerDenom}
          </button>
        </div>
      </div>

      <div>
        <div className="text-xs text-emerald-400 mb-1.5">
          Withdraw from mixer ({ownedMixerNotes.length} owned)
        </div>
        {ownedMixerNotes.length > 0 ? (
          <div className="space-y-1">
            <select className="bg-zinc-900 px-2 py-1 text-xs rounded w-full"
              value={mixerWithdrawIdx} onChange={e => setMixerWithdrawIdx(e.target.value)}>
              {ownedMixerNotes.map((n, i) => (
                <option key={i} value={i}>
                  #{i}: value={n.value} leaf={n.leaf}
                </option>
              ))}
            </select>
            <button onClick={doMixerWithdraw}
              className="bg-emerald-600 hover:bg-emerald-500 px-3 py-1 text-xs rounded w-full">
              Withdraw selected → STARK pool (anonymous)
            </button>
            <div className="text-xs text-zinc-600">
              Mine first if deposit is still pending. Withdrawal credits a fresh STARK note.
            </div>
          </div>
        ) : (
          <div className="text-xs text-zinc-600">deposit first to create a withdrawable note</div>
        )}
      </div>

      <div>
        <div className="text-xs text-zinc-500 mb-1.5">Mine a block</div>
        <div className="flex gap-1">
          <button onClick={() => doMine(false)}
            className="bg-green-600 hover:bg-green-500 px-3 py-1 text-sm rounded flex-1">PoW</button>
          <button onClick={() => doMine(true)}
            className="bg-green-600 hover:bg-green-500 px-3 py-1 text-sm rounded flex-1">PoS (QRNG)</button>
        </div>
      </div>
    </div>
  );
}

function EventFeed({ events }) {
  return (
    <div className="panel p-4">
      <div className="text-sm text-zinc-400 mb-3 uppercase tracking-wider">Live Events</div>
      <div className="space-y-1.5 max-h-96 overflow-y-auto">
        {events.map((ev, i) => (
          <div key={ev._id} className={`text-xs p-2 rounded event-${ev.type.replace("_","-")} pulse-new`}>
            <div className="flex justify-between items-baseline">
              <div className="font-bold uppercase text-[10px] tracking-wider">{ev.type}</div>
              <div className="text-zinc-500">{ago(ev.ts)} from {short(ev.node_id, 6)}</div>
            </div>
            <div className="mt-1 text-zinc-400">
              {ev.type === "block" && (
                <span>
                  #{ev.data.index} · {ev.data.n_transparent_txs}t
                  {ev.data.n_anon_txs > 0 && <> + <span className="text-purple-400">{ev.data.n_anon_txs}a</span></>}
                  {(ev.data.n_stark_anon_txs ?? 0) > 0 && <> + <span className="text-cyan-300">{ev.data.n_stark_anon_txs}s</span></>}
                  {" · "}{short(ev.data.hash, 18)}
                </span>
              )}
              {ev.type === "tx" && (
                <span>{short(ev.data.sender, 8)} → {short(ev.data.recipient, 8)} : {ev.data.amount}</span>
              )}
              {ev.type === "anon_tx" && (
                <span>{ev.data.n_inputs}in/{ev.data.n_outputs}out · shield={ev.data.shield_in} unshield={ev.data.unshield_out}</span>
              )}
              {ev.type === "stark_anon_tx" && (
                <span className="text-cyan-200">
                  → {short(ev.data.unshield_recipient, 10)} : {ev.data.unshield_amount}
                  {" · "}{ev.data.proof_bytes}B proof
                </span>
              )}
              {ev.type === "shield_tx" && (
                <span className="text-cyan-300">
                  {short(ev.data.sender, 10)} shields {ev.data.amount} → STARK pool
                </span>
              )}
              {ev.type === "mixer_deposit" && (
                <span className="text-emerald-300">
                  {short(ev.data.sender, 10)} deposits {ev.data.amount} → mixer
                </span>
              )}
              {ev.type === "mixer_withdraw" && (
                <span className="text-emerald-200">
                  {ev.data.is_local ? (
                    <>anon withdraw {ev.data.denomination} → STARK pool <span className="text-emerald-500">(yours)</span></>
                  ) : (
                    <>anon withdraw (denomination private) → STARK pool</>
                  )}
                  {" · "}{ev.data.proof_bytes}B proof
                </span>
              )}
            </div>
          </div>
        ))}
        {events.length === 0 && <div className="text-zinc-600 text-xs">waiting for events…</div>}
      </div>
    </div>
  );
}

function Footer() {
  return (
    <div className="text-center text-xs text-zinc-700 mt-6">
      QChain · post-quantum signatures · quantum randomness · shielded notes ·
      Schnorr ZK proofs · zk-STARKs (M8.6) · P2P gossip
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--node-id", default=None, help="Optional node id")
    parser.add_argument("--port", type=int, default=19101, help="TCP port for P2P")
    parser.add_argument("--http", type=int, default=8101, help="HTTP port for dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument(
        "--peer", action="append", default=[],
        help="Peer to connect to (host:port). Can be repeated.",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Bearer token for /api/* and /ws auth. If unset, falls back "
             "to QCHAIN_DASHBOARD_TOKEN env var; if that's also unset, a "
             "fresh token is auto-generated and printed to stdout. Use "
             "'--auth-token disabled' or set the env var to empty to "
             "disable auth entirely (only safe on a trusted-localhost-only "
             "deployment).",
    )
    parser.add_argument(
        "--wallet",
        default=None,
        help="Path to a persistent wallet JSON file. If the file exists "
             "it is loaded; otherwise a new wallet is created and saved "
             "there. The wallet is auto-saved after every block so mined "
             "balance survives restarts. Without this flag, the wallet is "
             "ephemeral (new keypair every startup, zero balance).",
    )
    args = parser.parse_args()

    node = Node(args.host, args.port, node_id=args.node_id)
    node.start()
    # Auto-connect to peers after a short delay so they have time to start
    def connect_later():
        time.sleep(0.5)
        for peer in args.peer:
            host, port = peer.split(":")
            ok = node.connect_to(host, int(port))
            print(f"connect {peer} -> {ok}")
    threading.Thread(target=connect_later, daemon=True).start()

    import os
    dash = Dashboard(
        node,
        wallet_path=args.wallet or os.environ.get("QCHAIN_WALLET_PATH"),
    )
    # Rate limiting: in production, defaults are tight. The env vars
    # let tests and special deployments override. Setting to 0 disables.
    action_limit = int(os.environ.get(
        "QCHAIN_DASHBOARD_ACTION_RATE", str(DASHBOARD_RL_ACTION_PER_SEC)
    ))
    query_limit = int(os.environ.get(
        "QCHAIN_DASHBOARD_QUERY_RATE", str(DASHBOARD_RL_QUERY_PER_SEC)
    ))

    # Auth token resolution:
    #   1. CLI flag --auth-token (explicit; "disabled" → disable)
    #   2. env var QCHAIN_DASHBOARD_TOKEN (deploy-friendly; empty → disable)
    #   3. auto-generated, printed to stdout
    if args.auth_token is not None:
        if args.auth_token.lower() == "disabled":
            auth_token = None
        else:
            auth_token = args.auth_token
    elif "QCHAIN_DASHBOARD_TOKEN" in os.environ:
        env_token = os.environ["QCHAIN_DASHBOARD_TOKEN"]
        auth_token = env_token if env_token else None
    else:
        auth_token = _generate_auth_token()
        # Print prominently so the user can find it in console output
        print("=" * 70)
        print("DASHBOARD AUTH TOKEN (random, this session only):")
        print(f"   {auth_token}")
        print("Open the dashboard with this token in the URL:")
        print(f"   http://{args.host}:{args.http}/?token={auth_token}")
        print("Or pin a token via --auth-token or QCHAIN_DASHBOARD_TOKEN.")
        print("=" * 70)

    app = create_app(
        dash,
        rate_limit_action_per_sec=action_limit,
        rate_limit_query_per_sec=query_limit,
        auth_token=auth_token,
    )

    print(f"Node {node.node_id} on {args.host}:{args.port}")
    print(f"Dashboard at http://{args.host}:{args.http}/")
    if auth_token is None:
        print("WARNING: dashboard auth is DISABLED — all endpoints unprotected")
    try:
        uvicorn.run(app, host=args.host, port=args.http, log_level="warning")
    finally:
        node.stop()


if __name__ == "__main__":
    main()

"""
P2P node for QChain.

Each node:
  * Runs a TCP server accepting peer connections
  * Maintains outbound connections to a list of known peers
  * Sends and processes eight message types: hello, get_blocks, blocks,
    new_tx, new_anon_tx, new_stark_anon_tx, new_shield_tx, new_block
  * Adopts longer valid chains from peers
  * Gossips received transactions and blocks to all other peers

Honest scope notes:
  * No peer discovery — peer addresses are hardcoded at startup
  * No authentication — anyone who can connect is trusted
  * Per-peer per-message-type rate limiting added in ROADMAP 1.5
    (T15 closure). Defends against gossip floods of any single
    message type. Does NOT defend against authentication-style
    attacks; an attacker with N connection slots can still produce
    N × the per-peer limit of traffic. See RATE-LIMITING-README.md.
  * Fork resolution is "first longer valid chain wins" with naive
    full-chain replay. Real chains use a checkpoint/headers-first
    sync to avoid replay cost.
  * Concurrent block production by two nodes at the same height is
    handled: both blocks get gossiped; the next block extends one of
    them and the loser's contents return to mempool.
  * STARK transactions are gossiped just like M4 anon transactions:
    new_stark_anon_tx messages flood the network. Honest spender's
    Merkle root must match the receiver's chain state, so practically
    a STARK tx propagates within one block window. Stale txs are
    dropped at submit time (which is the correct behavior — the
    spender must reconstruct against the latest pool root).
  * M8.7-D: Shield transactions (new_shield_tx) also gossip. These
    are depositor-signed and populate the STARK pool via on-chain
    events, so nodes that replay the chain all end up with the same
    STARK pool. Closes the Gap D pool-replication issue from M8.5.

Wire format: newline-delimited JSON. Each message is:
    {"type": "...", "payload": {...}, "from": "<node_id>"}
Each connection sends one message per line. We use one socket per
direction so we can read and write concurrently from threads.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional, Set, Tuple

from qchain.chain.anon_tx import AnonTransaction
from qchain.chain.anon_stark_tx import STARKAnonTransaction
from qchain.chain.block import Block
from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import MixerDepositTransaction, MixerWithdrawTransaction
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.transaction import Transaction
from qchain.network.rate_limit import SlidingWindowRateLimiter


# ---------------------------------------------------------------------------
# Wire framing — newline-delimited JSON
# ---------------------------------------------------------------------------

def _send_msg(sock: socket.socket, msg: dict) -> None:
    """Send a single JSON message terminated by newline."""
    data = (json.dumps(msg) + "\n").encode("utf-8")
    sock.sendall(data)


def _recv_lines(sock: socket.socket, buf: bytearray) -> List[dict]:
    """Drain whatever's on the socket; return any complete JSON messages.

    Caller maintains the buffer across calls so partial messages survive.
    Returns [] if no complete message is yet available (or on disconnect).
    """
    try:
        chunk = sock.recv(65536)
    except (OSError, ConnectionError):
        return []
    if not chunk:
        return []
    buf.extend(chunk)
    msgs: List[dict] = []
    while b"\n" in buf:
        line, _, rest = buf.partition(b"\n")
        del buf[: len(line) + 1]
        if not line.strip():
            continue
        try:
            msgs.append(json.loads(line.decode("utf-8")))
        except json.JSONDecodeError:
            # Skip malformed lines; in production we'd ban the peer
            continue
    return msgs


# ---------------------------------------------------------------------------
# Rate limiting (T15 closure — ROADMAP 1.5)
# ---------------------------------------------------------------------------
# Per-peer per-message-type sliding-window limits. Calibrated to be
# generous for honest peers and devastating for an attacker. Honest
# rate of each message kind on a real chain:
#
#   - Tx-class messages (new_tx, new_anon_tx, etc.): a few per second
#     from an active spender. 10/sec/peer is ~10× headroom.
#   - new_block: ~1 per few seconds during active mining. 5/sec/peer
#     handles fork scenarios and is still firmly below abuse.
#   - get_blocks / blocks: bursty during initial sync. 20/sec/peer.
#   - hello: handshake, sent rarely. 2/sec/peer.
#
# An attacker bypassing these by opening N parallel connections gets
# N × the per-peer limit. That's the fundamental ceiling of per-peer
# rate limiting; closing this gap would require connection-rate
# limits + authentication, which are explicitly out of scope here.
# See RATE-LIMITING-README.md.
RATE_LIMIT_WINDOW_SECONDS = 1.0
RATE_LIMIT_TX_PER_SEC = 100       # tx-class messages
RATE_LIMIT_BLOCK_PER_SEC = 50     # new_block — bursts during fork-recovery or batched mining
RATE_LIMIT_SYNC_PER_SEC = 50      # get_blocks, blocks
RATE_LIMIT_HELLO_PER_SEC = 10     # hello


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class Node:
    """A P2P node wrapping a local Blockchain.

    Threading model:
      * One thread accepts inbound connections (`_accept_loop`)
      * One thread per peer connection (`_peer_loop`)
      * Optional one thread for periodic block production (caller-driven)
    The Blockchain is protected by `self.lock` — every mutation goes
    through it.
    """

    def __init__(
        self,
        host: str,
        port: int,
        node_id: Optional[str] = None,
        blockchain: Optional[Blockchain] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.chain: Blockchain = blockchain or Blockchain()

        # Concurrency
        self.lock = threading.RLock()       # protects self.chain
        self._stop = threading.Event()
        self._server: Optional[socket.socket] = None

        # Peer state: address -> live socket. Two-way connections share
        # one socket: whoever opens it owns it.
        self._peers: Dict[str, socket.socket] = {}
        self._peers_lock = threading.Lock()

        # Recent gossip cache so we don't re-broadcast forever.
        self._seen_msgs: Set[str] = set()
        self._seen_lock = threading.Lock()

        # Optional callbacks for the dashboard to hook into events later
        self.on_block: Optional[Callable[[Block], None]] = None
        self.on_tx: Optional[Callable[[Transaction], None]] = None
        self.on_anon_tx: Optional[Callable[[AnonTransaction], None]] = None
        self.on_stark_anon_tx: Optional[Callable[[STARKAnonTransaction], None]] = None
        self.on_shield_tx: Optional[Callable[[ShieldTransaction], None]] = None
        # M10: mixer event callbacks
        self.on_mixer_deposit: Optional[Callable[[MixerDepositTransaction], None]] = None
        self.on_mixer_withdraw: Optional[Callable[[MixerWithdrawTransaction], None]] = None

        # ROADMAP 1.5: per-peer per-message-type rate limiters (T15).
        # Tx-class messages all share one limiter — flooding "tx of any kind"
        # is the same DoS shape. Block, sync, and hello get their own limits.
        # Tests can reach in and reset() these between cases.
        self._rl_tx = SlidingWindowRateLimiter(
            capacity=RATE_LIMIT_TX_PER_SEC,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        )
        self._rl_block = SlidingWindowRateLimiter(
            capacity=RATE_LIMIT_BLOCK_PER_SEC,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        )
        self._rl_sync = SlidingWindowRateLimiter(
            capacity=RATE_LIMIT_SYNC_PER_SEC,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        )
        self._rl_hello = SlidingWindowRateLimiter(
            capacity=RATE_LIMIT_HELLO_PER_SEC,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        )
        # Counter for diagnostics / tests
        self._rate_limited_drops: int = 0

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def start(self) -> None:
        """Open the listening socket and start the accept thread."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(8)
        self._server.settimeout(0.5)  # short timeout so we can stop cleanly
        threading.Thread(
            target=self._accept_loop, name=f"{self.node_id}-accept", daemon=True
        ).start()

    def stop(self) -> None:
        self._stop.set()
        with self._peers_lock:
            for sock in list(self._peers.values()):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
            self._peers.clear()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass

    def connect_to(self, host: str, port: int) -> bool:
        """Open an outbound connection to a peer. Returns True on success."""
        addr = f"{host}:{port}"
        if addr in self._peers:
            return True
        try:
            sock = socket.create_connection((host, port), timeout=2.0)
        except (OSError, socket.timeout):
            return False
        sock.settimeout(0.5)
        with self._peers_lock:
            self._peers[addr] = sock
        threading.Thread(
            target=self._peer_loop, args=(sock, addr),
            name=f"{self.node_id}-peer-{addr}", daemon=True,
        ).start()
        # Kick off the handshake
        self._send_to(sock, {
            "type": "hello",
            "from": self.node_id,
            "payload": {"height": self._height()},
        })
        return True

    # -----------------------------------------------------------------
    # Threads
    # -----------------------------------------------------------------

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                sock, peer_addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            sock.settimeout(0.5)
            addr = f"{peer_addr[0]}:{peer_addr[1]}"
            with self._peers_lock:
                self._peers[addr] = sock
            threading.Thread(
                target=self._peer_loop, args=(sock, addr),
                name=f"{self.node_id}-peer-{addr}", daemon=True,
            ).start()

    def _peer_loop(self, sock: socket.socket, addr: str) -> None:
        """Read messages from one peer until disconnect."""
        buf = bytearray()
        while not self._stop.is_set():
            msgs = _recv_lines(sock, buf)
            if not msgs and buf == bytearray():
                # No data; check if socket is closed
                try:
                    # Peek without consuming
                    sock.settimeout(0.1)
                    peek = sock.recv(1, socket.MSG_PEEK)
                    if not peek:
                        break
                    sock.settimeout(0.5)
                except socket.timeout:
                    continue
                except OSError:
                    break
            for msg in msgs:
                try:
                    self._handle_message(sock, addr, msg)
                except Exception as e:
                    # In production, ban the peer; here, just log.
                    print(f"[{self.node_id}] error from {addr}: {e}")
        # Disconnected; clean up
        with self._peers_lock:
            self._peers.pop(addr, None)
        try:
            sock.close()
        except OSError:
            pass

    # -----------------------------------------------------------------
    # Message handlers
    # -----------------------------------------------------------------

    def _handle_message(self, sock: socket.socket, peer_addr: str, msg: dict) -> None:
        msg_type = msg.get("type")
        payload = msg.get("payload", {})
        sender = msg.get("from", "?")

        # ROADMAP 1.5 (T15): per-peer per-message-type rate limit.
        # If the peer is over the limit for THIS message type, drop the
        # message silently. We don't disconnect — the limiter naturally
        # bounds work without making honest peers ban-able by transient
        # bursts. Logging is on for diagnostics.
        limiter = self._limiter_for_type(msg_type)
        if limiter is not None and not limiter.try_consume(peer_addr):
            self._rate_limited_drops += 1
            # Keep diagnostic noise low — don't log every drop, but the
            # counter is available via the dashboard later if we add it.
            return

        if msg_type == "hello":
            self._handle_hello(sock, sender, payload)
        elif msg_type == "get_blocks":
            self._handle_get_blocks(sock, payload)
        elif msg_type == "blocks":
            self._handle_blocks(payload)
        elif msg_type == "new_tx":
            self._handle_new_tx(payload)
        elif msg_type == "new_anon_tx":
            self._handle_new_anon_tx(payload)
        elif msg_type == "new_stark_anon_tx":
            self._handle_new_stark_anon_tx(payload)
        elif msg_type == "new_shield_tx":
            self._handle_new_shield_tx(payload)
        elif msg_type == "new_mixer_deposit":
            self._handle_new_mixer_deposit(payload)
        elif msg_type == "new_mixer_withdraw":
            self._handle_new_mixer_withdraw(payload)
        elif msg_type == "new_block":
            self._handle_new_block(payload)
        # Unknown types: ignored. A real node would close the connection
        # after too many invalid messages.

    def _limiter_for_type(self, msg_type: Optional[str]) -> Optional[SlidingWindowRateLimiter]:
        """Return the right rate limiter for a given message type, or None
        if the message type is unknown (in which case the dispatcher
        will ignore it anyway — no rate limit needed)."""
        if msg_type in (
            "new_tx", "new_anon_tx", "new_stark_anon_tx",
            "new_shield_tx", "new_mixer_deposit", "new_mixer_withdraw",
        ):
            return self._rl_tx
        if msg_type == "new_block":
            return self._rl_block
        if msg_type in ("get_blocks", "blocks"):
            return self._rl_sync
        if msg_type == "hello":
            return self._rl_hello
        return None

    def _handle_hello(self, sock: socket.socket, sender: str, payload: dict) -> None:
        """Respond to a hello with our own hello + maybe request blocks.

        Bidirectional handshake: whichever side is shorter requests blocks.
        We send our own hello back so the connecting peer can compare
        heights too — without this, only the connector knows about the
        connectee's chain length.
        """
        their_height = int(payload.get("height", 0))
        my_height = self._height()
        # Send our hello back (but only the first time per connection, by
        # checking if we've already greeted this sender).
        already_greeted = f"hello-back:{sender}"
        if self._mark_seen(already_greeted):
            self._send_to(sock, {
                "type": "hello",
                "from": self.node_id,
                "payload": {"height": my_height},
            })
        # If they're taller, ask for the missing blocks.
        if their_height > my_height:
            self._send_to(sock, {
                "type": "get_blocks",
                "from": self.node_id,
                "payload": {"from_height": my_height + 1},
            })

    def _handle_get_blocks(self, sock: socket.socket, payload: dict) -> None:
        from_height = int(payload.get("from_height", 1))
        with self.lock:
            blocks = self.chain.blocks[from_height:]
            block_dicts = [b.to_dict() for b in blocks]
        self._send_to(sock, {
            "type": "blocks",
            "from": self.node_id,
            "payload": {"blocks": block_dicts},
        })

    def _handle_blocks(self, payload: dict) -> None:
        """Receive a batch of blocks; adopt if they extend our chain."""
        block_dicts = payload.get("blocks", [])
        if not block_dicts:
            return
        try:
            new_blocks = [Block.from_dict(d) for d in block_dicts]
        except Exception as e:
            print(f"[{self.node_id}] couldn't deserialize blocks: {e}")
            return
        with self.lock:
            adopted = self._try_extend_or_replace(new_blocks)
            my_height = self.chain.height
        # If we couldn't adopt because of a deeper fork, ask for the full
        # chain from genesis. A real chain would binary-search for the
        # common ancestor; for an educational P2P, full re-sync is fine.
        #
        # GUARD: don't re-request if the alternative chain we just received
        # is no longer than our own. That's the same-length-fork case
        # (e.g. two miners producing competing height-1 blocks); re-requesting
        # creates an infinite get_blocks/blocks ping-pong between peers
        # since neither chain is preferred. We just wait for the next block
        # to extend one of them. ROADMAP 1.5 surfaced this — the rate
        # limiter made the ping-pong loop hit the sync rate limit, which
        # in turn deterministically broke test_concurrent_blocks_resolved.
        if not adopted and len(new_blocks) > 0:
            alt_height = new_blocks[-1].index if new_blocks else 0
            if alt_height > my_height:
                self._request_from_all(from_height=1)

    def _handle_new_tx(self, payload: dict) -> None:
        try:
            tx = Transaction.from_dict(payload)
        except Exception:
            return
        # Suppress re-gossip of duplicates
        if not self._mark_seen("tx:" + tx.txid()):
            return
        with self.lock:
            try:
                self.chain.submit(tx)
            except ValueError:
                return  # invalid or already known
        if self.on_tx:
            self.on_tx(tx)
        self._gossip({"type": "new_tx", "from": self.node_id, "payload": payload})

    def _handle_new_anon_tx(self, payload: dict) -> None:
        try:
            atx = AnonTransaction.from_dict(payload)
        except Exception as e:
            print(f"[{self.node_id}] bad anon tx: {e}")
            return
        if not self._mark_seen("atx:" + atx.txid()):
            return
        with self.lock:
            try:
                self.chain.submit_anon(atx)
            except ValueError:
                return
        if self.on_anon_tx:
            self.on_anon_tx(atx)
        self._gossip({"type": "new_anon_tx", "from": self.node_id, "payload": payload})

    def _handle_new_stark_anon_tx(self, payload: dict) -> None:
        """Handle an incoming M8.5/M8.6 STARK-anon transaction.

        Stale-root behavior: a STARK tx attests against a specific Merkle
        root. If our chain's STARK pool has moved on, submit_stark_anon
        will reject the tx with "stale Merkle root" — which is correct.
        The spender must rebuild the proof against the new root. We
        therefore swallow ValueError silently here, the same way the
        M4 path does. Network propagation doesn't fail; the tx just
        doesn't enter our mempool.

        Note: STARK tx verification involves running the Winterfell
        verifier on a ~29 KB proof. That's ~0.3-0.4 ms of CPU per tx.
        At high gossip rates this could become a DoS vector. A real
        node would rate-limit and/or batch-verify. Out of scope here.
        """
        try:
            stx = STARKAnonTransaction.from_dict(payload)
        except Exception as e:
            print(f"[{self.node_id}] bad stark-anon tx: {e}")
            return
        if not self._mark_seen("stx:" + stx.txid()):
            return
        with self.lock:
            try:
                self.chain.submit_stark_anon(stx)
            except ValueError:
                # Stale root, double-spend, or invalid proof — drop silently
                return
        if self.on_stark_anon_tx:
            self.on_stark_anon_tx(stx)
        self._gossip({"type": "new_stark_anon_tx", "from": self.node_id, "payload": payload})

    def _handle_new_shield_tx(self, payload: dict) -> None:
        """Handle an incoming M8.7-D shield transaction.

        Validation happens inside `chain.submit_shield`:
          * signature verifies (depositor controls the address)
          * depositor has the funds (taking pending shields/txs into account)
          * amount > 0, leaf well-formed

        Any of these fail → ValueError, we drop the message silently.
        Successful submission gossips onward.
        """
        try:
            shtx = ShieldTransaction.from_dict(payload)
        except Exception as e:
            print(f"[{self.node_id}] bad shield tx: {e}")
            return
        if not self._mark_seen("shld:" + shtx.txid()):
            return
        with self.lock:
            try:
                self.chain.submit_shield(shtx)
            except ValueError:
                # Insufficient balance, bad sig, etc — drop silently
                return
        if self.on_shield_tx:
            self.on_shield_tx(shtx)
        self._gossip({"type": "new_shield_tx", "from": self.node_id, "payload": payload})

    def _handle_new_mixer_deposit(self, payload: dict) -> None:
        """M10: handle incoming mixer deposit gossip.

        Validation in chain.submit_mixer_deposit:
          * signature verifies (depositor controls the address)
          * amount is a valid denomination
          * depositor has sufficient balance (accounting for pending mempool)
        Any failure → ValueError, drop silently. Successful submission
        gossips onward.
        """
        try:
            mdtx = MixerDepositTransaction.from_dict(payload)
        except Exception as e:
            print(f"[{self.node_id}] bad mixer deposit: {e}")
            return
        if not self._mark_seen("md:" + mdtx.txid()):
            return
        with self.lock:
            try:
                self.chain.submit_mixer_deposit(mdtx)
            except ValueError:
                return
        if self.on_mixer_deposit:
            self.on_mixer_deposit(mdtx)
        self._gossip({"type": "new_mixer_deposit", "from": self.node_id, "payload": payload})

    def _handle_new_mixer_withdraw(self, payload: dict) -> None:
        """M10: handle incoming mixer withdrawal gossip.

        Validation in chain.submit_mixer_withdraw:
          * STARK proof verifies against current mixer pool root + nullifier set
          * The proof's bound public inputs (root, nullifier, output_leaf,
            unshield_amount=0, fee=0) match what the prover committed to via FS
        Stale-root rejections (the mixer pool moved on) drop silently —
        the spender must rebuild against the new root.
        """
        try:
            mwtx = MixerWithdrawTransaction.from_dict(payload)
        except Exception as e:
            print(f"[{self.node_id}] bad mixer withdraw: {e}")
            return
        if not self._mark_seen("mw:" + mwtx.txid()):
            return
        with self.lock:
            try:
                self.chain.submit_mixer_withdraw(mwtx)
            except ValueError:
                return
        if self.on_mixer_withdraw:
            self.on_mixer_withdraw(mwtx)
        self._gossip({"type": "new_mixer_withdraw", "from": self.node_id, "payload": payload})

    def _handle_new_block(self, payload: dict) -> None:
        try:
            block = Block.from_dict(payload)
        except Exception as e:
            print(f"[{self.node_id}] bad block: {e}")
            return
        # ROADMAP 1.5 (T23): reject oversized blocks cheaply, before
        # any chain-side work. is_valid() also checks this — but the
        # admission-side check saves the wasted parse / replay cost
        # if the block is obviously bogus.
        from qchain.chain.blockchain import MAX_BLOCK_TX_COUNT
        total_tx_count = (
            len(block.transactions)
            + len(block.anon_transactions)
            + len(block.stark_anon_transactions)
            + len(block.shield_transactions)
            + len(block.mixer_deposit_transactions)
            + len(block.mixer_withdraw_transactions)
        )
        if total_tx_count > MAX_BLOCK_TX_COUNT:
            print(
                f"[{self.node_id}] dropping oversized block: "
                f"{total_tx_count} txs > MAX_BLOCK_TX_COUNT={MAX_BLOCK_TX_COUNT}"
            )
            return
        if not self._mark_seen("blk:" + block.hash()):
            return
        with self.lock:
            adopted = self._try_extend_or_replace([block])
        # If we couldn't connect this block to our chain, we're probably
        # on a different fork. Request the chain from genesis so we can
        # see if there's a longer valid alternative.
        if not adopted:
            self._request_from_all(from_height=1)
        if self.on_block:
            self.on_block(block)
        self._gossip({"type": "new_block", "from": self.node_id, "payload": payload})

    # -----------------------------------------------------------------
    # Chain logic
    # -----------------------------------------------------------------

    def _try_extend_or_replace(self, new_blocks: List[Block]) -> bool:
        """Either extend our chain with new blocks, or replace it if a
        longer valid alternative chain is on offer.

        Returns True if we adopted any new blocks.

        Strategy:
          1. If the first new block extends our current tip → extend.
          2. Otherwise, splice new_blocks onto whichever prefix of our
             own chain has a matching previous_hash, then check if the
             alternative is longer AND valid.
          3. Drop incompatible blocks otherwise.

        Mempool handling: if we replace blocks, their transactions are
        re-submitted to the mempool so they're not lost (unless they're
        now invalid against the new state).
        """
        if not new_blocks:
            return False

        # Case 1: direct extension
        if new_blocks[0].previous_hash == self.chain.head.hash():
            adopted_any = False
            for b in new_blocks:
                if b.previous_hash != self.chain.head.hash():
                    break
                self.chain.blocks.append(b)
                # M-timing: _apply_block_state includes the mixer_root_history
                # snapshot at the right moment (after deposits, before
                # withdrawals).
                self.chain._apply_block_state(b)
                adopted_any = True
            return adopted_any

        # Case 2: see if the new blocks fork from somewhere in our chain
        fork_at: Optional[int] = None
        for i, b in enumerate(self.chain.blocks):
            if b.hash() == new_blocks[0].previous_hash:
                fork_at = i
                break
        if fork_at is None:
            # No common ancestor — caller may want to re-sync from earlier
            return False

        alt_height = fork_at + len(new_blocks)
        if alt_height <= self.chain.height:
            return False  # alternative isn't longer

        # Build a candidate chain and validate it
        candidate = Blockchain()
        candidate.blocks = self.chain.blocks[: fork_at + 1] + list(new_blocks)
        from qchain.crypto.merkle import MerkleTree
        candidate.anon_tree = MerkleTree()
        candidate.nullifiers = set()
        candidate.mined_txids = set()
        # M8.7-D: STARK pool is now FULLY rebuildable from chain history.
        # Shield txs add leaves; STARK-anon txs mark nullifiers. Both are
        # on-chain events, so a fork resolution can deterministically
        # reconstruct the STARK pool state. This closes Gap D.
        from qchain.crypto.anon_stark import STARKAnonTree
        candidate.stark_anon_tree = STARKAnonTree()
        candidate.stark_nullifiers = set()
        # M10: mixer pool state is also chain-replicated, same idea.
        candidate.mixer_tree = STARKAnonTree()
        candidate.mixer_nullifiers = set()
        # M-timing: candidate's mixer_root_history starts at genesis.
        candidate.mixer_root_history = [candidate.mixer_tree.root()]
        candidate.mixer_leaf_count_history = [0]
        for b in candidate.blocks[1:]:
            # M-timing: _apply_block_state correctly snapshots
            # mixer_root_history at the right point in the canonical order.
            candidate._apply_block_state(b)

        if not candidate.is_valid():
            return False

        # Adopt!
        old_tail = self.chain.blocks[fork_at + 1 :]
        self.chain.blocks = candidate.blocks
        self.chain.anon_tree = candidate.anon_tree
        self.chain.nullifiers = candidate.nullifiers
        self.chain.mined_txids = candidate.mined_txids
        self.chain.stark_anon_tree = candidate.stark_anon_tree
        self.chain.stark_nullifiers = candidate.stark_nullifiers
        # M10: also copy mixer state
        self.chain.mixer_tree = candidate.mixer_tree
        self.chain.mixer_nullifiers = candidate.mixer_nullifiers
        # M-timing: copy mixer root/leaf-count history — without this,
        # mixer withdrawal anchor validation uses stale roots after a
        # chain reorganization and rejects valid withdrawals.
        self.chain.mixer_root_history = candidate.mixer_root_history
        self.chain.mixer_leaf_count_history = candidate.mixer_leaf_count_history

        # Re-submit transactions from the orphaned blocks to the mempool
        for ob in old_tail:
            for tx in ob.transactions:
                if tx.sender == "COINBASE":
                    continue
                try:
                    self.chain.submit(tx)
                except ValueError:
                    pass
            for atx in ob.anon_transactions:
                try:
                    self.chain.submit_anon(atx)
                except ValueError:
                    pass
            for stx in ob.stark_anon_transactions:
                try:
                    self.chain.submit_stark_anon(stx)
                except ValueError:
                    # Likely stale root after re-org — spender must rebuild
                    pass
            for shtx in ob.shield_transactions:
                try:
                    self.chain.submit_shield(shtx)
                except ValueError:
                    # Depositor might now have insufficient balance in the
                    # new chain history — drop, they can re-shield later.
                    pass
            # M10: re-submit orphaned mixer deposits and withdrawals.
            # Deposits may fail if the depositor's balance is now
            # insufficient in the new chain; withdrawals may fail if
            # the anchor root no longer matches or timing constraints
            # aren't met. In both cases, drop silently — the user can
            # re-create them against the new chain state.
            for mdtx in ob.mixer_deposit_transactions:
                try:
                    self.chain.submit_mixer_deposit(mdtx)
                except ValueError:
                    pass
            for mwtx in ob.mixer_withdraw_transactions:
                try:
                    self.chain.submit_mixer_withdraw(mwtx)
                except ValueError:
                    # Likely stale anchor root after re-org — spender
                    # must rebuild the withdrawal against the new chain.
                    pass
        return True

    def _request_from_all(self, from_height: int) -> None:
        """Ask every connected peer for their chain starting at from_height."""
        # Don't dedup here: chain state can legitimately change rapidly
        # (e.g. concurrent block arrival followed by extension), and we
        # need fresh requests to catch up. Dedup at the peer level is
        # cheaper than retrying.
        msg = {
            "type": "get_blocks",
            "from": self.node_id,
            "payload": {"from_height": from_height},
        }
        with self._peers_lock:
            peers = list(self._peers.values())
        for sock in peers:
            self._send_to(sock, msg)

    # -----------------------------------------------------------------
    # Public API for callers (tests, the dashboard, the CLI)
    # -----------------------------------------------------------------

    def submit_tx(self, tx: Transaction) -> None:
        """Submit a transparent tx locally AND broadcast to peers."""
        with self.lock:
            self.chain.submit(tx)
        # Mark seen BEFORE gossiping so any echo from a peer doesn't
        # cause us to re-submit it to our own mempool.
        self._mark_seen("tx:" + tx.txid())
        if self.on_tx:
            self.on_tx(tx)
        self._gossip({"type": "new_tx", "from": self.node_id, "payload": tx.to_dict()})

    def submit_anon_tx(self, atx: AnonTransaction) -> None:
        """Submit an anon tx locally AND broadcast to peers."""
        with self.lock:
            self.chain.submit_anon(atx)
        self._mark_seen("atx:" + atx.txid())
        if self.on_anon_tx:
            self.on_anon_tx(atx)
        self._gossip({
            "type": "new_anon_tx",
            "from": self.node_id,
            "payload": atx.to_dict(),
        })

    def submit_stark_anon_tx(self, stx: STARKAnonTransaction) -> None:
        """Submit a STARK-anon tx locally AND broadcast to peers."""
        with self.lock:
            self.chain.submit_stark_anon(stx)
        self._mark_seen("stx:" + stx.txid())
        if self.on_stark_anon_tx:
            self.on_stark_anon_tx(stx)
        self._gossip({
            "type": "new_stark_anon_tx",
            "from": self.node_id,
            "payload": stx.to_dict(),
        })

    def submit_shield_tx(self, shtx: ShieldTransaction) -> None:
        """Submit a M8.7-D shield tx locally AND broadcast to peers."""
        with self.lock:
            self.chain.submit_shield(shtx)
        self._mark_seen("shld:" + shtx.txid())
        if self.on_shield_tx:
            self.on_shield_tx(shtx)
        self._gossip({
            "type": "new_shield_tx",
            "from": self.node_id,
            "payload": shtx.to_dict(),
        })

    def submit_mixer_deposit_tx(self, mdtx: MixerDepositTransaction) -> None:
        """M10: submit a mixer deposit locally AND broadcast to peers."""
        with self.lock:
            self.chain.submit_mixer_deposit(mdtx)
        self._mark_seen("md:" + mdtx.txid())
        if self.on_mixer_deposit:
            self.on_mixer_deposit(mdtx)
        self._gossip({
            "type": "new_mixer_deposit",
            "from": self.node_id,
            "payload": mdtx.to_dict(),
        })

    def submit_mixer_withdraw_tx(self, mwtx: MixerWithdrawTransaction) -> None:
        """M10: submit a mixer withdrawal locally AND broadcast to peers."""
        with self.lock:
            self.chain.submit_mixer_withdraw(mwtx)
        self._mark_seen("mw:" + mwtx.txid())
        if self.on_mixer_withdraw:
            self.on_mixer_withdraw(mwtx)
        self._gossip({
            "type": "new_mixer_withdraw",
            "from": self.node_id,
            "payload": mwtx.to_dict(),
        })

    def broadcast_block(self, block: Block) -> None:
        """After producing a block, gossip it to all peers."""
        self._mark_seen("blk:" + block.hash())
        if self.on_block:
            self.on_block(block)
        self._gossip({
            "type": "new_block",
            "from": self.node_id,
            "payload": block.to_dict(),
        })

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _height(self) -> int:
        with self.lock:
            return self.chain.height

    def _send_to(self, sock: socket.socket, msg: dict) -> None:
        try:
            _send_msg(sock, msg)
        except OSError:
            pass  # peer disconnected; cleaned up in peer_loop

    def _gossip(self, msg: dict) -> None:
        """Send a message to all connected peers."""
        with self._peers_lock:
            peers = list(self._peers.values())
        for sock in peers:
            self._send_to(sock, msg)

    def _mark_seen(self, key: str) -> bool:
        """Return True if this is the first time we've seen `key`."""
        with self._seen_lock:
            if key in self._seen_msgs:
                return False
            self._seen_msgs.add(key)
            # Bound the cache so it doesn't grow forever
            if len(self._seen_msgs) > 10000:
                # Drop the oldest 5000 (cheap-ish in CPython 3.7+)
                self._seen_msgs = set(list(self._seen_msgs)[5000:])
            return True

    def peer_count(self) -> int:
        with self._peers_lock:
            return len(self._peers)

    def wait_until_synced(self, target_height: int, timeout: float = 5.0) -> bool:
        """Block until our height >= target. Returns True on success."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._height() >= target_height:
                return True
            time.sleep(0.05)
        return False

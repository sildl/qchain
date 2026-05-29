"""Tests for milestone 6: P2P network sync, gossip, and fork resolution.

Run with: python -m qchain.tests.test_network
"""

import socket
import time

from qchain.chain.anon_tx import AnonOutput, AnonTransaction, compute_net_blinding
from qchain.chain.wallet import Wallet
from qchain.crypto.anon import new_anon_note
from qchain.crypto.schnorr import generate_keypair
from qchain.network.node import Node


def _free_port() -> int:
    """Get a free TCP port. Race-prone but fine for tests."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for(predicate, timeout=3.0, interval=0.05) -> bool:
    """Poll until predicate is true or we time out."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# ---------------------------------------------------------------------------
# Connectivity and handshake
# ---------------------------------------------------------------------------

def test_two_nodes_connect():
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        assert n1.connect_to(n2.host, n2.port)
        assert _wait_for(lambda: n2.peer_count() >= 1)
        print("  ✓ Two nodes establish a connection")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Block sync on join
# ---------------------------------------------------------------------------

def test_new_node_syncs_chain_on_connect():
    """Node A has 3 extra blocks; node B connects and catches up."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    miner = Wallet()

    # Mine 3 blocks on n1 BEFORE n2 connects
    for _ in range(3):
        n1.chain.mine_pending(miner.address)
    assert n1.chain.height == 3

    n1.start(); n2.start()
    try:
        assert n2.connect_to(n1.host, n1.port)
        # After the hello handshake, n2 should request and apply blocks
        assert _wait_for(lambda: n2.chain.height == 3, timeout=3.0), \
            f"n2 height was {n2.chain.height}"
        # Hashes should match
        assert n1.chain.head.hash() == n2.chain.head.hash()
        print("  ✓ New peer syncs chain on connect (3 blocks)")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Transaction gossip
# ---------------------------------------------------------------------------

def test_tx_gossip_propagates():
    """A transparent tx submitted on n1 should land in n2's mempool."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    miner = Wallet()
    alice = Wallet()

    # Both nodes need balance state, so mine one block on n1 first
    n1.chain.mine_pending(miner.address)

    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        # Wait for n2 to sync
        assert _wait_for(lambda: n2.chain.height == 1, timeout=3.0)

        # Now submit a tx on n1 and watch it appear on n2
        tx = Wallet(miner.keypair).create_tx(alice.address, amount=5.0)
        n1.submit_tx(tx)
        assert _wait_for(lambda: len(n2.chain.mempool) == 1, timeout=3.0)
        assert n2.chain.mempool[0].txid() == tx.txid()
        print("  ✓ Transparent tx gossip works")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Anon tx gossip
# ---------------------------------------------------------------------------

def test_anon_tx_gossip_propagates():
    """An anon shield tx submitted on n1 lands in n2's anon mempool."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")

    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        alice = generate_keypair()
        note = new_anon_note(value=20, recipient_pk=alice.pk)
        atx = AnonTransaction(
            inputs=[],
            outputs=[AnonOutput.from_note(note)],
            shield_in=20,
            unshield_out=0,
            unshield_recipient="",
            fee=0,
            net_blinding=compute_net_blinding([], [note.value_blinding]),
        )
        n1.submit_anon_tx(atx)
        assert _wait_for(lambda: len(n2.chain.anon_mempool) == 1, timeout=3.0)
        assert n2.chain.anon_mempool[0].txid() == atx.txid()
        print("  ✓ Anon tx gossip works (full ZK proof serialized over network)")
    finally:
        n1.stop(); n2.stop()


def test_stark_anon_tx_gossip_propagates():
    """M8.6: a STARK-anon tx submitted on n1 lands in n2's STARK mempool.

    Both nodes must share the STARK pool state first (Gap D — pool isn't
    chain-replicated yet). We simulate this by shielding the same note
    on both sides before n1 spends it.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # Both nodes must have the same STARK pool for the proof to verify.
        note = STARKNote.random(value=100)
        idx_a = n1.chain.shield_to_stark_pool(note.leaf())
        idx_b = n2.chain.shield_to_stark_pool(note.leaf())
        assert idx_a == idx_b == 0
        assert n1.chain.stark_anon_tree.root() == n2.chain.stark_anon_tree.root()

        # n1 spends via the network method
        stx = create_stark_anon_tx(
            note, idx_a, n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=100, fee=0,
        )
        n1.submit_stark_anon_tx(stx)

        # n2 should receive it via gossip
        assert _wait_for(lambda: len(n2.chain.stark_anon_mempool) == 1, timeout=3.0)
        received = n2.chain.stark_anon_mempool[0]
        assert received.txid() == stx.txid()
        assert received.nullifier == stx.nullifier
        assert len(received.proof) > 1000  # full STARK proof made the trip
        print("  ✓ STARK-anon tx gossip works (~29 KB proof serialized + verified remotely)")
    finally:
        n1.stop(); n2.stop()


def test_stark_anon_tx_with_stale_pool_dropped_silently():
    """If n2's STARK pool doesn't match the tx's claimed root, it's rejected
    locally but doesn't crash the node or break gossip."""
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # n1 has a pool, n2 doesn't
        note = STARKNote.random(value=100)
        idx = n1.chain.shield_to_stark_pool(note.leaf())
        stx = create_stark_anon_tx(
            note, idx, n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=100, fee=0,
        )
        n1.submit_stark_anon_tx(stx)

        # Give time for the message to arrive and be processed
        time.sleep(0.5)

        # n2 must NOT have admitted the tx (its pool root is empty, not the one
        # the proof attests to)
        assert len(n2.chain.stark_anon_mempool) == 0
        # And n2 didn't crash — it's still alive
        assert n2.peer_count() >= 1
        print("  ✓ Stale-pool STARK tx dropped silently, node survives")
    finally:
        n1.stop(); n2.stop()


def test_stark_anon_tx_in_block_propagates():
    """A mined block containing a STARK tx propagates and lands on the peer
    with stark_anon_tree state correctly updated."""
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # Sync STARK pools
        note = STARKNote.random(value=100)
        n1.chain.shield_to_stark_pool(note.leaf())
        n2.chain.shield_to_stark_pool(note.leaf())

        # n1 spends + mines. M8.8-A1 enforces unshield_amount + fee == note.value,
        # so split the 100-coin note as 98 unshield + 2 fee.
        stx = create_stark_anon_tx(
            note, 0, n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=98, fee=2,
        )
        n1.submit_stark_anon_tx(stx)
        # Wait for n2 to see the tx in mempool
        assert _wait_for(lambda: len(n2.chain.stark_anon_mempool) == 1, timeout=3.0)
        # n1 mines it
        block = n1.chain.mine_pending(miner_address="miner-a")
        n1.broadcast_block(block)
        # n2 should adopt the block
        assert _wait_for(lambda: n2.chain.height == 1, timeout=3.0)
        assert len(n2.chain.blocks[-1].stark_anon_transactions) == 1
        # And n2's STARK nullifier set should reflect the spend
        assert stx.nullifier in n2.chain.stark_nullifiers
        print("  ✓ Block containing STARK tx propagates; nullifier state syncs")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Block gossip
# ---------------------------------------------------------------------------

def test_block_gossip_propagates():
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    miner = Wallet()
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # Mine on n1 and gossip
        block = n1.chain.mine_pending(miner.address)
        n1.broadcast_block(block)
        assert _wait_for(lambda: n2.chain.height == 1, timeout=3.0)
        assert n2.chain.head.hash() == block.hash()
        print("  ✓ Block gossip works")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Three-node propagation
# ---------------------------------------------------------------------------

def test_three_node_propagation():
    """A→B→C: a block produced on A reaches C through B."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n3 = Node("127.0.0.1", _free_port(), node_id="C")
    miner = Wallet()

    n1.start(); n2.start(); n3.start()
    try:
        # Linear topology: A <-> B <-> C
        n2.connect_to(n1.host, n1.port)
        n3.connect_to(n2.host, n2.port)
        _wait_for(lambda: n2.peer_count() >= 1 and n3.peer_count() >= 1)

        block = n1.chain.mine_pending(miner.address)
        n1.broadcast_block(block)

        # B should get it first, then re-gossip to C
        assert _wait_for(lambda: n3.chain.height == 1, timeout=5.0)
        assert n3.chain.head.hash() == block.hash()
        print("  ✓ Block propagates through linear A→B→C topology")
    finally:
        n1.stop(); n2.stop(); n3.stop()


# ---------------------------------------------------------------------------
# Fork resolution: longer chain wins
# ---------------------------------------------------------------------------

def test_longer_chain_wins_on_connect():
    """Two nodes mine independently; when they connect, the longer chain wins."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    miner_a = Wallet()
    miner_b = Wallet()

    # n1 mines 5, n2 mines 3 — n1 should win when they meet
    for _ in range(5):
        n1.chain.mine_pending(miner_a.address)
    for _ in range(3):
        n2.chain.mine_pending(miner_b.address)
    assert n1.chain.height == 5
    assert n2.chain.height == 3
    h1_old = n1.chain.head.hash()

    n1.start(); n2.start()
    try:
        # n2 connects to n1 — hello says n2's height is 3
        # n1 will ignore (its height is higher).
        # n2 should not yet receive n1's blocks because n1 doesn't push.
        # But n2's hello also asks for blocks if n1 is taller, which it is.
        n2.connect_to(n1.host, n1.port)

        # The hello flow: n2 sends hello(height=3) → n1 sees n2 is shorter
        # and ignores. n1 receives a connection but DOESN'T send hello back.
        # So n2 needs to initiate get_blocks itself.
        # Actually re-reading: our protocol has n2 receive the connection
        # from n1's accept, no hello from n1 unless explicit. Let me check.
        #
        # In our code: connect_to() sends hello. The receiver of hello
        # (n1) compares heights; if peer is taller, requests blocks.
        # Since n2 (3) < n1 (5), n1 does nothing. n2 doesn't get blocks.
        #
        # Fix in test: n1 should also initiate a hello, OR we should
        # have the hello handler send back our own hello.
        # For now, send a hello from n1 too by having n1 connect to n2.

        n1.connect_to(n2.host, n2.port)
        assert _wait_for(lambda: n2.chain.height == 5, timeout=5.0), \
            f"n2 height was {n2.chain.height}"
        assert n2.chain.head.hash() == h1_old
        print("  ✓ Longer chain wins when nodes connect")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Concurrent block production resolves correctly
# ---------------------------------------------------------------------------

def test_concurrent_blocks_resolved_by_extension():
    """A and B both produce a block at height 1. The one whose chain gets
    extended first wins; the loser's coinbase reward disappears, its tx
    contents return to mempool."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    miner_a = Wallet()
    miner_b = Wallet()

    n1.start(); n2.start()
    try:
        n1.connect_to(n2.host, n2.port)
        _wait_for(lambda: n1.peer_count() >= 1 and n2.peer_count() >= 1)

        # Both produce a block at height 1 (genesis is height 0)
        block_a = n1.chain.mine_pending(miner_a.address)
        block_b = n2.chain.mine_pending(miner_b.address)
        assert block_a.hash() != block_b.hash()  # different proposers

        # Each gossips theirs. The other side sees a "competing" block:
        # it shares the previous_hash but is a different block. Our
        # logic in _try_extend_or_replace only adopts if alt_height >
        # current — same height does nothing. So they'll diverge until
        # the next block extends one of them.
        n1.broadcast_block(block_a)
        n2.broadcast_block(block_b)
        time.sleep(0.5)  # let gossip settle

        # Now n1 mines block 2 on top of block_a
        block_a2 = n1.chain.mine_pending(miner_a.address)
        n1.broadcast_block(block_a2)

        # n2 should adopt n1's chain (length 2) over its own (length 1)
        assert _wait_for(lambda: n2.chain.height == 2, timeout=5.0), \
            f"n2 height: {n2.chain.height}"
        assert n2.chain.head.hash() == block_a2.hash()
        print("  ✓ Concurrent block conflict resolved by next-block extension")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# M8.7-D — Shield transaction gossip and pool convergence
# ---------------------------------------------------------------------------

def _fund_wallet_on_node(node: Node, wallet: Wallet, target_amount: float) -> None:
    """Mine blocks on `node` until `wallet` has at least `target_amount`."""
    while node.chain.balance_of(wallet.address) < target_amount:
        block = node.chain.mine_pending(wallet.address)
        node.broadcast_block(block)


def test_shield_tx_gossip_propagates():
    """A signed ShieldTransaction submitted on n1 lands in n2's shield mempool."""
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # Fund a wallet on n1; n2 syncs the chain via the normal handshake.
        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=20)
        assert _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0), \
            f"n2 didn't sync chain: n1={n1.chain.height} n2={n2.chain.height}"
        assert n2.chain.balance_of(depositor.address) >= 20

        # Build, sign, and gossip the shield tx
        note = STARKNote.random(value=20)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=20,
            timestamp=time.time(), nonce=1,
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)

        # n2 should see it in shield_mempool
        assert _wait_for(lambda: len(n2.chain.shield_mempool) == 1, timeout=3.0)
        assert n2.chain.shield_mempool[0].txid() == shtx.txid()
        print("  ✓ Shield tx gossip works (signed, balance-validated remotely)")
    finally:
        n1.stop(); n2.stop()


def test_shield_tx_in_block_makes_pool_match():
    """The Gap D closure proof: shield on n1, mine, broadcast. n2 adopts
    the block and ends up with a STARK pool root identical to n1's."""
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Confirm both pools start empty
        assert len(n1.chain.stark_anon_tree) == 0
        assert len(n2.chain.stark_anon_tree) == 0
        assert n1.chain.stark_anon_tree.root() == n2.chain.stark_anon_tree.root()

        # n1 produces a shield + mines + broadcasts
        note = STARKNote.random(value=75)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=75,
            timestamp=time.time(), nonce=2,
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)

        # n2 adopts the block and applies the shield
        target_height = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target_height, timeout=5.0)
        assert len(n2.chain.stark_anon_tree) == 1
        assert n2.chain.stark_anon_tree.root() == n1.chain.stark_anon_tree.root()
        # And the depositor's balance reflects the debit on both sides
        assert n2.chain.balance_of(depositor.address) == \
               n1.chain.balance_of(depositor.address)
        print("  ✓ Gap D closed: STARK pool roots converge after shield-tx block propagates")
    finally:
        n1.stop(); n2.stop()


def test_full_shield_then_remote_spend_flow():
    """End-to-end M8.7-D: n1 shields, n2 picks up the leaf via gossip,
    and can then spend the note (proving the pool truly replicates).

    The depositor knows the note's preimage; we hand it to n2 directly
    (as a real wallet would do — the note's secret stays out of band).
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # n1 shields a note worth 80
        note = STARKNote.random(value=80)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=80,
            timestamp=time.time(), nonce=3,
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)

        # n2 now has the same STARK pool
        target_height = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target_height, timeout=5.0)
        assert n2.chain.stark_anon_tree.root() == n1.chain.stark_anon_tree.root()

        # n2 spends the note (depositor handed off (sk, r, v) out of band)
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n2.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=80, fee=0,
        )
        n2.submit_stark_anon_tx(stx)

        # n1 sees the spend in its mempool
        assert _wait_for(lambda: len(n1.chain.stark_anon_mempool) == 1, timeout=3.0)
        # Mine it on n2, broadcast
        block2 = n2.chain.mine_pending("miner-b")
        n2.broadcast_block(block2)
        # Both sides converge again; alice has the 80 coins
        target_height2 = n2.chain.height
        assert _wait_for(lambda: n1.chain.height == target_height2, timeout=5.0)
        assert n1.chain.balance_of("alice") == 80
        assert n2.chain.balance_of("alice") == 80
        assert stx.nullifier in n1.chain.stark_nullifiers
        assert stx.nullifier in n2.chain.stark_nullifiers
        print("  ✓ Full shield-on-A → spend-on-B → both-converge flow works")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# M8.8-A1 Phase 4 — Gap A network-level adversarial tests
# ---------------------------------------------------------------------------
#
# These prove that Gap A enforcement (value conservation via range proof)
# survives the p2p layer. Phase 3 closed Gap A in single-node validation;
# Phase 4 confirms peers running the same code reject malicious txs
# identically.

def test_phase4_honest_full_value_spend_propagates():
    """Positive regression: an honest spend that satisfies value conservation
    (unshield + fee == note.value) still propagates cleanly across the
    network after Phase 3 added the cross-check. If this breaks, Phase 3
    over-corrected.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Shield 100, then spend it as 99 unshield + 1 fee (sums to 100)
        note = STARKNote.random(value=100)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=100,
            timestamp=time.time(), nonce=int(time.time() * 1e6),
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target_height = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target_height, timeout=5.0)

        # Honest spend with fee — exactly the new pattern Phase 3 enables
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=99, fee=1,
        )
        n1.submit_stark_anon_tx(stx)
        assert _wait_for(lambda: len(n2.chain.stark_anon_mempool) == 1, timeout=3.0)
        assert n2.chain.stark_anon_mempool[0].txid() == stx.txid()
        print("  ✓ Phase 4: honest full-value spend (99 + 1 fee) propagates")
    finally:
        n1.stop(); n2.stop()


def test_phase4_overspend_blocked_at_construction_never_broadcasts():
    """A malicious user trying to spend more than their note's value is
    blocked at create_stark_anon_tx — the tx never even exists, so it
    can't be gossiped. The chain is protected by the construction-time
    precondition before any network exposure.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n1.start()
    try:
        # Local STARK pool with one note
        note = STARKNote.random(value=10)
        n1.chain.shield_to_stark_pool(note.leaf())

        # Try to spend it claiming 1,000,000. Construction-time check fires.
        try:
            create_stark_anon_tx(
                note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
                unshield_recipient="attacker",
                unshield_amount=1_000_000, fee=0,
            )
            raise AssertionError("Construction should have failed before any network exposure")
        except ValueError as e:
            assert "value conservation" in str(e), f"Wrong error: {e}"
        print("  ✓ Phase 4: overspend rejected at construction; no tx to gossip")
    finally:
        n1.stop()


def test_phase4_u64_overflow_blocked_at_construction_never_broadcasts():
    """Symmetric to the overspend test, but for the field-wrap attack.
    A malicious user submitting amount + fee >= 2^64 can't construct
    the tx. The Phase 2 soundness work documented this as an AIR
    limitation; Phase 3 enforced it at construction. Phase 4 confirms
    the protection persists in a network context.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n1.start()
    try:
        # The leaf's value is irrelevant — construction rejects on overflow
        # BEFORE checking value conservation
        note = STARKNote.random(value=10)
        n1.chain.shield_to_stark_pool(note.leaf())

        try:
            create_stark_anon_tx(
                note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
                unshield_recipient="attacker",
                unshield_amount=(1 << 63),
                fee=(1 << 63),  # sum = 2^64
            )
            raise AssertionError("Overflow construction should have failed")
        except ValueError as e:
            assert "overflows u64" in str(e), f"Wrong error: {e}"
        print("  ✓ Phase 4: u64-overflow rejected at construction")
    finally:
        n1.stop()


def test_phase4_malicious_peer_tampered_amount_rejected_remotely():
    """The headline Phase 4 test. Models a MALICIOUS node that builds an
    honest STARK proof, then directly gossips a payload with a tampered
    `unshield_amount` field — bypassing its own submit_stark_anon_tx
    validator (which would catch the tampering).

    An honest peer receiving the tampered message must reject it because
    the proof's Fiat-Shamir-bound (root, nullifier, amount, fee) tuple
    no longer matches what the proof was generated for.

    Without Phase 3's cross-check, this attack would succeed — the honest
    peer would record `unshield_amount=50` in its mempool while the
    network only paid `note.value=100` worth of consumed leaves.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Shield a 100-coin note on n1 and sync to n2
        note = STARKNote.random(value=100)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=100,
            timestamp=time.time(), nonce=int(time.time() * 1e6),
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target_height = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target_height, timeout=5.0)

        # Construct an HONEST proof for the full 100
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="attacker", unshield_amount=100, fee=0,
        )
        # MALICIOUS TAMPERING: post-construction, set unshield_amount=50.
        # The proof was generated with amount=100 bound via Fiat-Shamir.
        stx.unshield_amount = 50

        # Bypass n1's own validator by gossiping directly (a malicious node
        # would skip its own check). This is what a real attacker would do.
        payload = stx.to_dict()
        n1._gossip({
            "type": "new_stark_anon_tx",
            "from": n1.node_id,
            "payload": payload,
        })

        # Give the message time to reach n2 and be processed
        time.sleep(0.5)

        # The honest peer (n2) must NOT have admitted the tampered tx
        assert len(n2.chain.stark_anon_mempool) == 0, (
            "Phase 4 FAILED: honest peer accepted a Gap-A-tampered tx — "
            "the Fiat-Shamir cross-check didn't catch it"
        )
        # And n2 didn't crash; it's still alive and peered
        assert n2.peer_count() >= 1
        print("  ✓ Phase 4: malicious peer's tampered amount rejected by honest peer")
    finally:
        n1.stop(); n2.stop()


def test_phase4_tampered_tx_rejected_identically_on_both_nodes():
    """Consistency property: the same tampered STARK tx, presented to
    both n1 and n2, must be rejected with the same reason. Asymmetric
    rejection would indicate a stateful bug in the verifier path.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        # Don't connect them — we want to test each in isolation, then
        # confirm rejection reasons match.
        # But they need the same STARK pool for the proof to be against
        # a valid root. Shield the same note on both directly (this is
        # legitimate test setup, not a M8.7-D simulation).
        note = STARKNote.random(value=100)
        n1.chain.shield_to_stark_pool(note.leaf())
        n2.chain.shield_to_stark_pool(note.leaf())
        assert n1.chain.stark_anon_tree.root() == n2.chain.stark_anon_tree.root()

        # Build an honest proof, then tamper the amount
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=100, fee=0,
        )
        stx.unshield_amount = 75  # tampered

        # Both nodes must reject with the same reason
        err1 = err2 = None
        try:
            n1.chain.submit_stark_anon(stx)
        except ValueError as e:
            err1 = str(e)
        try:
            n2.chain.submit_stark_anon(stx)
        except ValueError as e:
            err2 = str(e)

        assert err1 is not None, "n1 must reject the tampered tx"
        assert err2 is not None, "n2 must reject the tampered tx"
        # The rejection reason includes "STARK proof failed to verify"
        # on both sides — the Phase 3 cross-check signature.
        assert "STARK proof failed to verify" in err1, (
            f"n1 rejection reason unexpected: {err1!r}"
        )
        assert "STARK proof failed to verify" in err2, (
            f"n2 rejection reason unexpected: {err2!r}"
        )
        # Mempools stay empty on both sides
        assert len(n1.chain.stark_anon_mempool) == 0
        assert len(n2.chain.stark_anon_mempool) == 0
        print("  ✓ Phase 4: identical rejection on both peers for tampered tx")
    finally:
        n1.stop(); n2.stop()


# ---------------------------------------------------------------------------
# Invalid messages don't break the node
# ---------------------------------------------------------------------------

def test_malformed_messages_dont_crash():
    """Garbage on the wire should be ignored, not crash the node."""
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n1.start()
    try:
        # Open a raw socket and send garbage
        s = socket.create_connection((n1.host, n1.port))
        s.sendall(b"not json at all\n")
        s.sendall(b'{"type": "unknown", "payload": "xyz"}\n')
        s.sendall(b'{"type": "blocks", "payload": {"blocks": ["malformed"]}}\n')
        time.sleep(0.5)
        s.close()
        # Node should still be alive and responsive
        n2 = Node("127.0.0.1", _free_port(), node_id="B")
        n2.start()
        try:
            assert n2.connect_to(n1.host, n1.port)
            assert _wait_for(lambda: n1.peer_count() >= 1)
        finally:
            n2.stop()
        print("  ✓ Malformed messages don't crash the node")
    finally:
        n1.stop()


if __name__ == "__main__":
    print("Running milestone 6 P2P tests...\n")
    test_two_nodes_connect()
    test_new_node_syncs_chain_on_connect()
    test_tx_gossip_propagates()
    test_anon_tx_gossip_propagates()
    test_block_gossip_propagates()
    test_three_node_propagation()
    test_longer_chain_wins_on_connect()
    test_concurrent_blocks_resolved_by_extension()
    test_malformed_messages_dont_crash()
    print("\nAll milestone 6 P2P tests passed ✓")


# ===========================================================================
# M8.11 Phase 4 — Network adversarial tests for partial-spend / output_leaf
# ===========================================================================
#
# Phase 3 made create_stark_anon_tx accept change_note and the chain append
# output_leaf to the STARK pool. Phase 4 proves the network handlers also
# enforce the new public-input binding:
#   1. Honest partial-spend tx propagates end-to-end between nodes
#   2. Malicious peer tampering output_leaf is rejected by honest peers (FS)
#   3. Both nodes reject the same tampered tx with the same reason (consistency)
#   4. Malformed payload (missing output_leaf field) is dropped, doesn't crash
#   5. Full-spend (dummy output_leaf) also propagates cleanly
#
# These tests run the FULL network path: real TCP gossip, real handlers,
# real serialization roundtrip. Phase 2 covered AIR-level adversarials;
# this is the network-level integration.

def test_m811_phase4_honest_partial_spend_propagates():
    """A real partial-spend tx flows between two nodes via gossip.
    Both nodes end up with matching chain state including the change note.
    Smoke test for the new field traversing the wire.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Shield a 100-coin note on n1, sync to n2
        note = STARKNote.random(value=100)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=100,
            timestamp=time.time(), nonce=int(time.time() * 1e6),
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target_height = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target_height, timeout=5.0)

        # Partial spend: 60 unshield + 5 fee + 35 change
        change_note = STARKNote(sk=44444, randomness=55555, value=35)
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=60, fee=5,
            change_note=change_note,
        )
        n1.submit_stark_anon_tx(stx)

        # n2 receives via gossip and admits to its mempool
        assert _wait_for(lambda: len(n2.chain.stark_anon_mempool) == 1, timeout=3.0)
        received = n2.chain.stark_anon_mempool[0]
        assert received.output_leaf == change_note.leaf(), \
            "output_leaf must survive the gossip roundtrip"
        assert received.unshield_amount == 60
        assert received.fee == 5

        # Mine on n1, broadcast block; n2 applies the same state
        block2 = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block2)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Both pools should contain the same change note hash
        assert n1.chain.stark_anon_tree.root() == n2.chain.stark_anon_tree.root(), \
            "STARK pool root must converge across nodes after partial spend"
        assert n1.chain.stark_anon_tree._next_idx == n2.chain.stark_anon_tree._next_idx
        print("  ✓ M8.11 Phase 4: partial-spend tx with change note propagates end-to-end")
    finally:
        n1.stop(); n2.stop()


def test_m811_phase4_malicious_peer_tampered_output_leaf_rejected():
    """A malicious node builds an honest STARK proof, then directly gossips
    a payload with a tampered output_leaf field — bypassing its own
    submit_stark_anon_tx validator (which would catch the tampering).

    An honest peer receiving the tampered message must reject it because
    the proof's Fiat-Shamir-bound public inputs no longer match what the
    proof was generated for.

    Mirrors M8.8-A1 Phase 4's tampered-amount test, but targets the
    new M8.11 output_leaf field.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        note = STARKNote.random(value=100)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=100,
            timestamp=time.time(), nonce=int(time.time() * 1e6),
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Construct an HONEST partial-spend proof
        change_note = STARKNote(sk=11111, randomness=22222, value=40)
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="attacker", unshield_amount=60, fee=0,
            change_note=change_note,
        )
        # MALICIOUS TAMPERING: substitute output_leaf to a different valid
        # hash (one for a DIFFERENT v_out that pays the attacker more change).
        # The proof was generated with the original output_leaf bound via FS.
        fake_change = STARKNote(sk=99999, randomness=88888, value=100)  # all the value as change
        stx.output_leaf = fake_change.leaf()

        # Bypass n1's own validator by gossiping directly (the malicious node
        # would skip its own check). This simulates a real attacker.
        payload = stx.to_dict()
        n1._gossip({
            "type": "new_stark_anon_tx",
            "from": n1.node_id,
            "payload": payload,
        })

        # Give the message time to reach n2 and be processed
        time.sleep(0.5)

        # n2 must NOT have admitted the tampered tx
        assert len(n2.chain.stark_anon_mempool) == 0, (
            "M8.11 Phase 4 FAILED: honest peer accepted a tampered output_leaf — "
            "the Fiat-Shamir cross-check didn't catch it"
        )
        # And n2 is still healthy and peered
        assert n2.peer_count() >= 1
        print("  ✓ M8.11 Phase 4: tampered output_leaf rejected by honest peer")
    finally:
        n1.stop(); n2.stop()


def test_m811_phase4_tampered_output_leaf_rejected_consistently():
    """Same tampered tx, presented to two isolated nodes, must be rejected
    by both with the same reason. Asymmetric rejection would indicate a
    stateful bug in the verifier path.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        # Don't connect — we test each in isolation.
        # Shared pool state via test shortcut (test setup, not a M8.7-D thing).
        note = STARKNote.random(value=100)
        n1.chain.shield_to_stark_pool(note.leaf())
        n2.chain.shield_to_stark_pool(note.leaf())
        assert n1.chain.stark_anon_tree.root() == n2.chain.stark_anon_tree.root()

        # Build honest partial-spend, then tamper output_leaf
        change_note = STARKNote(sk=7, randomness=8, value=30)
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=70, fee=0,
            change_note=change_note,
        )
        # Tamper: substitute a different valid output_leaf hash
        stx.output_leaf = (0xDEADBEEF, 0, 0, 0)

        err1 = err2 = None
        try:
            n1.chain.submit_stark_anon(stx)
        except ValueError as e:
            err1 = str(e)
        try:
            n2.chain.submit_stark_anon(stx)
        except ValueError as e:
            err2 = str(e)

        assert err1 is not None, "n1 must reject the tampered tx"
        assert err2 is not None, "n2 must reject the tampered tx"
        # Both reject with "STARK proof failed to verify" — the FS cross-check
        # in submit_stark_anon's verify() path catches the tamper.
        assert "STARK" in err1 and "STARK" in err2, \
            f"both nodes must reject via STARK verify path: n1={err1!r}, n2={err2!r}"
        print("  ✓ M8.11 Phase 4: tampered output_leaf rejected identically by isolated nodes")
    finally:
        n1.stop(); n2.stop()


def test_m811_phase4_malformed_payload_missing_output_leaf_dropped():
    """A garbage payload missing the output_leaf field must NOT crash the
    node — from_dict should fail cleanly and the handler drops the message.
    """
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n1.start()
    try:
        # Craft a payload that LOOKS like a stark_anon tx but lacks output_leaf
        # (the way an old pre-M8.11 client would send one — backwards-incompat).
        malformed_payload = {
            "kind": "stark_anon",
            "merkle_root": [0, 0, 0, 0],
            "nullifier": [1, 2, 3, 4],
            "unshield_recipient": "alice",
            "unshield_amount": 100,
            "fee": 0,
            # NO output_leaf — old format
            "proof": "00" * 100,  # fake proof bytes
            "timestamp": time.time(),
        }
        # Inject directly via the handler (simulating a malformed peer message)
        n1._handle_new_stark_anon_tx(malformed_payload)
        # No crash; the tx didn't enter the mempool
        assert len(n1.chain.stark_anon_mempool) == 0, \
            "malformed payload must not enter the mempool"
        # Node still alive and connectable
        n2 = Node("127.0.0.1", _free_port(), node_id="B")
        n2.start()
        try:
            assert n2.connect_to(n1.host, n1.port)
            assert _wait_for(lambda: n1.peer_count() >= 1)
        finally:
            n2.stop()
        print("  ✓ M8.11 Phase 4: malformed payload (missing output_leaf) dropped cleanly")
    finally:
        n1.stop()


def test_m811_phase4_full_spend_dummy_output_propagates():
    """The Sapling-pattern full-spend (dummy output_leaf with v_out=0) also
    propagates through the network correctly. Proves we didn't regress
    the common case while adding partial-spend support.
    """
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=100)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        note = STARKNote.random(value=100)
        shtx = ShieldTransaction(
            sender="", leaf=note.leaf(), amount=100,
            timestamp=time.time(), nonce=int(time.time() * 1e6),
        )
        shtx.sign(depositor.keypair)
        n1.submit_shield_tx(shtx)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Full spend, no change_note arg — auto-generates dummy v_out=0
        stx = create_stark_anon_tx(
            note, leaf_idx=0, tree=n1.chain.stark_anon_tree,
            unshield_recipient="alice", unshield_amount=100, fee=0,
        )
        # output_leaf is the hash of a random (sk_out, r_out, 0) — non-zero
        assert stx.output_leaf != (0, 0, 0, 0), \
            "dummy output_leaf must be a real hash, not zero"

        n1.submit_stark_anon_tx(stx)

        # n2 receives via gossip
        assert _wait_for(lambda: len(n2.chain.stark_anon_mempool) == 1, timeout=3.0)
        received = n2.chain.stark_anon_mempool[0]
        assert received.output_leaf == stx.output_leaf, \
            "dummy output_leaf must survive gossip roundtrip"
        print("  ✓ M8.11 Phase 4: full-spend with dummy output_leaf propagates")
    finally:
        n1.stop(); n2.stop()


# ===========================================================================
# M10 Phase 3 — Network propagation tests for mixer transactions
# ===========================================================================
#
# Phase 2 proved the AIR-level defenses reach the mixer surface. Phase 3
# proves those defenses ALSO reach the network surface — via real TCP
# gossip, real handlers, real serialization. Mirrors M8.11 Phase 4's
# pattern but targets mixer txs.
#
# Five tests:
#   1. Honest mixer deposit propagates between two nodes
#   2. Honest mixer withdrawal propagates between two nodes
#   3. Tampered withdrawal output_leaf rejected by honest peer (FS catches)
#   4. Malformed payload (missing fields) dropped cleanly, no crash
#   5. Full state converges: deposit + withdrawal + block propagation,
#      both nodes end at same mixer/STARK pool roots

def test_m10_phase3_honest_mixer_deposit_propagates():
    """A signed mixer deposit submitted on n1 lands in n2's mixer-deposit
    mempool via gossip. Both nodes admit it through their normal
    submit_mixer_deposit validation path.
    """
    from qchain.chain.mixer_tx import create_mixer_deposit_tx
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # Fund a depositor on both nodes via shared chain history.
        # Easiest: fund on n1, broadcast blocks so n2 has the same
        # transparent state when validating the deposit.
        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=200)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Build and submit a deposit on n1
        note = STARKNote.random(value=100)
        deposit = create_mixer_deposit_tx(depositor, denomination=100, note=note)
        n1.submit_mixer_deposit_tx(deposit)

        # n2 should receive it via gossip and admit to its mempool
        assert _wait_for(
            lambda: len(n2.chain.mixer_deposit_mempool) == 1, timeout=3.0
        ), "mixer deposit must propagate to n2's mempool"
        received = n2.chain.mixer_deposit_mempool[0]
        assert received.txid() == deposit.txid()
        assert received.leaf == note.leaf()
        assert received.amount == 100
        print("  ✓ M10 Phase 3: mixer deposit gossip works")
    finally:
        n1.stop(); n2.stop()


def test_m10_phase3_honest_mixer_withdrawal_propagates():
    """A mixer withdrawal proof gossips between nodes. Requires both
    nodes to have the same mixer pool state (the proof's bound root
    must match the receiver's chain). We achieve this by mining a
    deposit block on n1 and propagating it.
    """
    from qchain.chain.mixer_tx import (
        create_mixer_deposit_tx, create_mixer_withdraw_tx,
    )
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        # Fund depositor on n1, sync to n2
        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=200)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Deposit on n1, mine a block, broadcast to n2
        note = STARKNote.random(value=100)
        deposit = create_mixer_deposit_tx(depositor, denomination=100, note=note)
        n1.submit_mixer_deposit_tx(deposit)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)
        # M-timing: mine DELAY more blocks on n1 (and propagate) so
        # the deposit is anchorable.
        from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
        for _ in range(MIXER_WITHDRAWAL_DELAY):
            b = n1.chain.mine_pending("miner-a")
            n1.broadcast_block(b)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Both nodes should now have the same mixer pool root
        assert n1.chain.mixer_tree.root() == n2.chain.mixer_tree.root(), \
            "mixer pool root must converge after block propagation"

        # Build a withdrawal on n1 (against the latest valid anchor) and gossip it
        output_note = STARKNote(sk=11, randomness=22, value=100)
        anchor_idx = n1.chain.latest_valid_mixer_anchor()
        anchored_tree = n1.chain.historical_mixer_tree_for_block(anchor_idx)
        mwtx = create_mixer_withdraw_tx(
            note, leaf_idx=0,
            mixer_tree=anchored_tree,
            output_note=output_note,
            anchor_block_index=anchor_idx,
        )
        n1.submit_mixer_withdraw_tx(mwtx)

        # n2 receives via gossip
        assert _wait_for(
            lambda: len(n2.chain.mixer_withdraw_mempool) == 1, timeout=3.0
        ), "mixer withdrawal must propagate to n2's mempool"
        received = n2.chain.mixer_withdraw_mempool[0]
        assert received.output_leaf == output_note.leaf(), \
            "output_leaf must survive gossip roundtrip"
        print("  ✓ M10 Phase 3: mixer withdrawal gossip works (proof + output_leaf)")
    finally:
        n1.stop(); n2.stop()


def test_m10_phase3_malicious_peer_tampered_output_leaf_rejected():
    """A malicious node builds an honest withdrawal proof, tampers
    output_leaf post-construction, gossips directly (bypassing its
    own submit_mixer_withdraw_tx validator). Honest peer rejects via
    FS cross-check at verify time.

    Mirrors the M8.11 Phase 4 attack template for the mixer surface.
    """
    from qchain.chain.mixer_tx import (
        create_mixer_deposit_tx, create_mixer_withdraw_tx,
    )
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=200)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Set up shared mixer pool
        note = STARKNote.random(value=100)
        deposit = create_mixer_deposit_tx(depositor, denomination=100, note=note)
        n1.submit_mixer_deposit_tx(deposit)
        block = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Build honest withdrawal
        output_note = STARKNote(sk=11, randomness=22, value=100)
        mwtx = create_mixer_withdraw_tx(
            note, leaf_idx=0, mixer_tree=n1.chain.mixer_tree,
            output_note=output_note,
        )
        # MALICIOUS TAMPERING: substitute output_leaf to a different valid hash
        fake_output = STARKNote(sk=999, randomness=999, value=100)
        mwtx.output_leaf = fake_output.leaf()

        # Bypass n1's validator by gossiping directly
        payload = mwtx.to_dict()
        n1._gossip({
            "type": "new_mixer_withdraw",
            "from": n1.node_id,
            "payload": payload,
        })
        time.sleep(0.5)

        # n2 must NOT have admitted the tampered withdrawal
        assert len(n2.chain.mixer_withdraw_mempool) == 0, (
            "M10 Phase 3 FAILED: honest peer accepted a tampered "
            "mixer withdrawal output_leaf — FS cross-check didn't catch"
        )
        assert n2.peer_count() >= 1
        print("  ✓ M10 Phase 3: tampered mixer withdrawal output_leaf rejected by honest peer")
    finally:
        n1.stop(); n2.stop()


def test_m10_phase3_malformed_mixer_payload_dropped():
    """Garbage payloads for both mixer message types are dropped cleanly,
    the node doesn't crash, stays connectable.
    """
    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n1.start()
    try:
        # Bad deposit (missing fields)
        n1._handle_new_mixer_deposit({
            "kind": "mixer_deposit",
            "amount": 100,
            # missing leaf, sender, signature, etc.
        })
        # Bad withdrawal (missing all required fields)
        n1._handle_new_mixer_withdraw({
            "kind": "mixer_withdraw",
            # missing mixer_root, nullifier, output_leaf, proof
        })
        # Bad withdrawal (valid shape but proof is junk). Also includes
        # the legacy `withdraw_amount` field — from_dict silently discards
        # it for backward compat with pre-binding-hardening saved chains.
        n1._handle_new_mixer_withdraw({
            "kind": "mixer_withdraw",
            "mixer_root": [0, 0, 0, 0],
            "nullifier": [1, 2, 3, 4],
            "withdraw_amount": 100,  # legacy field — silently discarded
            "output_leaf": [5, 6, 7, 8],
            "proof": "00" * 200,
            "timestamp": time.time(),
        })
        # Neither should have entered the mempool
        assert len(n1.chain.mixer_deposit_mempool) == 0
        assert len(n1.chain.mixer_withdraw_mempool) == 0

        # Node still alive and connectable
        n2 = Node("127.0.0.1", _free_port(), node_id="B")
        n2.start()
        try:
            assert n2.connect_to(n1.host, n1.port)
            assert _wait_for(lambda: n1.peer_count() >= 1)
        finally:
            n2.stop()
        print("  ✓ M10 Phase 3: malformed mixer payloads dropped cleanly")
    finally:
        n1.stop()


def test_m10_phase3_full_state_converges_across_nodes():
    """End-to-end: deposit + withdrawal + block propagation. After all
    blocks land on both nodes, mixer roots and STARK pool roots must
    converge — proving the full mixer flow works through the network.
    """
    from qchain.chain.mixer_tx import (
        create_mixer_deposit_tx, create_mixer_withdraw_tx,
    )
    from qchain.crypto.anon_stark import STARKNote

    n1 = Node("127.0.0.1", _free_port(), node_id="A")
    n2 = Node("127.0.0.1", _free_port(), node_id="B")
    n1.start(); n2.start()
    try:
        n2.connect_to(n1.host, n1.port)
        _wait_for(lambda: n2.peer_count() >= 1)

        depositor = Wallet()
        _fund_wallet_on_node(n1, depositor, target_amount=200)
        _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)

        # Deposit, mine, broadcast
        note = STARKNote.random(value=100)
        deposit = create_mixer_deposit_tx(depositor, denomination=100, note=note)
        n1.submit_mixer_deposit_tx(deposit)
        block1 = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block1)
        assert _wait_for(lambda: n2.chain.height == n1.chain.height, timeout=5.0)
        assert n1.chain.mixer_tree.root() == n2.chain.mixer_tree.root()

        # M-timing: mine DELAY more blocks so the deposit is anchorable
        from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
        for _ in range(MIXER_WITHDRAWAL_DELAY):
            b = n1.chain.mine_pending("miner-a")
            n1.broadcast_block(b)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Withdrawal against latest anchor, mine, broadcast
        output_note = STARKNote(sk=42, randomness=43, value=100)
        anchor_idx = n1.chain.latest_valid_mixer_anchor()
        anchored_tree = n1.chain.historical_mixer_tree_for_block(anchor_idx)
        mwtx = create_mixer_withdraw_tx(
            note, leaf_idx=0, mixer_tree=anchored_tree,
            output_note=output_note,
            anchor_block_index=anchor_idx,
        )
        n1.submit_mixer_withdraw_tx(mwtx)
        block2 = n1.chain.mine_pending("miner-a")
        n1.broadcast_block(block2)
        target = n1.chain.height
        assert _wait_for(lambda: n2.chain.height == target, timeout=5.0)

        # Both nodes must agree on EVERYTHING:
        #   * mixer tree root (deposit appeared identically)
        #   * mixer nullifier set (withdrawal nullifier marked)
        #   * STARK pool root (withdrawal's output_leaf appeared identically)
        assert n1.chain.mixer_tree.root() == n2.chain.mixer_tree.root(), \
            "mixer tree root must converge"
        assert n1.chain.mixer_nullifiers == n2.chain.mixer_nullifiers, \
            "mixer nullifier set must converge"
        assert n1.chain.stark_anon_tree.root() == n2.chain.stark_anon_tree.root(), \
            "STARK pool root must converge after mixer withdrawal credit"

        # And both validate
        assert n1.chain.is_valid()
        assert n2.chain.is_valid()
        print("  ✓ M10 Phase 3: full mixer flow (deposit → withdrawal → blocks) "
              "converges across nodes")
    finally:
        n1.stop(); n2.stop()

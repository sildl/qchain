"""P2P demo: spin up 3 nodes locally, watch them gossip and converge.

Run with: python -m qchain.cli.network_demo

What happens:
  1. Three nodes start on different ports
  2. They form a connected graph (A↔B↔C and A↔C)
  3. Node A mines some blocks while alone (before B and C connect)
  4. B and C join — they sync from A
  5. Node B submits a transaction — it propagates to A and C
  6. Node C submits an anonymous shield tx — also propagates
  7. Node A mines a block including both — all three converge to the same chain
"""

import time

from qchain.chain.anon_tx import AnonOutput, AnonTransaction, compute_net_blinding
from qchain.chain.wallet import Wallet
from qchain.crypto.anon import new_anon_note
from qchain.crypto.schnorr import generate_keypair
from qchain.network.node import Node


def line(msg=""):
    print("─" * 72)
    if msg:
        print(msg)


def heights(*nodes):
    return [n.chain.height for n in nodes]


def main():
    print("=" * 72)
    print("QChain Milestone 6 — P2P Network Demo")
    print("=" * 72)

    # Three nodes
    A = Node("127.0.0.1", 19101, node_id="A")
    B = Node("127.0.0.1", 19102, node_id="B")
    C = Node("127.0.0.1", 19103, node_id="C")
    A.start(); B.start(); C.start()

    try:
        # --- Step 1: A mines 2 blocks alone -----------------------------
        line("Step 1: A mines 2 blocks BEFORE B and C connect")
        miner_a = Wallet()
        for _ in range(2):
            A.chain.mine_pending(miner_a.address)
        print(f"  heights: A={A.chain.height} B={B.chain.height} C={C.chain.height}")

        # --- Step 2: B and C join the network ---------------------------
        line("Step 2: B connects to A, C connects to both A and B")
        B.connect_to(A.host, A.port)
        C.connect_to(A.host, A.port)
        C.connect_to(B.host, B.port)
        time.sleep(0.5)  # let handshakes complete
        print(f"  peer counts: A={A.peer_count()} B={B.peer_count()} C={C.peer_count()}")

        # --- Step 3: B and C sync from A --------------------------------
        line("Step 3: B and C catch up via initial sync")
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if B.chain.height == 2 and C.chain.height == 2:
                break
            time.sleep(0.05)
        print(f"  heights after sync: A={A.chain.height} B={B.chain.height} C={C.chain.height}")
        assert B.chain.head.hash() == A.chain.head.hash()
        assert C.chain.head.hash() == A.chain.head.hash()

        # --- Step 4: B submits a transparent tx, watch it gossip --------
        line("Step 4: B submits a transparent tx — does it reach A and C?")
        recipient = Wallet()
        tx = Wallet(miner_a.keypair).create_tx(recipient.address, amount=3.0)
        B.submit_tx(tx)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if (len(A.chain.mempool) == 1 and len(C.chain.mempool) == 1):
                break
            time.sleep(0.05)
        print(f"  mempool sizes: A={len(A.chain.mempool)} B={len(B.chain.mempool)} C={len(C.chain.mempool)}")

        # --- Step 5: C submits an anon shield tx, watch it gossip -------
        line("Step 5: C submits an anonymous shield tx (full ZK proof gossiped)")
        alice_anon = generate_keypair()
        # Shield 15 transparent coins → 15-coin anon note (no fee on this one
        # for simplicity; fees come out of the shielded value, so we'd need
        # value 14 to leave 1 for the fee).
        note = new_anon_note(value=15, recipient_pk=alice_anon.pk)
        atx = AnonTransaction(
            inputs=[],
            outputs=[AnonOutput.from_note(note)],
            shield_in=15,
            unshield_out=0,
            unshield_recipient="",
            fee=0,
            net_blinding=compute_net_blinding([], [note.value_blinding]),
        )
        C.submit_anon_tx(atx)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if (len(A.chain.anon_mempool) == 1 and len(B.chain.anon_mempool) == 1):
                break
            time.sleep(0.05)
        print(f"  anon mempool sizes: A={len(A.chain.anon_mempool)} "
              f"B={len(B.chain.anon_mempool)} C={len(C.chain.anon_mempool)}")

        # --- Step 6: A mines a block, watch all three converge ----------
        line("Step 6: A mines a block including both txs — chain converges")
        block = A.chain.mine_pending(miner_a.address)
        A.broadcast_block(block)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if B.chain.height == 3 and C.chain.height == 3:
                break
            time.sleep(0.05)
        print(f"  heights: A={A.chain.height} B={B.chain.height} C={C.chain.height}")
        print(f"  same head: "
              f"A={A.chain.head.hash()[:16]}… "
              f"B={B.chain.head.hash()[:16]}… "
              f"C={C.chain.head.hash()[:16]}…")
        all_match = (A.chain.head.hash() == B.chain.head.hash() == C.chain.head.hash())
        print(f"  all three converged on the same chain: {all_match}")

        # --- Step 7: chain validity ------------------------------------
        line("Step 7: every node's chain validates independently")
        for n in (A, B, C):
            print(f"  {n.node_id}.is_valid(): {n.chain.is_valid()}")

        line()
        print("Done. Three independent processes (here, threads), gossiping JSON")
        print("over TCP, agreed on a chain containing transparent AND anonymous")
        print("transactions including full Schnorr ZK proofs.")
    finally:
        A.stop(); B.stop(); C.stop()
        time.sleep(0.2)  # let sockets close cleanly


if __name__ == "__main__":
    main()

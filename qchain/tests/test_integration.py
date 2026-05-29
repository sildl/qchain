"""Integration tests for milestone 5: anon txs in blocks + mempool.

Run with: python -m qchain.tests.test_integration
"""

import secrets

from qchain.chain.anon_tx import AnonOutput, AnonTransaction, compute_net_blinding
from qchain.chain.blockchain import Blockchain
from qchain.chain.proposer import Validator
from qchain.chain.wallet import Wallet
from qchain.crypto.anon import new_anon_note, prove_anon_spend
from qchain.crypto.schnorr import generate_keypair
from qchain.quantum.qrng import QRNG


# ---------------------------------------------------------------------------
# Mixed-tx block production
# ---------------------------------------------------------------------------

def test_block_with_only_transparent_txs():
    """Sanity: blocks without any anon txs still work exactly as before."""
    bc = Blockchain()
    miner = Wallet()
    bc.mine_pending(miner.address)
    assert bc.height == 1
    assert bc.is_valid()
    assert bc.blocks[1].anon_transactions == []
    print("  ✓ Pure-transparent blocks unchanged by integration")


def test_block_with_only_anon_txs():
    """A block containing only anon txs (no transparent payments) is valid."""
    bc = Blockchain()
    miner = Wallet()
    # Mine a block first so the chain has some history
    bc.mine_pending(miner.address)

    # Build an anon shield-only tx: 25 transparent coins → 1 anon note
    alice = generate_keypair()
    note = new_anon_note(value=25, recipient_pk=alice.pk)
    net_b = compute_net_blinding([], [note.value_blinding])
    atx = AnonTransaction(
        inputs=[],
        outputs=[AnonOutput.from_note(note)],
        shield_in=25,
        unshield_out=0,
        unshield_recipient="",
        fee=0,
        net_blinding=net_b,
    )
    bc.submit_anon(atx)
    bc.mine_pending(miner.address)

    assert bc.height == 2
    assert len(bc.blocks[2].anon_transactions) == 1
    assert bc.anon_tree.size == 1
    assert bc.is_valid()
    print("  ✓ Block carrying anon-only txs validates")


def test_block_with_mixed_txs():
    """A block with both transparent and anon txs validates."""
    bc = Blockchain()
    miner = Wallet()
    alice_wallet = Wallet()
    bc.mine_pending(miner.address)  # miner has 10 coins

    # Transparent: miner pays Alice 3 coins
    tx_t = Wallet(miner.keypair).create_tx(alice_wallet.address, amount=3.0)
    bc.submit(tx_t)

    # Anon: shield 5 transparent coins into a fresh anon note
    alice_anon = generate_keypair()
    note = new_anon_note(value=5, recipient_pk=alice_anon.pk)
    net_b = compute_net_blinding([], [note.value_blinding])
    atx = AnonTransaction(
        inputs=[],
        outputs=[AnonOutput.from_note(note)],
        shield_in=5,
        unshield_out=0,
        unshield_recipient="",
        fee=0,
        net_blinding=net_b,
    )
    bc.submit_anon(atx)

    block = bc.mine_pending(miner.address)
    assert len(block.transactions) == 2  # coinbase + miner→alice
    assert len(block.anon_transactions) == 1
    assert bc.is_valid()
    print("  ✓ Mixed block (transparent + anon) validates")


# ---------------------------------------------------------------------------
# Multi-block anon flow (shield, spend, unshield)
# ---------------------------------------------------------------------------

def test_full_anon_lifecycle_across_blocks():
    """Alice shields, transfers to Bob privately, Bob unshields."""
    bc = Blockchain()
    miner = Wallet()
    alice = generate_keypair()
    bob = generate_keypair()

    # Block 1: Alice shields 100 coins
    alice_note = new_anon_note(value=100, recipient_pk=alice.pk)
    net_b1 = compute_net_blinding([], [alice_note.value_blinding])
    atx1 = AnonTransaction(
        inputs=[],
        outputs=[AnonOutput.from_note(alice_note)],
        shield_in=100,
        unshield_out=0,
        unshield_recipient="",
        fee=0,
        net_blinding=net_b1,
    )
    bc.submit_anon(atx1)
    bc.mine_pending(miner.address)
    assert bc.anon_tree.size == 1
    alice_idx = 0

    # Block 2: Alice spends her note, sending 70 to Bob, keeping 28 change, 2 fee
    bob_note = new_anon_note(value=70, recipient_pk=bob.pk)
    change_note = new_anon_note(value=28, recipient_pk=alice.pk)

    spend = prove_anon_spend(
        alice_note, alice.sk, bc.anon_tree.proof(alice_idx)
    )
    net_b2 = compute_net_blinding(
        [alice_note.value_blinding],
        [bob_note.value_blinding, change_note.value_blinding],
    )
    atx2 = AnonTransaction(
        inputs=[spend],
        outputs=[AnonOutput.from_note(bob_note), AnonOutput.from_note(change_note)],
        shield_in=0,
        unshield_out=0,
        unshield_recipient="",
        fee=2,
        net_blinding=net_b2,
    )
    bc.submit_anon(atx2)
    bc.mine_pending(miner.address)
    assert bc.anon_tree.size == 3  # alice_note + bob_note + change_note
    assert len(bc.nullifiers) == 1
    bob_idx = 1  # bob_note added next after alice_note

    # Block 3: Bob unshields his 70-coin note (gets 69 transparent, 1 fee)
    bob_spend = prove_anon_spend(
        bob_note, bob.sk, bc.anon_tree.proof(bob_idx)
    )
    net_b3 = compute_net_blinding([bob_note.value_blinding], [])
    atx3 = AnonTransaction(
        inputs=[bob_spend],
        outputs=[],
        shield_in=0,
        unshield_out=69,
        unshield_recipient="bob_transparent_addr",
        fee=1,
        net_blinding=net_b3,
    )
    bc.submit_anon(atx3)
    bc.mine_pending(miner.address)

    assert len(bc.nullifiers) == 2
    assert bc.balance_of("bob_transparent_addr") == 69
    # Miner balance: 10 + 10 + 0 (block 2 anon fee) + 10 + 2 + 1 = 33
    # Actually: each mine_pending gives BLOCK_REWARD + anon_fees
    # Block 1: 10 + 0 (atx1 had fee 0) = 10
    # Block 2: 10 + 2 = 12
    # Block 3: 10 + 1 = 11
    # Total: 33
    assert bc.balance_of(miner.address) == 33.0
    assert bc.is_valid()
    print("  ✓ Full anon lifecycle (shield → transfer → unshield) works")


# ---------------------------------------------------------------------------
# Double-spend prevention across blocks
# ---------------------------------------------------------------------------

def test_double_spend_across_blocks_blocked():
    """Spending the same note in two different blocks must fail."""
    bc = Blockchain()
    miner = Wallet()
    alice = generate_keypair()

    # Block 1: shield 50
    note = new_anon_note(value=50, recipient_pk=alice.pk)
    net_b = compute_net_blinding([], [note.value_blinding])
    bc.submit_anon(AnonTransaction(
        inputs=[], outputs=[AnonOutput.from_note(note)],
        shield_in=50, unshield_out=0, unshield_recipient="",
        fee=0, net_blinding=net_b,
    ))
    bc.mine_pending(miner.address)

    # Block 2: spend the note (unshield)
    spend = prove_anon_spend(note, alice.sk, bc.anon_tree.proof(0))
    net_b2 = compute_net_blinding([note.value_blinding], [])
    bc.submit_anon(AnonTransaction(
        inputs=[spend], outputs=[],
        shield_in=0, unshield_out=50, unshield_recipient="alice",
        fee=0, net_blinding=net_b2,
    ))
    bc.mine_pending(miner.address)

    # Block 3: try to spend the SAME note again
    spend_again = prove_anon_spend(note, alice.sk, bc.anon_tree.proof(0))
    assert spend_again.statement.nullifier == spend.statement.nullifier
    try:
        bc.submit_anon(AnonTransaction(
            inputs=[spend_again], outputs=[],
            shield_in=0, unshield_out=50, unshield_recipient="eve",
            fee=0, net_blinding=net_b2,
        ))
        raise AssertionError("double-spend should have been rejected")
    except ValueError as e:
        assert "nullifier" in str(e) or "double" in str(e)
    print("  ✓ Cross-block double-spend rejected at mempool admission")


def test_mempool_rejects_conflicting_nullifiers():
    """Two pending anon txs trying to spend the same note must conflict."""
    bc = Blockchain()
    miner = Wallet()
    alice = generate_keypair()
    note = new_anon_note(value=20, recipient_pk=alice.pk)
    bc.submit_anon(AnonTransaction(
        inputs=[], outputs=[AnonOutput.from_note(note)],
        shield_in=20, unshield_out=0, unshield_recipient="",
        fee=0, net_blinding=compute_net_blinding([], [note.value_blinding]),
    ))
    bc.mine_pending(miner.address)

    s1 = prove_anon_spend(note, alice.sk, bc.anon_tree.proof(0))
    s2 = prove_anon_spend(note, alice.sk, bc.anon_tree.proof(0))

    nb = compute_net_blinding([note.value_blinding], [])
    bc.submit_anon(AnonTransaction(
        inputs=[s1], outputs=[],
        shield_in=0, unshield_out=20, unshield_recipient="alice",
        fee=0, net_blinding=nb,
    ))
    try:
        bc.submit_anon(AnonTransaction(
            inputs=[s2], outputs=[],
            shield_in=0, unshield_out=20, unshield_recipient="eve",
            fee=0, net_blinding=nb,
        ))
        raise AssertionError("conflict should have been rejected")
    except ValueError as e:
        assert "conflict" in str(e) or "nullifier" in str(e)
    print("  ✓ Mempool rejects conflicting-nullifier anon txs")


# ---------------------------------------------------------------------------
# Chain validity & tampering
# ---------------------------------------------------------------------------

def test_chain_tampering_caught_for_anon():
    """Editing a confirmed anon tx invalidates the chain."""
    bc = Blockchain()
    miner = Wallet()
    alice = generate_keypair()
    note = new_anon_note(value=40, recipient_pk=alice.pk)
    bc.submit_anon(AnonTransaction(
        inputs=[], outputs=[AnonOutput.from_note(note)],
        shield_in=40, unshield_out=0, unshield_recipient="",
        fee=0, net_blinding=compute_net_blinding([], [note.value_blinding]),
    ))
    bc.mine_pending(miner.address)
    assert bc.is_valid()

    # Tamper: claim more was unshielded than authorized
    bc.blocks[1].anon_transactions[0].unshield_out = 99999
    assert not bc.is_valid()
    print("  ✓ Tampering with anon tx in a sealed block is caught on replay")


def test_pos_block_with_anon_txs():
    """PoS-style block (QRNG proposer) can include anon txs."""
    bc = Blockchain()
    miner = Wallet()
    validators = [Validator(address=miner.address, stake=1.0)]
    qrng = QRNG(num_qubits=4, shots=32, prefer_hardware=False)

    alice = generate_keypair()
    note = new_anon_note(value=15, recipient_pk=alice.pk)
    bc.submit_anon(AnonTransaction(
        inputs=[], outputs=[AnonOutput.from_note(note)],
        shield_in=15, unshield_out=0, unshield_recipient="",
        fee=0, net_blinding=compute_net_blinding([], [note.value_blinding]),
    ))
    block = bc.propose_pending(validators, qrng)
    assert "|qrng=" in block.proposer
    assert len(block.anon_transactions) == 1
    assert bc.is_valid()
    print("  ✓ PoS blocks carry anon txs correctly")


if __name__ == "__main__":
    print("Running milestone 5 integration tests...\n")
    test_block_with_only_transparent_txs()
    test_block_with_only_anon_txs()
    test_block_with_mixed_txs()
    test_full_anon_lifecycle_across_blocks()
    test_double_spend_across_blocks_blocked()
    test_mempool_rejects_conflicting_nullifiers()
    test_chain_tampering_caught_for_anon()
    test_pos_block_with_anon_txs()
    print("\nAll milestone 5 integration tests passed ✓")

"""Tests for M8.7-D — depositor-signed shield transactions.

Run with: python -m pytest qchain/tests/test_shield_tx.py -v

These tests cover:
  * ShieldTransaction signing and verification
  * Mempool admission (balance checks, double-spend at depositor level)
  * Block inclusion and on-chain state application
  * Chain replay rebuilds the STARK pool deterministically
  * Adversarial cases: forged signature, sender swap, amount tampering
"""

from __future__ import annotations

import time

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.transaction import Transaction, coinbase
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chain_with_funded_wallet(amount: float = 1000.0) -> tuple[Blockchain, Wallet]:
    """Build a chain where `wallet` has `amount` mined coins."""
    chain = Blockchain()
    wallet = Wallet()
    # Manually inject a coinbase tx in a block so the wallet is funded.
    # We use mine_pending(miner_address=wallet.address) which credits via coinbase.
    chain.mine_pending(miner_address=wallet.address)
    # Block reward is 10; to get more, mine more blocks.
    while chain.balance_of(wallet.address) < amount:
        chain.mine_pending(miner_address=wallet.address)
    return chain, wallet


def _shield_tx_from(wallet: Wallet, amount: float, note: STARKNote, nonce: int = 0) -> ShieldTransaction:
    shtx = ShieldTransaction(
        sender="",  # filled in by sign()
        leaf=note.leaf(),
        amount=amount,
        timestamp=time.time(),
        nonce=nonce,
    )
    shtx.sign(wallet.keypair)
    return shtx


# ---------------------------------------------------------------------------
# Signing and verifying
# ---------------------------------------------------------------------------

def test_shield_tx_signed_and_verifies():
    wallet = Wallet()
    note = STARKNote.random(value=42)
    shtx = _shield_tx_from(wallet, amount=42, note=note)
    assert shtx.verify()
    assert shtx.sender == wallet.address


def test_shield_tx_tampered_amount_fails_verify():
    wallet = Wallet()
    note = STARKNote.random(value=42)
    shtx = _shield_tx_from(wallet, amount=42, note=note)
    shtx.amount = 1_000_000
    assert not shtx.verify()


def test_shield_tx_tampered_leaf_fails_verify():
    wallet = Wallet()
    note = STARKNote.random(value=42)
    shtx = _shield_tx_from(wallet, amount=42, note=note)
    shtx.leaf = (0, 0, 0, 0)  # someone else's leaf
    assert not shtx.verify()


def test_shield_tx_swapped_sender_fails_verify():
    """A different sender than the one derived from the pubkey is rejected."""
    wallet = Wallet()
    other = Wallet()
    note = STARKNote.random(value=42)
    shtx = _shield_tx_from(wallet, amount=42, note=note)
    shtx.sender = other.address  # impersonation attempt
    assert not shtx.verify()


def test_shield_tx_zero_amount_rejected():
    wallet = Wallet()
    note = STARKNote.random(value=0)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=0,
        timestamp=time.time(), nonce=0,
    )
    shtx.sign(wallet.keypair)
    assert not shtx.verify()


def test_shield_tx_negative_amount_rejected():
    wallet = Wallet()
    note = STARKNote.random(value=42)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=-5,
        timestamp=time.time(), nonce=0,
    )
    shtx.sign(wallet.keypair)
    assert not shtx.verify()


def test_shield_tx_malformed_leaf_rejected():
    """Leaf must be 4-tuple of u64."""
    wallet = Wallet()
    bad_shapes = [
        (0, 0, 0),                          # too short
        (0, 0, 0, 0, 0),                    # too long
        (-1, 0, 0, 0),                      # negative
        ((1 << 64), 0, 0, 0),               # overflow
    ]
    for bad in bad_shapes:
        shtx = ShieldTransaction(
            sender="", leaf=bad, amount=10,
            timestamp=time.time(), nonce=0,
        )
        # sign may succeed or fail depending on what _payload does;
        # what matters is verify rejects all of these.
        try:
            shtx.sign(wallet.keypair)
        except Exception:
            continue  # signing failed → not even valid input, ok
        assert not shtx.verify(), f"verify should reject leaf {bad}"


def test_shield_tx_serialization_roundtrip():
    wallet = Wallet()
    note = STARKNote.random(value=42)
    shtx = _shield_tx_from(wallet, amount=42, note=note)
    d = shtx.to_dict()
    rebuilt = ShieldTransaction.from_dict(d)
    assert rebuilt.txid() == shtx.txid()
    assert rebuilt.verify()
    assert rebuilt.leaf == shtx.leaf  # tuple is normalized


# ---------------------------------------------------------------------------
# Mempool admission
# ---------------------------------------------------------------------------

def test_submit_shield_happy_path():
    chain, wallet = _make_chain_with_funded_wallet(amount=100)
    note = STARKNote.random(value=50)
    shtx = _shield_tx_from(wallet, amount=50, note=note)
    chain.submit_shield(shtx)
    assert len(chain.shield_mempool) == 1
    assert chain.shield_mempool[0].txid() == shtx.txid()


def test_submit_shield_insufficient_balance_rejected():
    chain, wallet = _make_chain_with_funded_wallet(amount=10)
    note = STARKNote.random(value=50)
    shtx = _shield_tx_from(wallet, amount=1_000_000, note=note)
    with pytest.raises(ValueError, match="insufficient balance"):
        chain.submit_shield(shtx)


def test_submit_shield_rejects_bad_signature():
    chain, wallet = _make_chain_with_funded_wallet(amount=100)
    note = STARKNote.random(value=50)
    shtx = _shield_tx_from(wallet, amount=50, note=note)
    shtx.amount = 10  # tamper after signing
    with pytest.raises(ValueError):
        chain.submit_shield(shtx)


def test_submit_shield_double_spend_at_depositor_level():
    """Two pending shields can't collectively overdraw the depositor."""
    chain, wallet = _make_chain_with_funded_wallet(amount=60)
    n1, n2 = STARKNote.random(value=40), STARKNote.random(value=40)
    sh1 = _shield_tx_from(wallet, amount=40, note=n1, nonce=1)
    sh2 = _shield_tx_from(wallet, amount=40, note=n2, nonce=2)
    chain.submit_shield(sh1)
    # The second shield would push total debit to 80 from a 60-balance account.
    with pytest.raises(ValueError, match="insufficient balance"):
        chain.submit_shield(sh2)


def test_submit_shield_duplicate_rejected():
    chain, wallet = _make_chain_with_funded_wallet(amount=100)
    note = STARKNote.random(value=10)
    shtx = _shield_tx_from(wallet, amount=10, note=note)
    chain.submit_shield(shtx)
    with pytest.raises(ValueError, match="duplicate"):
        chain.submit_shield(shtx)


# ---------------------------------------------------------------------------
# Block inclusion + state application
# ---------------------------------------------------------------------------

def test_mining_shield_tx_debits_sender_and_populates_pool():
    chain, wallet = _make_chain_with_funded_wallet(amount=100)
    starting = chain.balance_of(wallet.address)
    note = STARKNote.random(value=30)
    shtx = _shield_tx_from(wallet, amount=30, note=note)
    chain.submit_shield(shtx)

    pool_size_before = len(chain.stark_anon_tree)
    block = chain.mine_pending(miner_address="miner")
    pool_size_after = len(chain.stark_anon_tree)

    assert pool_size_after == pool_size_before + 1
    assert chain.balance_of(wallet.address) == starting - 30
    assert len(block.shield_transactions) == 1
    assert block.shield_transactions[0].txid() == shtx.txid()
    assert chain.shield_mempool == []


def test_mined_shield_enables_subsequent_stark_spend():
    """End-to-end: shield via on-chain tx, then spend the resulting note."""
    from qchain.chain.anon_stark_tx import create_stark_anon_tx
    chain, wallet = _make_chain_with_funded_wallet(amount=200)
    starting = chain.balance_of(wallet.address)

    # Shield 100 to the pool via a proper on-chain shield tx
    note = STARKNote.random(value=100)
    shtx = _shield_tx_from(wallet, amount=100, note=note)
    chain.submit_shield(shtx)
    chain.mine_pending(miner_address="miner")

    # Mid-state: wallet debited, pool has 1 leaf
    assert chain.balance_of(wallet.address) == starting - 100
    assert len(chain.stark_anon_tree) == 1

    # Now spend that note via a STARK spend (unshield to "alice")
    stx = create_stark_anon_tx(
        note, leaf_idx=0, tree=chain.stark_anon_tree,
        unshield_recipient="alice", unshield_amount=100, fee=0,
    )
    chain.submit_stark_anon(stx)
    chain.mine_pending(miner_address="miner")

    # Alice received the 100; nullifier marks the note spent
    assert chain.balance_of("alice") == 100
    assert stx.nullifier in chain.stark_nullifiers


def test_chain_replay_rebuilds_stark_pool_from_blocks():
    """The whole point of Gap D closure: a fresh node syncing from blocks
    deterministically reconstructs the same STARK pool root."""
    chain, wallet = _make_chain_with_funded_wallet(amount=300)

    # Shield three notes in successive blocks
    leaves_added = []
    for v in [50, 75, 100]:
        note = STARKNote.random(value=v)
        leaves_added.append(note.leaf())
        shtx = _shield_tx_from(wallet, amount=v, note=note, nonce=int(time.time() * 1e6) + v)
        chain.submit_shield(shtx)
        chain.mine_pending(miner_address="miner")

    expected_root = chain.stark_anon_tree.root()
    assert len(chain.stark_anon_tree) == 3

    # Now simulate a fresh node: take the blocks, apply them to a fresh chain
    fresh = Blockchain()
    for block in chain.blocks[1:]:  # skip genesis
        fresh.blocks.append(block)
        for atx in block.anon_transactions:
            fresh._apply_anon_tx(atx)
        for sh in block.shield_transactions:
            fresh._apply_shield_tx(sh)
        for stx in block.stark_anon_transactions:
            fresh._apply_stark_anon_tx(stx)

    assert fresh.stark_anon_tree.root() == expected_root
    assert len(fresh.stark_anon_tree) == 3

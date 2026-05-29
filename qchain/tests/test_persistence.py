"""Persistence tests — chain derived state + wallet shielded notes.

Before this pass:
  * `Blockchain.load()` reconstructed `blocks` from disk but left every
    derived state structure (anon_tree, stark_anon_tree, mixer_tree,
    nullifier sets) at its empty post-__init__ values. A loaded chain
    would look healthy by block count but be unusable: any STARK spend
    would fail "stale root" because the loaded tree's root didn't match
    what the on-chain shields had deposited.
  * `Wallet.save()` only persisted the Dilithium keypair. The
    `mixer_notes` and `stark_notes` lists tracked by Phase 4's wallet
    bookkeeping were lost on every restart, so a user's view of their
    shielded notes vanished.

This file verifies both fixes round-trip every concrete state element
through save → load.
"""

from __future__ import annotations

import os
import tempfile
import time

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    create_mixer_deposit_tx, create_mixer_withdraw_tx,
)
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fund_wallet(chain: Blockchain, wallet: Wallet, target: float) -> None:
    while chain.balance_of(wallet.address) < target:
        chain.mine_pending(wallet.address)


def _tmp_json_path() -> str:
    """Return a path to a fresh writable .json file. Caller is
    responsible for deleting it (use try/finally)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Blockchain persistence — empty chain
# ---------------------------------------------------------------------------

def test_persistence_empty_chain_roundtrips():
    """An empty chain (just genesis) saves and loads with matching state."""
    chain = Blockchain()
    path = _tmp_json_path()
    try:
        chain.save(path)
        loaded = Blockchain.load(path)
        assert len(loaded.blocks) == 1  # genesis only
        assert loaded.stark_anon_tree._next_idx == 0
        assert loaded.mixer_tree._next_idx == 0
        assert loaded.anon_tree.size == 0
        assert loaded.nullifiers == set()
        assert loaded.stark_nullifiers == set()
        assert loaded.mixer_nullifiers == set()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Blockchain persistence — STARK pool state
# ---------------------------------------------------------------------------

def test_persistence_stark_pool_rebuilt_after_load():
    """A chain with a shielded note must have stark_anon_tree
    reconstructed on load. This was the headline bug — pre-fix, the
    loaded tree's root differed from the saved tree's root."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=100)

    note = STARKNote.random(value=100)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=100.0,
        timestamp=time.time(), nonce=int(time.time() * 1e6),
    )
    shtx.sign(w.keypair)
    chain.submit_shield(shtx)
    chain.mine_pending("proposer")

    pre_root = chain.stark_anon_tree.root()
    pre_size = chain.stark_anon_tree._next_idx
    assert pre_size == 1, "test setup: shield should have added one leaf"

    path = _tmp_json_path()
    try:
        chain.save(path)
        loaded = Blockchain.load(path)
        assert loaded.stark_anon_tree._next_idx == pre_size
        assert loaded.stark_anon_tree.root() == pre_root
        # The leaf at index 0 matches the shielded note
        assert loaded.stark_anon_tree._layers[0][0] == note.leaf()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Blockchain persistence — mixer state (deposit + withdrawal)
# ---------------------------------------------------------------------------

def test_persistence_mixer_state_rebuilt_after_load():
    """A chain with both a mixer deposit and a mixer withdrawal must
    rebuild mixer_tree, mixer_nullifiers, AND the resulting STARK pool
    output_leaf on load."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=150)

    # Deposit
    note = STARKNote.random(value=100)
    deposit = create_mixer_deposit_tx(w, 100, note)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    # M-timing: wait DELAY blocks so the deposit is anchorable
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")

    # Withdraw against the latest valid anchor
    anchor_idx = chain.latest_valid_mixer_anchor()
    anchored_tree = chain.historical_mixer_tree_for_block(anchor_idx)
    output_note = STARKNote.random(value=100)
    withdrawal = create_mixer_withdraw_tx(
        note=note, leaf_idx=0,
        mixer_tree=anchored_tree,
        output_note=output_note,
        anchor_block_index=anchor_idx,
    )
    chain.submit_mixer_withdraw(withdrawal)
    chain.mine_pending("proposer")

    # Snapshot of pre-save derived state
    pre = {
        "stark_root": chain.stark_anon_tree.root(),
        "stark_size": chain.stark_anon_tree._next_idx,
        "mixer_root": chain.mixer_tree.root(),
        "mixer_size": chain.mixer_tree._next_idx,
        "mixer_nullifiers": set(chain.mixer_nullifiers),
        "stark_nullifiers": set(chain.stark_nullifiers),
        # M-timing: also confirm the root history rebuilds correctly
        "mixer_root_history": list(chain.mixer_root_history),
        "mixer_leaf_count_history": list(chain.mixer_leaf_count_history),
    }

    path = _tmp_json_path()
    try:
        chain.save(path)
        loaded = Blockchain.load(path)
        assert loaded.stark_anon_tree.root() == pre["stark_root"]
        assert loaded.stark_anon_tree._next_idx == pre["stark_size"]
        assert loaded.mixer_tree.root() == pre["mixer_root"]
        assert loaded.mixer_tree._next_idx == pre["mixer_size"]
        assert loaded.mixer_nullifiers == pre["mixer_nullifiers"]
        assert loaded.stark_nullifiers == pre["stark_nullifiers"]
        # M-timing: history must rebuild deterministically
        assert loaded.mixer_root_history == pre["mixer_root_history"]
        assert loaded.mixer_leaf_count_history == pre["mixer_leaf_count_history"]
        # And the chain still passes is_valid()
        assert loaded.is_valid()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Loaded chain is functionally usable
# ---------------------------------------------------------------------------

def test_persistence_loaded_chain_can_be_extended():
    """The acid test: load a chain, then keep building on it. The new
    block must be appendable, and is_valid() must still pass.
    Catches any subtle state-mismatch bug that wouldn't show up in a
    pure root-equality check."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=100)

    note = STARKNote.random(value=100)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=100.0,
        timestamp=time.time(), nonce=int(time.time() * 1e6),
    )
    shtx.sign(w.keypair)
    chain.submit_shield(shtx)
    chain.mine_pending("proposer")

    path = _tmp_json_path()
    try:
        chain.save(path)
        loaded = Blockchain.load(path)
        # Mine an additional block on the loaded chain
        loaded.mine_pending("post-load-proposer")
        assert loaded.height > chain.height
        assert loaded.is_valid()
        # The STARK leaf from the saved era is still discoverable in the
        # loaded chain's pool
        assert loaded.stark_anon_tree._layers[0][0] == note.leaf()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Wallet persistence — basic keypair (regression)
# ---------------------------------------------------------------------------

def test_persistence_wallet_keypair_roundtrips():
    """Wallet save/load preserves the keypair (existing behavior).
    This was working before; included as a regression check that the
    new shielded-notes serialization didn't break basic wallet use."""
    w = Wallet()
    addr = w.address
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="testpw")
        loaded = Wallet.load(path, passphrase="testpw")
        assert loaded.address == addr
        # Loaded wallet can still sign — basic sanity
        tx = loaded.create_tx(recipient="alice", amount=1.0)
        assert tx.verify()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Wallet persistence — shielded notes (the new behavior)
# ---------------------------------------------------------------------------

def test_persistence_wallet_shielded_notes_roundtrip():
    """A wallet that has tracked mixer and STARK notes must reload them
    intact. Note equality is structural (sk, randomness, value)."""
    w = Wallet()
    w.mixer_notes.append(STARKNote(sk=10, randomness=20, value=100))
    w.mixer_notes.append(STARKNote(sk=30, randomness=40, value=10))
    w.stark_notes.append(STARKNote(sk=50, randomness=60, value=50))

    path = _tmp_json_path()
    try:
        w.save(path, passphrase="testpw")
        loaded = Wallet.load(path, passphrase="testpw")
        assert len(loaded.mixer_notes) == 2
        assert len(loaded.stark_notes) == 1
        assert loaded.mixer_notes[0] == STARKNote(sk=10, randomness=20, value=100)
        assert loaded.mixer_notes[1] == STARKNote(sk=30, randomness=40, value=10)
        assert loaded.stark_notes[0] == STARKNote(sk=50, randomness=60, value=50)
    finally:
        os.unlink(path)


def test_persistence_wallet_old_format_loads_with_empty_notes():
    """A wallet file written before this persistence pass (lacking
    `mixer_notes` and `stark_notes` keys) must still load, with empty
    note lists. Migration-friendly behavior — no broken old files."""
    import json
    from base64 import b64encode
    from qchain.crypto import dilithium

    kp = dilithium.generate_keypair()
    # Write an "old format" wallet by hand
    old_data = {
        "public_key": b64encode(kp.public_key).decode(),
        "secret_key": b64encode(kp.secret_key).decode(),
        # NO mixer_notes, NO stark_notes
    }
    path = _tmp_json_path()
    try:
        from pathlib import Path
        Path(path).write_text(json.dumps(old_data))
        loaded = Wallet.load(path)
        assert loaded.address == kp.address()
        assert loaded.mixer_notes == []
        assert loaded.stark_notes == []
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# End-to-end: wallet + chain together survive restart and remain usable
# ---------------------------------------------------------------------------

def test_persistence_end_to_end_restart_then_spend():
    """The headline integration test: deposit a mixer note, save chain
    and wallet, simulate a 'restart' by loading both into fresh objects,
    then complete a withdrawal using the loaded state. Proves the
    persistence pass enables a real-world restart workflow."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=150)

    # Use the wallet helper API — exercises the full bookkeeping path
    deposit = w.create_mixer_deposit(denomination=100)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    assert len(w.mixer_notes) == 1
    # M-timing: wait DELAY blocks before save so the deposit is
    # anchorable after restart. This is also realistic: you'd save
    # well after a deposit landed, not the exact same instant.
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")

    # Save BOTH
    chain_path = _tmp_json_path()
    wallet_path = _tmp_json_path()
    try:
        chain.save(chain_path)
        w.save(wallet_path, passphrase="testpw")

        # "Restart": fresh objects from disk
        loaded_chain = Blockchain.load(chain_path)
        loaded_w = Wallet.load(wallet_path, passphrase="testpw")
        assert len(loaded_w.mixer_notes) == 1
        assert loaded_w.mixer_notes[0].value == 100

        # The mixer note must be findable in the loaded chain's pool
        idx = loaded_w.find_mixer_note_idx(loaded_chain, loaded_w.mixer_notes[0])
        assert idx == 0, "mixer note must be findable in reloaded chain"

        # Withdrawal proceeds end-to-end against loaded state
        withdrawal = loaded_w.create_mixer_withdrawal(
            loaded_chain, loaded_w.mixer_notes[0]
        )
        # Note: create_mixer_withdrawal raises if its argument isn't in
        # mixer_notes, but it removes from the list before we can re-
        # access. We use a copy reference here in tests for clarity. The
        # withdrawal object itself is what we care about.
        loaded_chain.submit_mixer_withdraw(withdrawal)
        loaded_chain.mine_pending("post-restart-proposer")

        # State is consistent post-restart
        assert loaded_chain.is_valid()
        assert loaded_chain.mixer_nullifiers, "withdrawal must have marked a nullifier"
        assert len(loaded_w.stark_notes) == 1, "withdrawal must have credited stark_notes"
    finally:
        os.unlink(chain_path)
        os.unlink(wallet_path)

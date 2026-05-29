"""Tests for ROADMAP 1.6: wallet note lifecycle helpers.

Closes the SPIRIT of the original 1.6 item (make note tracking
robust). The original problem statement — "notes are stored in-memory
only and not persisted by save()" — was stale; note persistence has
shipped since the persistence pass. The remaining real gap was that
the wallet could carry orphaned pending notes after a failed
deposit. This pass adds:

  * `Wallet.reconcile_with_chain(chain)` — read-only classifier
    that returns a `WalletReconciliation` report
  * `Wallet.reconcile_summary(chain)` — one-line human-readable view
  * `Wallet.prune_pending_notes(chain)` — destructive cleanup based
    on the report

See WALLET-NOTE-LIFECYCLE-README.md for the full discovery, the
honest-scope decisions (no nullifier-spent check, no chain rescan
from genesis), and the design rationale.
"""

from __future__ import annotations

import time

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    MIXER_DENOMINATIONS, MIXER_WITHDRAWAL_DELAY, create_mixer_deposit_tx,
)
from qchain.chain.wallet import (
    ReconciledNote, Wallet, WalletReconciliation,
)
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fund_wallet(chain: Blockchain, wallet: Wallet, target: float) -> None:
    """Mine blocks to wallet until target balance reached."""
    while chain.balance_of(wallet.address) < target:
        chain.mine_pending(wallet.address)


def _deposit_and_mine(
    chain: Blockchain, wallet: Wallet, denomination: int = 10,
) -> STARKNote:
    """Build a mixer deposit, submit it, mine a block so the deposit lands.

    Returns the STARKNote backing the deposit (which is also in
    wallet.mixer_notes after this).
    """
    deposit = wallet.create_mixer_deposit(denomination)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("miner-x")
    # The wallet's create_mixer_deposit already appended to mixer_notes
    return wallet.mixer_notes[-1]


# ---------------------------------------------------------------------------
# 1. reconcile_with_chain — empty / trivial cases
# ---------------------------------------------------------------------------

def test_reconcile_empty_wallet_returns_empty_report():
    """A wallet with no notes against any chain produces empty lists."""
    w = Wallet()
    chain = Blockchain()
    rec = w.reconcile_with_chain(chain)
    assert isinstance(rec, WalletReconciliation)
    assert rec.confirmed == []
    assert rec.pending == []


def test_reconcile_summary_format():
    """Summary string contains counts in the documented shape."""
    w = Wallet()
    chain = Blockchain()
    # Empty case
    assert w.reconcile_summary(chain) == (
        "0 confirmed (0 mixer, 0 stark), 0 pending (0 mixer, 0 stark)"
    )
    # Add some in-memory notes that aren't on chain
    w.mixer_notes.append(STARKNote(sk=1, randomness=2, value=10))
    w.mixer_notes.append(STARKNote(sk=3, randomness=4, value=100))
    w.stark_notes.append(STARKNote(sk=5, randomness=6, value=42))
    summary = w.reconcile_summary(chain)
    assert "0 confirmed" in summary
    assert "3 pending" in summary
    assert "2 mixer" in summary
    assert "1 stark" in summary


# ---------------------------------------------------------------------------
# 2. reconcile_with_chain — pending notes (in-memory, not yet on-chain)
# ---------------------------------------------------------------------------

def test_reconcile_classifies_in_memory_only_notes_as_pending():
    """Notes the wallet owns but that aren't on any chain are pending,
    with leaf_idx = None."""
    w = Wallet()
    chain = Blockchain()
    w.mixer_notes.append(STARKNote(sk=1, randomness=2, value=10))
    w.stark_notes.append(STARKNote(sk=3, randomness=4, value=100))

    rec = w.reconcile_with_chain(chain)
    assert len(rec.confirmed) == 0
    assert len(rec.pending) == 2

    # Each pending entry has the right shape
    pools = {r.pool for r in rec.pending}
    assert pools == {"mixer", "stark"}
    for r in rec.pending:
        assert r.leaf_idx is None
        assert isinstance(r.note, STARKNote)


def test_reconcile_does_not_mutate_wallet_state():
    """Reconciliation must be read-only — calling it multiple times
    leaves the wallet unchanged."""
    w = Wallet()
    w.mixer_notes.append(STARKNote(sk=1, randomness=2, value=10))
    chain = Blockchain()

    before_mixer = list(w.mixer_notes)
    before_stark = list(w.stark_notes)

    for _ in range(3):
        w.reconcile_with_chain(chain)
        w.reconcile_summary(chain)

    assert w.mixer_notes == before_mixer
    assert w.stark_notes == before_stark


# ---------------------------------------------------------------------------
# 3. reconcile_with_chain — confirmed mixer notes
# ---------------------------------------------------------------------------

def test_reconcile_classifies_confirmed_mixer_note():
    """After deposit + mine, a note shows as confirmed with a real
    leaf_idx in the mixer pool."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=20)
    note = _deposit_and_mine(chain, w, denomination=10)

    rec = w.reconcile_with_chain(chain)
    assert len(rec.confirmed) == 1
    assert len(rec.pending) == 0
    entry = rec.confirmed[0]
    assert entry.pool == "mixer"
    assert entry.leaf_idx is not None
    assert entry.leaf_idx >= 0
    assert entry.note == note


def test_reconcile_handles_mixed_pending_and_confirmed():
    """A wallet with one confirmed deposit AND one in-memory-only note
    correctly classifies both."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=20)
    _deposit_and_mine(chain, w, denomination=10)
    # Add a second note WITHOUT depositing — it stays pending
    w.mixer_notes.append(STARKNote(sk=999, randomness=888, value=10))

    rec = w.reconcile_with_chain(chain)
    assert len(rec.confirmed) == 1
    assert len(rec.pending) == 1
    assert rec.confirmed[0].leaf_idx is not None
    assert rec.pending[0].leaf_idx is None


# ---------------------------------------------------------------------------
# 4. reconcile_with_chain — confirmed stark-pool notes
# ---------------------------------------------------------------------------

def test_reconcile_classifies_confirmed_stark_note():
    """After a complete mixer-deposit → wait → withdrawal flow, the
    wallet has a `stark_notes` entry that should reconcile as
    confirmed in the stark pool."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    # Deposit 100 into mixer
    mixer_note = _deposit_and_mine(chain, w, denomination=100)

    # Mine enough blocks for the withdrawal anchor delay
    for _ in range(MIXER_WITHDRAWAL_DELAY + 1):
        chain.mine_pending("miner-x")

    # Now withdraw — this creates a STARK-pool credit note
    withdrawal = w.create_mixer_withdrawal(chain, mixer_note)
    chain.submit_mixer_withdraw(withdrawal)
    chain.mine_pending("miner-x")

    # The output note moved to stark_notes; mixer_note removed from mixer_notes
    assert mixer_note not in w.mixer_notes
    assert len(w.stark_notes) == 1

    rec = w.reconcile_with_chain(chain)
    assert len(rec.confirmed) == 1
    assert rec.confirmed[0].pool == "stark"
    assert rec.confirmed[0].leaf_idx is not None


# ---------------------------------------------------------------------------
# 5. prune_pending_notes — destructive cleanup
# ---------------------------------------------------------------------------

def test_prune_pending_notes_removes_only_pending():
    """Confirmed notes survive a prune; pending notes are removed."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=20)
    confirmed_note = _deposit_and_mine(chain, w, denomination=10)
    # Add a pending in-memory-only note
    dead_note = STARKNote(sk=999, randomness=888, value=10)
    w.mixer_notes.append(dead_note)

    assert len(w.mixer_notes) == 2  # confirmed + dead

    n_removed = w.prune_pending_notes(chain)

    assert n_removed == 1
    assert len(w.mixer_notes) == 1
    assert w.mixer_notes[0] == confirmed_note
    assert dead_note not in w.mixer_notes


def test_prune_returns_correct_count():
    """Multiple pending notes across both pools — count matches removals."""
    w = Wallet()
    chain = Blockchain()
    # Three pending mixer notes, two pending stark notes
    w.mixer_notes.append(STARKNote(sk=1, randomness=1, value=10))
    w.mixer_notes.append(STARKNote(sk=2, randomness=2, value=10))
    w.mixer_notes.append(STARKNote(sk=3, randomness=3, value=10))
    w.stark_notes.append(STARKNote(sk=4, randomness=4, value=50))
    w.stark_notes.append(STARKNote(sk=5, randomness=5, value=50))

    n_removed = w.prune_pending_notes(chain)

    assert n_removed == 5
    assert w.mixer_notes == []
    assert w.stark_notes == []


def test_prune_empty_wallet_returns_zero():
    """Pruning a wallet with no notes is a no-op returning 0."""
    w = Wallet()
    chain = Blockchain()
    assert w.prune_pending_notes(chain) == 0


def test_prune_preserves_wallet_keypair():
    """The keypair must NOT be touched by prune — only note lists."""
    w = Wallet()
    chain = Blockchain()
    w.mixer_notes.append(STARKNote(sk=1, randomness=2, value=10))
    addr_before = w.address
    sk_before = w.keypair.secret_key

    w.prune_pending_notes(chain)

    assert w.address == addr_before
    assert w.keypair.secret_key == sk_before


# ---------------------------------------------------------------------------
# 6. Integration with persistence (1.4 + 1.6 interaction)
# ---------------------------------------------------------------------------

def test_reconcile_after_save_and_load_legacy_format():
    """Reconciliation works the same way on a wallet that was saved
    and reloaded. Confirms persistence didn't drop reconciliation
    state (it shouldn't — reconciliation is recomputed from chain
    each call)."""
    import os
    import tempfile

    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=20)
    _deposit_and_mine(chain, w, denomination=10)

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        w.save(path, passphrase="testpw")
        loaded = Wallet.load(path, passphrase="testpw")

        rec = loaded.reconcile_with_chain(chain)
        assert len(rec.confirmed) == 1
        assert rec.confirmed[0].pool == "mixer"
        assert rec.confirmed[0].leaf_idx is not None
    finally:
        os.unlink(path)


def test_reconcile_after_encrypted_save_and_load():
    """Same as above but with encryption-at-rest enabled — confirms
    1.6 reconciliation composes cleanly with 1.4 encryption."""
    import os
    import tempfile

    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=20)
    _deposit_and_mine(chain, w, denomination=10)

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        w.save(path, passphrase="testpw")
        loaded = Wallet.load(path, passphrase="testpw")

        rec = loaded.reconcile_with_chain(chain)
        assert len(rec.confirmed) == 1
        assert rec.confirmed[0].pool == "mixer"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# 7. Dataclass shape sanity
# ---------------------------------------------------------------------------

def test_reconciled_note_is_frozen():
    """ReconciledNote should be immutable — it's a value-object snapshot
    of a note's state at one moment. Tests can't mutate the report
    after reconcile_with_chain returns."""
    entry = ReconciledNote(
        note=STARKNote(sk=1, randomness=2, value=10),
        pool="mixer",
        leaf_idx=0,
    )
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        entry.leaf_idx = 99  # type: ignore[misc]


def test_wallet_reconciliation_default_empty():
    """The dataclass default-constructs to empty lists, so callers
    can build a report incrementally if needed."""
    rec = WalletReconciliation()
    assert rec.confirmed == []
    assert rec.pending == []

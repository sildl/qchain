"""M10 Phase 4 — Wallet bookkeeping for mixer notes.

Phase 3 made mixer txs propagate over the network. Phase 4 adds the
convenience layer on the Wallet: tracking which mixer notes the wallet
owns, finding their leaf indices in the pool, and a one-shot
`create_mixer_withdrawal` that handles the bookkeeping automatically.

These tests prove the Wallet API works correctly. No new cryptography,
no new chain semantics — this is pure Python ergonomics.

Honest scope: in-memory only, not persisted by `save()`. A wallet
restart loses the note bookkeeping (the chain state is still recoverable
by scanning).
"""

from __future__ import annotations

import time

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import MIXER_DENOMINATIONS
from qchain.chain.wallet import Wallet


def _fund_wallet(chain: Blockchain, wallet: Wallet, target: float) -> None:
    while chain.balance_of(wallet.address) < target:
        chain.mine_pending(wallet.address)


# ---------------------------------------------------------------------------
# Test 1: create_mixer_deposit remembers the note
# ---------------------------------------------------------------------------

def test_m10_phase4_create_mixer_deposit_remembers_note():
    """A wallet's `create_mixer_deposit` builds a signed deposit AND
    records the note in `wallet.mixer_notes` so it can be withdrawn later.
    """
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)
    assert len(w.mixer_notes) == 0

    deposit = w.create_mixer_deposit(denomination=100)

    assert len(w.mixer_notes) == 1
    assert w.mixer_notes[0].value == 100
    # The deposit's leaf matches the wallet's stored note
    assert deposit.leaf == w.mixer_notes[0].leaf()
    # And the deposit is properly signed
    assert deposit.verify_signature()


def test_m10_phase4_create_mixer_deposit_rejects_bad_denomination():
    """Helper validates against allowed set, doesn't pollute wallet state."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    assert 50 not in MIXER_DENOMINATIONS
    with pytest.raises(ValueError, match="denomination 50 not in allowed"):
        w.create_mixer_deposit(denomination=50)

    # Wallet state unchanged
    assert len(w.mixer_notes) == 0


# ---------------------------------------------------------------------------
# Test 2: find_mixer_note_idx returns None pre-mining, real index post-mining
# ---------------------------------------------------------------------------

def test_m10_phase4_find_mixer_note_idx_lifecycle():
    """Before mining the deposit, find_mixer_note_idx returns None
    (the leaf isn't on-chain yet — it's only in the mempool).
    After mining, it returns the correct leaf index.
    """
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    deposit = w.create_mixer_deposit(denomination=100)
    note = w.mixer_notes[0]

    # Submit but don't mine yet
    chain.submit_mixer_deposit(deposit)
    assert w.find_mixer_note_idx(chain, note) is None, \
        "before mining, leaf isn't on-chain yet"

    # Mine the block
    chain.mine_pending("proposer")
    idx = w.find_mixer_note_idx(chain, note)
    assert idx is not None, "after mining, leaf must be findable"
    assert idx == 0, "first deposit lands at leaf index 0"
    assert chain.mixer_tree._layers[0][idx] == note.leaf()


# ---------------------------------------------------------------------------
# Test 3: create_mixer_withdrawal round-trips state correctly
# ---------------------------------------------------------------------------

def test_m10_phase4_create_mixer_withdrawal_updates_wallet_state():
    """After a withdrawal: the mixer note is removed from `mixer_notes`,
    the output note is added to `stark_notes`.
    """
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    # Deposit + mine
    deposit = w.create_mixer_deposit(denomination=100)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    # M-timing: wait DELAY blocks so the deposit can be anchored
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")
    mixer_note = w.mixer_notes[0]
    assert len(w.mixer_notes) == 1
    assert len(w.stark_notes) == 0

    # Withdraw
    withdrawal = w.create_mixer_withdrawal(chain, mixer_note)

    # Wallet state: mixer note removed, stark note added
    assert len(w.mixer_notes) == 0, "mixer note removed after withdrawal"
    assert len(w.stark_notes) == 1, "output note added to stark_notes"
    assert w.stark_notes[0].value == 100, \
        "output note value matches deposit denomination"

    # Withdrawal's output_leaf matches the new stark note
    assert withdrawal.output_leaf == w.stark_notes[0].leaf()


def test_m10_phase4_withdrawal_output_note_findable_after_mining():
    """After mining the withdrawal, the wallet's output note is in
    the STARK pool at a discoverable index. This is what the spender
    would use to construct a follow-up STARK-anon spend.
    """
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    deposit = w.create_mixer_deposit(denomination=100)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    # M-timing: wait DELAY blocks
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")

    withdrawal = w.create_mixer_withdrawal(chain, w.mixer_notes[0])
    chain.submit_mixer_withdraw(withdrawal)
    chain.mine_pending("proposer")

    # The wallet's output note should now be findable in the STARK pool
    output_note = w.stark_notes[0]
    idx = w.find_stark_note_idx(chain, output_note)
    assert idx is not None, "output note must be on-chain after withdrawal mined"
    assert chain.stark_anon_tree._layers[0][idx] == output_note.leaf()


# ---------------------------------------------------------------------------
# Test 4 / 5: Error cases — unknown mixer note, not-yet-mined note
# ---------------------------------------------------------------------------

def test_m10_phase4_withdrawal_of_unknown_note_rejected():
    """Trying to withdraw a note the wallet doesn't own raises."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    # Some other wallet's note (not in `w.mixer_notes`)
    from qchain.crypto.anon_stark import STARKNote
    foreign_note = STARKNote.random(value=100)

    with pytest.raises(ValueError, match="does not own that mixer note"):
        w.create_mixer_withdrawal(chain, foreign_note)


def test_m10_phase4_withdrawal_of_unmined_note_rejected():
    """A wallet that just deposited but hasn't waited the timing-defense
    delay (or hasn't seen the block yet) can't withdraw.

    M-timing: the wallet helper picks the most recent anchor that's
    DELAY blocks old. If the deposit isn't yet at or before that
    anchor's block, the wallet raises.

    Failure modes covered here:
      * Deposit still in mempool (not even mined) → chain too young
        or anchor block doesn't contain leaf
      * Deposit mined but DELAY blocks haven't passed → similar
    """
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    deposit = w.create_mixer_deposit(denomination=100)
    chain.submit_mixer_deposit(deposit)
    # Deliberately NOT mining the deposit

    mixer_note = w.mixer_notes[0]
    # Either "chain too young" (if height < DELAY) or "not present in
    # mixer tree at anchor block" (the historical tree at the anchor
    # block doesn't contain this unmined deposit).
    with pytest.raises(ValueError, match="(not present in mixer tree|chain too young)"):
        w.create_mixer_withdrawal(chain, mixer_note)
